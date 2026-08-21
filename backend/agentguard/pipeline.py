"""
The evaluation pipeline — the heart of Agent Guard.

Flow (Phase 3):

  1. Run the deterministic gates -> deterministic signals.
  2. Aggregate them -> the DETERMINISTIC decision (the security authority).
  3. If an advisor is configured (and we're not skipping it on a hard DENY),
     build a minimized, redacted request and ask the advisor for a goal-relevance
     assessment. Convert it into ADVISORY signals (sanitized: never DENY-capable).
  4. Aggregate deterministic + advisory signals -> the FINAL decision.

Invariants:
  * The final decision is never LESS restrictive than the deterministic one.
  * The advisor can escalate ALLOW->ASK but can neither create nor cancel a DENY.
  * If the advisor is unavailable, the deterministic decision stands (fail-closed,
    never fail-open).
  * The pipeline NEVER executes the agent's action.
"""

from __future__ import annotations

import time
from typing import Protocol

from .advisors.base import build_advisor_request
from .detectors.scan import categories
from .gates import DEFAULT_GATES
from .gates.base import Gate, GateContext
from .goal import RelevanceAssessment, RelevanceLevel
from .models import (
    Action,
    Decision,
    DecisionResult,
    Policy,
    SecretMatch,
    SensitiveMatch,
    Severity,
    Signal,
)
from .risk import aggregate


class RelevanceAdvisor(Protocol):
    def evaluate(self, request) -> RelevanceAssessment:  # pragma: no cover
        ...


# Advisory relevance -> (risk points, base severity). Points are capped low and,
# being advisory, are excluded from the deterministic DENY threshold in risk.py.
_RELEVANCE_MAP = {
    RelevanceLevel.HIGH: (0, Severity.INFO),
    RelevanceLevel.MEDIUM: (15, Severity.ELEVATE),
    RelevanceLevel.LOW: (30, Severity.ASK),
}


class Engine:
    """Stateless evaluation engine. Safe to share across requests/threads."""

    def __init__(
        self,
        gates: tuple[Gate, ...] | None = None,
        advisor: RelevanceAdvisor | None = None,
        advise_on_deny: bool = False,
    ) -> None:
        self._gates = gates if gates is not None else DEFAULT_GATES
        self._advisor = advisor
        # By default we skip the advisor when the deterministic verdict is already
        # DENY: it cannot change the outcome, and skipping avoids sending any data.
        self._advise_on_deny = advise_on_deny

    def evaluate(self, action: Action, policy: Policy) -> DecisionResult:
        start = time.perf_counter()
        ctx = GateContext(action=action, policy=policy)

        det_signals: list[Signal] = []
        for gate in self._gates:
            try:
                det_signals.extend(gate.evaluate(ctx))
            except Exception:  # fail closed: a broken gate must not open the door
                det_signals.append(
                    Signal(
                        gate=getattr(gate, "name", "unknown"),
                        severity=Severity.ASK,
                        risk_points=45,
                        reason=(
                            "A security gate failed to evaluate this action; "
                            "defaulting to human approval (fail-closed)."
                        ),
                        rule_id="ENGINE::gate-error",
                    )
                )

        secrets = [
            SecretMatch(type=f.type, fingerprint=f.fingerprint, entropy=f.entropy)
            for f in ctx.payload_secrets
        ]
        sensitive = [
            SensitiveMatch(category=f.category.value, subtype=f.subtype,
                           severity=f.severity.value, confidence=f.confidence,
                           fingerprint=f.fingerprint, location=f.location)
            for f in ctx.sensitive
        ]
        sens_cats = categories(ctx.sensitive)

        # Deterministic decision — the security authority.
        det_result = aggregate(action, policy, det_signals, secrets=secrets,
                               sensitive=sensitive, sensitive_categories=sens_cats)

        # Advisory pass.
        assessment: RelevanceAssessment | None = None
        if self._advisor is not None and (
            det_result.decision is not Decision.DENY or self._advise_on_deny
        ):
            request = build_advisor_request(action, policy)
            try:
                assessment = self._advisor.evaluate(request)
            except Exception:
                assessment = None  # unavailable -> deterministic stands (not fail-open)

        advisory_signals = _assessment_to_signals(assessment)
        all_signals = det_signals + [_sanitize_advisory(s) for s in advisory_signals]

        final = aggregate(action, policy, all_signals, secrets=secrets,
                          sensitive=sensitive, sensitive_categories=sens_cats)

        latency_ms = round((time.perf_counter() - start) * 1000.0, 2)
        return final.model_copy(update={
            "deterministic_decision": det_result.decision,
            "deterministic_risk_score": det_result.risk_score,
            "goal_relevance": assessment.relevance.value if assessment else None,
            "goal_relevance_confidence": assessment.confidence if assessment else None,
            "goal_drift": assessment.goal_drift if assessment else False,
            "advisory_recommendation": assessment.recommended_action.value if assessment else None,
            "advisory_available": bool(assessment and assessment.available),
            "advisory_source": assessment.source if assessment else None,
            "advisory_reason": assessment.reason if assessment else None,
            "latency_ms": latency_ms,
        })


def _assessment_to_signals(assessment: RelevanceAssessment | None) -> list[Signal]:
    if assessment is None:
        return []
    points, severity = _RELEVANCE_MAP[assessment.relevance]

    # An advisory ASK/DENY recommendation nudges severity to ASK (never beyond).
    if assessment.recommended_action in (Decision.ASK, Decision.DENY):
        severity = Severity.ASK
        points = max(points, 34)  # still bounded; excluded from the DENY threshold

    drift = " — potential goal drift" if assessment.goal_drift else ""
    reason = (
        f"Goal relevance {assessment.relevance.value} "
        f"(confidence {assessment.confidence:.0%}, {assessment.source}){drift}: "
        f"{assessment.reason}"
    )
    rule = "GOALDRIFT::low-relevance" if assessment.goal_drift else "RELEVANCE::advisory"
    return [Signal(
        gate="relevance",
        severity=severity,
        risk_points=points,
        reason=reason,
        rule_id=rule,
        advisory=True,
    )]


def _sanitize_advisory(sig: Signal) -> Signal:
    """Force advisory=True and cap severity at ASK. Advisories cannot force DENY."""
    severity = Severity.ASK if sig.severity == Severity.DENY else sig.severity
    gate = sig.gate if sig.gate.startswith("advisory:") else f"advisory:{sig.gate}"
    return sig.model_copy(update={"advisory": True, "severity": severity, "gate": gate})
