"""
Risk aggregation and final decision logic.

Two tiers, combined by "max severity wins":

* HARD verdict  — derived from the highest-severity signal any gate emitted.
                  A DENY signal forces DENY; an ASK signal forces at least ASK.
* SCORE verdict — the numeric risk (operation base + sum of signal points,
                  capped 0..100) mapped through the policy thresholds.

The final decision is the MORE severe of the two. Crucially, advisory (LLM)
signals are constrained at construction time to never carry DENY severity, so
the LLM can push a borderline ALLOW up to ASK but can neither create nor cancel
a deterministic hard DENY.
"""

from __future__ import annotations

from .constants import MAX_RISK, OPERATION_BASE_RISK
from .models import (
    Decision,
    DecisionResult,
    Policy,
    SecretMatch,
    Severity,
    Signal,
    severity_rank,
)


def _score_to_decision(score: int, policy: Policy) -> Decision:
    if score >= policy.deny_threshold:
        return Decision.DENY
    if score >= policy.ask_threshold:
        return Decision.ASK
    return Decision.ALLOW


def _severity_to_decision(sev: Severity | None) -> Decision:
    if sev == Severity.DENY:
        return Decision.DENY
    if sev == Severity.ASK:
        return Decision.ASK
    return Decision.ALLOW


_DECISION_RANK = {Decision.ALLOW: 0, Decision.ASK: 1, Decision.DENY: 2}


def aggregate(
    action,
    policy: Policy,
    signals: list[Signal],
    secrets: list[SecretMatch] | None = None,
    latency_ms: float = 0.0,
) -> DecisionResult:
    """Combine gate signals into a final, explainable ``DecisionResult``."""
    base = OPERATION_BASE_RISK.get(action.operation.value, 20)
    score = min(MAX_RISK, base + sum(max(0, s.risk_points) for s in signals))

    # Deterministic-only score: advisory (LLM) points are excluded. A DENY via
    # the score tier must be reachable WITHOUT advisory help, so the LLM can
    # never push an action into the DENY band on its own.
    deterministic_score = min(
        MAX_RISK, base + sum(max(0, s.risk_points) for s in signals if not s.advisory)
    )

    # Hard verdict from the strongest signal severity. (Advisory signals are
    # sanitized upstream to never carry DENY severity.)
    hard_severity: Severity | None = None
    if signals:
        hard_severity = max((s.severity for s in signals), key=severity_rank)

    hard_decision = _severity_to_decision(hard_severity)
    score_decision = _score_to_decision(score, policy)

    # If the DENY comes only from advisory points, downgrade the score tier to
    # ASK — advisory reasoning may raise suspicion but never authorizes a DENY.
    if (
        score_decision is Decision.DENY
        and deterministic_score < policy.deny_threshold
    ):
        score_decision = Decision.ASK

    # Max severity wins.
    final = (
        hard_decision
        if _DECISION_RANK[hard_decision] >= _DECISION_RANK[score_decision]
        else score_decision
    )

    reason, matched_rule = _primary_reason(signals, final)

    secrets = secrets or []
    return DecisionResult(
        action_id=action.action_id,
        session_id=action.session_id,
        decision=final,
        risk_score=score,
        reason=reason,
        matched_rule=matched_rule,
        sensitive_data_detected=bool(secrets),
        secrets=secrets,
        signals=signals,
        latency_ms=round(latency_ms, 2),
    )


def _primary_reason(signals: list[Signal], final: Decision) -> tuple[str, str | None]:
    """Pick the most relevant reason: strongest severity, then highest points."""
    if not signals:
        return (
            "Action is within the authorized goal scope and assessed as low risk.",
            None,
        )
    top = max(signals, key=lambda s: (severity_rank(s.severity), s.risk_points))
    return top.reason, top.rule_id
