"""
The evaluation pipeline — the heart of Agent Guard.

Runs an ordered set of deterministic gates over a proposed action, then folds
their signals into a final decision via the risk engine. Optionally consults an
LLM goal-relevance advisor (injected; added in a later phase) whose output is
sanitized so it can never carry DENY authority.

The pipeline NEVER executes the agent's action. It only returns a verdict. It
also performs a defensive last check: even if given a malformed/partial context
it fails closed rather than open.
"""

from __future__ import annotations

import time
from typing import Protocol

from .gates import DEFAULT_GATES
from .gates.base import Gate, GateContext
from .models import (
    Action,
    DecisionResult,
    Policy,
    SecretMatch,
    Severity,
    Signal,
)
from .risk import aggregate


class RelevanceAdvisor(Protocol):
    """Optional semantic advisor (e.g. LLM). Returns advisory signals only."""

    def assess(self, action: Action, policy: Policy) -> list[Signal]:  # pragma: no cover
        ...


class Engine:
    """Stateless evaluation engine. Safe to share across requests/threads."""

    def __init__(
        self,
        gates: tuple[Gate, ...] | None = None,
        advisor: RelevanceAdvisor | None = None,
    ) -> None:
        self._gates = gates if gates is not None else DEFAULT_GATES
        self._advisor = advisor

    def evaluate(self, action: Action, policy: Policy) -> DecisionResult:
        start = time.perf_counter()
        ctx = GateContext(action=action, policy=policy)

        signals: list[Signal] = []
        for gate in self._gates:
            try:
                signals.extend(gate.evaluate(ctx))
            except Exception as exc:  # fail closed: a broken gate must not open the door
                signals.append(
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

        # Optional LLM advisory pass — sanitized to never hold DENY authority.
        if self._advisor is not None:
            for sig in self._advisor.assess(action, policy):
                signals.append(_sanitize_advisory(sig))

        # Redacted secret fingerprints for the response (never raw values).
        secrets = [
            SecretMatch(type=f.type, fingerprint=f.fingerprint, entropy=f.entropy)
            for f in ctx.payload_secrets
        ]

        latency_ms = (time.perf_counter() - start) * 1000.0
        return aggregate(action, policy, signals, secrets=secrets, latency_ms=latency_ms)


def _sanitize_advisory(sig: Signal) -> Signal:
    """Force advisory=True and cap severity at ASK. LLMs cannot force a hard DENY."""
    severity = sig.severity
    if severity == Severity.DENY:
        severity = Severity.ASK
    return sig.model_copy(
        update={"advisory": True, "severity": severity, "gate": f"advisory:{sig.gate}"}
    )
