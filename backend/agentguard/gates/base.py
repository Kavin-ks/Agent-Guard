"""
Gate interface.

A gate inspects a proposed ``Action`` against a ``Policy`` and emits zero or more
``Signal`` objects. Gates are pure functions of their inputs: no I/O, no execution
of the agent's action, no mutation of the action or policy. This purity is what
makes the security engine deterministic and unit-testable.

Deterministic gates only ever emit non-advisory signals. The optional LLM
goal-relevance evaluator (added in a later phase) emits ``advisory=True`` signals
that are explicitly forbidden from carrying DENY severity, so the LLM can raise
suspicion but can never fabricate — nor override — a hard DENY.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..detectors.base import SensitiveFinding
from ..detectors.scan import scan_text
from ..detectors.secrets import SecretFinding, detect_secrets
from ..models import Action, Policy, Signal


@dataclass
class GateContext:
    """Shared, cached evaluation context passed to every gate for one action.

    Caches expensive work (e.g. secret scanning of the payload) so multiple gates
    don't recompute it.
    """

    action: Action
    policy: Policy
    _payload_secrets: list[SecretFinding] | None = field(default=None, repr=False)
    _sensitive: list[SensitiveFinding] | None = field(default=None, repr=False)

    @property
    def payload_secrets(self) -> list[SecretFinding]:
        if self._payload_secrets is None:
            self._payload_secrets = detect_secrets(self.action.payload)
        return self._payload_secrets

    @property
    def sensitive(self) -> list[SensitiveFinding]:
        """All sensitive findings (secrets + PII + financial) in the payload and
        stringified context values. Cached; the raw text never leaves here."""
        if self._sensitive is None:
            findings = scan_text(self.action.payload, "payload")
            for k, v in (self.action.context or {}).items():
                if isinstance(v, str):
                    findings.extend(scan_text(v, "context"))
            self._sensitive = findings
        return self._sensitive


class Gate:
    """Base class for all gates."""

    name: str = "gate"

    def evaluate(self, ctx: GateContext) -> list[Signal]:  # pragma: no cover
        raise NotImplementedError
