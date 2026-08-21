"""
External-communication gate.

Governs outbound network/transmit actions to destinations not on the policy
allowlist, according to ``policy.external_communication``:

* ``deny``  -> DENY
* ``ask``   -> ASK (human confirmation)
* ``allow`` -> no signal

Note: secret exfiltration is handled with higher authority by the secret_exfil
gate; this gate covers ordinary external communication that isn't carrying a
detected secret.
"""

from __future__ import annotations

from ..models import Operation, Severity, Signal
from .base import Gate, GateContext

_OUTBOUND = {Operation.TRANSMIT, Operation.NETWORK}


def _external_destination(action, allowlist) -> str | None:
    dest = action.destination or (
        action.resource.value if action.resource.kind.value == "url" else None
    )
    if not dest:
        return None
    low = dest.strip().lower()
    for allowed in allowlist:
        if allowed.lower() in low:
            return None
    return dest


class ExternalCommGate(Gate):
    name = "external_comm"

    def evaluate(self, ctx: GateContext) -> list[Signal]:
        action = ctx.action
        if action.operation not in _OUTBOUND:
            return []

        dest = _external_destination(action, ctx.policy.network_allowlist)
        if dest is None:
            return []

        mode = ctx.policy.external_communication.lower()
        if mode == "allow":
            return []

        if mode == "deny":
            return [
                Signal(
                    gate=self.name,
                    severity=Severity.DENY,
                    risk_points=70,
                    reason=(
                        f"Outbound communication to external destination '{dest}' "
                        f"is prohibited by policy."
                    ),
                    rule_id="EXTCOMM::deny",
                )
            ]

        # Default: ask.
        return [
            Signal(
                gate=self.name,
                severity=Severity.ASK,
                risk_points=30,
                reason=(
                    f"Outbound communication to external destination '{dest}' "
                    f"requires human confirmation."
                ),
                rule_id="EXTCOMM::ask",
            )
        ]
