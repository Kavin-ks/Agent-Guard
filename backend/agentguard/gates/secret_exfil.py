"""
Secret-exfiltration gate — the highest-authority gate.

DENIES any attempt to send a secret to an external destination. Two triggers:

1. The payload being transmitted contains a detected secret, OR
2. The resource being transmitted is itself a protected/secret file,

combined with an outbound operation (``transmit``/``network``) to a destination
that is not on the policy's network allowlist.

Only redacted fingerprints of the secret are ever placed on the signal.
"""

from __future__ import annotations

from ..constants import DEFAULT_PROTECTED_GLOBS
from ..models import Operation, Severity, Signal
from ..paths import matches_any
from .base import Gate, GateContext

_OUTBOUND = {Operation.TRANSMIT, Operation.NETWORK}


def _is_external(destination: str | None, allowlist: list[str]) -> bool:
    if not destination:
        return False
    dest = destination.strip().lower()
    for allowed in allowlist:
        if allowed.lower() in dest:
            return False
    return True


class SecretExfilGate(Gate):
    name = "secret_exfil"

    def evaluate(self, ctx: GateContext) -> list[Signal]:
        action = ctx.action
        if action.operation not in _OUTBOUND:
            return []

        destination = action.destination or (
            action.resource.value if action.resource.kind.value == "url" else None
        )
        if not _is_external(destination, ctx.policy.network_allowlist):
            return []

        secrets = ctx.payload_secrets
        resource_is_protected = matches_any(
            DEFAULT_PROTECTED_GLOBS, action.resource.value
        )

        if not secrets and not resource_is_protected:
            return []

        if secrets:
            kinds = ", ".join(sorted({s.type for s in secrets}))
            detail = f"payload contains secret material ({kinds})"
        else:
            detail = f"the source '{action.resource.value}' is a protected secret file"

        return [
            Signal(
                gate=self.name,
                severity=Severity.DENY,
                risk_points=76,
                reason=(
                    f"Potential sensitive-data exfiltration detected: {detail} "
                    f"is being sent to external destination '{destination}'."
                ),
                rule_id="EXFIL::external-secret-transmit",
            )
        ]
