"""
Exfiltration gate — the highest-authority gate.

Blocks sensitive data from leaving through an unauthorized external action. It
fires only for OUTBOUND operations (transmit/network) to an EXTERNAL destination
(not on the policy allowlist), and then reasons about what is being sent:

  * a protected/secret file being transmitted, OR
  * HIGH/CRITICAL sensitive findings in the payload/context (secrets, private
    keys, cards, government IDs)               -> DENY (exfiltration)
  * MEDIUM findings only (e.g. a lone email)   -> ASK (human confirmation)

This means ordinary text with a single email doesn't get hard-blocked, while
real secret/financial/ID exfiltration is denied outright. Only redacted
fingerprints ever appear on the emitted signal.
"""

from __future__ import annotations

from ..constants import DEFAULT_PROTECTED_GLOBS
from ..detectors.scan import categories, has_high_or_critical
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

        findings = ctx.sensitive
        resource_is_protected = matches_any(DEFAULT_PROTECTED_GLOBS, action.resource.value)
        cats = categories(findings)

        # DENY: protected source file, or any high/critical sensitive datum.
        if resource_is_protected or has_high_or_critical(findings):
            detail = (
                f"the source '{action.resource.value}' is a protected secret file"
                if resource_is_protected and not findings
                else f"outbound payload contains sensitive data ({', '.join(cats)})"
            )
            return [Signal(
                gate=self.name,
                severity=Severity.DENY,
                risk_points=76,
                reason=(
                    f"Potential sensitive-data exfiltration detected: {detail} "
                    f"being sent to external destination '{destination}'."
                ),
                rule_id="EXFIL::external-sensitive-transmit",
            )]

        # ASK: medium-severity sensitive data leaving (e.g. a lone email address).
        # risk_points=0 so this flags/escalates without stacking with the
        # external-comm gate to falsely reach the DENY band — the nuance the
        # spec asks for ("do not simply block every action with sensitive data").
        if findings:
            return [Signal(
                gate=self.name,
                severity=Severity.ASK,
                risk_points=0,
                reason=(
                    f"Outbound communication to '{destination}' contains sensitive data "
                    f"({', '.join(cats)}); human confirmation required before it leaves."
                ),
                rule_id="EXFIL::external-sensitive-ask",
            )]

        return []
