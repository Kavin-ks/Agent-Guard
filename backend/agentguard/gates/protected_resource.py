"""
Protected-resource gate.

Any operation touching a resource that matches a protected glob is DENIED. The
protected set is ALWAYS the union of the built-in defaults and the user's
additions — a user policy can *add* protections but can never remove a built-in
one. This is the concrete implementation of "don't trust user-provided policy
blindly": even a policy that lists ``**`` as allowed cannot expose ``.env``.
"""

from __future__ import annotations

from ..constants import DEFAULT_PROTECTED_GLOBS
from ..models import ResourceKind, Severity, Signal
from ..paths import matches_any
from .base import Gate, GateContext


class ProtectedResourceGate(Gate):
    name = "protected_resource"

    def evaluate(self, ctx: GateContext) -> list[Signal]:
        resource = ctx.action.resource
        # URLs/DBs are handled by the scope/external gates; this gate guards files
        # and generic named resources by path.
        if resource.kind in (ResourceKind.URL,):
            return []

        # Built-ins first and always; user additions can only extend the set.
        patterns = list(DEFAULT_PROTECTED_GLOBS) + list(ctx.policy.protected_resources)
        matched = matches_any(patterns, resource.value)
        if matched is None:
            return []

        return [
            Signal(
                gate=self.name,
                severity=Severity.DENY,
                risk_points=86,
                reason=(
                    f"Access to protected resource '{resource.value}' is not "
                    f"authorized and may expose sensitive credentials or secrets."
                ),
                rule_id=f"PR::{matched}",
            )
        ]
