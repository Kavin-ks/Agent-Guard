"""
Policy-scope gate.

Enforces the goal-derived scope:

* A resource in a ``restricted_scope`` is DENIED for any operation (this is the
  goal-drift guard: "do not modify backend/database").
* A *mutating* operation (write/delete/execute) on a resource that is not within
  any ``allowed_scope`` is DENIED as out-of-scope — the agent is straying beyond
  what the user authorized.

Reads that are merely outside the allowed scope are not denied here (they are
low-impact and protected files are already handled by the protected-resource
gate); this keeps false positives low while still blocking writes/drift.
"""

from __future__ import annotations

from ..models import Operation, ResourceKind, Severity, Signal
from ..paths import matches_any
from .base import Gate, GateContext

_MUTATING = {Operation.WRITE, Operation.DELETE, Operation.EXECUTE}


class PolicyScopeGate(Gate):
    name = "policy_scope"

    def evaluate(self, ctx: GateContext) -> list[Signal]:
        action = ctx.action
        policy = ctx.policy
        resource = action.resource

        # Restricted scope: hard DENY for any operation.
        restricted_hit = matches_any(policy.restricted_scopes, resource.value)
        if restricted_hit is not None:
            return [
                Signal(
                    gate=self.name,
                    severity=Severity.DENY,
                    risk_points=74,
                    reason=(
                        f"Action targets '{resource.value}', which is outside the "
                        f"user's authorized goal (restricted scope '{restricted_hit}')."
                    ),
                    rule_id=f"SCOPE::restricted::{restricted_hit}",
                )
            ]

        # Out-of-scope mutation: DENY writes/deletes/execs beyond allowed scope.
        if action.operation in _MUTATING and policy.allowed_scopes:
            # Only meaningful for file-like resources.
            if resource.kind in (ResourceKind.FILE, ResourceKind.OTHER):
                if matches_any(policy.allowed_scopes, resource.value) is None:
                    return [
                        Signal(
                            gate=self.name,
                            severity=Severity.DENY,
                            risk_points=66,
                            reason=(
                                f"{action.operation.value.capitalize()} of "
                                f"'{resource.value}' is outside the authorized "
                                f"frontend scope for this goal."
                            ),
                            rule_id="SCOPE::out-of-scope-mutation",
                        )
                    ]

        return []
