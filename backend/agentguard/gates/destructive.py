"""
Destructive-action gate.

Escalates potentially irreversible actions to ASK (human-in-the-loop) rather
than auto-allowing them, when the policy requires approval for destructive ops.
Two triggers:

* the operation is ``delete``, or
* the resource/payload of an ``execute`` action matches a destructive command
  pattern (``rm -rf``, ``DROP TABLE``, ``git push --force``, fork bombs, ...).

This gate emits ASK, not DENY: the action may be legitimate but needs a human.
If the same action is also out-of-scope or hits a protected resource, those
higher-severity DENY signals win under "max severity".
"""

from __future__ import annotations

from ..constants import DESTRUCTIVE_PATTERNS
from ..models import Operation, Severity, Signal
from .base import Gate, GateContext


class DestructiveGate(Gate):
    name = "destructive"

    def evaluate(self, ctx: GateContext) -> list[Signal]:
        action = ctx.action
        if not ctx.policy.destructive_requires_approval:
            return []

        trigger: str | None = None

        if action.operation == Operation.DELETE:
            trigger = f"delete of '{action.resource.value}'"
        elif action.operation == Operation.EXECUTE:
            haystack = f"{action.resource.value}\n{action.payload or ''}"
            for pattern in DESTRUCTIVE_PATTERNS:
                if pattern.search(haystack):
                    trigger = f"destructive command pattern '{pattern.pattern}'"
                    break

        if trigger is None:
            return []

        return [
            Signal(
                gate=self.name,
                severity=Severity.ASK,
                risk_points=30,
                reason=(
                    f"Destructive or irreversible action detected ({trigger}); "
                    f"human approval is required before execution."
                ),
                rule_id="DESTRUCTIVE::approval-required",
            )
        ]
