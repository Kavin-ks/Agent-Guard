"""
Approval handlers — how an ASK decision gets resolved to approve/reject.

The executor asks a handler whether to approve a pending ASK. This keeps the
human-in-the-loop policy pluggable: a CLI can prompt a person, a test can auto-
approve/reject, and a production integration can route to a review UI.
"""

from __future__ import annotations

from typing import Callable, Protocol


class ApprovalHandler(Protocol):
    def resolve(self, approval: dict) -> bool:  # True => approve, False => reject
        ...


class AutoApprove:
    def resolve(self, approval: dict) -> bool:
        return True


class AutoReject:
    def resolve(self, approval: dict) -> bool:
        return False


class CallbackApprovalHandler:
    """Delegate the decision to a callable (e.g. a CLI prompt)."""

    def __init__(self, fn: Callable[[dict], bool]) -> None:
        self._fn = fn

    def resolve(self, approval: dict) -> bool:
        return bool(self._fn(approval))
