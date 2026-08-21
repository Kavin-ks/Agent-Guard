"""
Dependency wiring: a shared engine instance and the request -> engine bridge.

The bridge translates the wire schema into the engine's ``Action`` + ``Policy``.
It derives a policy from the goal (deterministic compiler), applies any explicit
overrides, and infers the resource kind when the caller omits it. It performs no
I/O and never executes the action.
"""

from __future__ import annotations

from functools import lru_cache

from agentguard import Action, Engine, Operation, Policy, Resource
from agentguard.goal_compiler import compile_goal
from agentguard.models import ResourceKind

from .schemas import EvaluateRequest


@lru_cache
def get_engine() -> Engine:
    """Shared, stateless engine (default deterministic gates; no LLM advisor yet)."""
    return Engine()


def _infer_kind(req: EvaluateRequest) -> ResourceKind:
    if req.resource_kind is not None:
        return req.resource_kind
    if req.action in (Operation.NETWORK, Operation.TRANSMIT):
        return ResourceKind.URL
    value = req.resource.strip().lower()
    if value.startswith(("http://", "https://")):
        return ResourceKind.URL
    return ResourceKind.FILE


def build_policy(req: EvaluateRequest) -> Policy:
    """Goal-derived policy, with any explicit request overrides applied on top."""
    policy = compile_goal(req.goal, session_id=req.session_id)

    if req.policy is not None:
        ov = req.policy
        data = policy.model_dump()
        if ov.allowed_scopes is not None:
            data["allowed_scopes"] = ov.allowed_scopes
        if ov.restricted_scopes is not None:
            data["restricted_scopes"] = ov.restricted_scopes
        if ov.protected_resources is not None:
            # Additive only; engine still unions built-ins and never drops them.
            data["protected_resources"] = ov.protected_resources
        if ov.external_communication is not None:
            data["external_communication"] = ov.external_communication
        if ov.network_allowlist is not None:
            data["network_allowlist"] = ov.network_allowlist
        if ov.destructive_requires_approval is not None:
            data["destructive_requires_approval"] = ov.destructive_requires_approval
        policy = Policy(**data)

    return policy


def build_action(req: EvaluateRequest) -> Action:
    return Action(
        session_id=req.session_id,
        agent_id=req.agent_id,
        tool=req.tool,
        operation=req.action,
        resource=Resource(kind=_infer_kind(req), value=req.resource),
        payload=req.payload,
        destination=req.destination,
        context=req.context,
    )
