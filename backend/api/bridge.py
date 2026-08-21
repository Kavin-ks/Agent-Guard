"""
Request -> engine translation (no I/O, no DB).

Builds the engine's ``Action`` + ``Policy`` from the wire schema: derives a policy
from the goal, applies explicit overrides, and infers the resource kind. Kept
separate from ``deps``/``service`` so both can import it without a cycle.
"""

from __future__ import annotations

from agentguard import Action, Operation, Policy, Resource
from agentguard.goal_compiler import compile_goal
from agentguard.models import ResourceKind

from .schemas import EvaluateRequest


def infer_kind(req: EvaluateRequest) -> ResourceKind:
    if req.resource_kind is not None:
        return req.resource_kind
    if req.action in (Operation.NETWORK, Operation.TRANSMIT):
        return ResourceKind.URL
    if req.resource.strip().lower().startswith(("http://", "https://")):
        return ResourceKind.URL
    return ResourceKind.FILE


def build_policy(req: EvaluateRequest) -> Policy:
    policy = compile_goal(req.goal, session_id=req.session_id)
    if req.policy is not None:
        ov = req.policy
        data = policy.model_dump()
        if ov.allowed_scopes is not None:
            data["allowed_scopes"] = ov.allowed_scopes
        if ov.restricted_scopes is not None:
            data["restricted_scopes"] = ov.restricted_scopes
        if ov.protected_resources is not None:
            data["protected_resources"] = ov.protected_resources  # additive; built-ins still apply
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
        resource=Resource(kind=infer_kind(req), value=req.resource),
        payload=req.payload,
        destination=req.destination,
        context=req.context,
    )
