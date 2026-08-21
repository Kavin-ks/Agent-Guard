"""
Action integrity fingerprint.

An approval is bound to a fingerprint computed over every security-relevant part
of an evaluation: the goal, the compiled policy, the operation, the resource, the
destination, a hash of the payload, and the context. If ANY of these change, the
fingerprint changes and the prior approval no longer matches — defeating the
"approve a harmless action, then execute a dangerous one with the old approval"
attack.

The payload is never included raw — only a SHA-256 hash of it — so the fingerprint
(which is stored) can never leak secret material.
"""

from __future__ import annotations

import hashlib
import json

from .models import Action, Policy


def _payload_hash(payload: str | None) -> str:
    if not payload:
        return ""
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def action_fingerprint(action: Action, policy: Policy) -> str:
    """Return a stable SHA-256 fingerprint binding goal+policy+action+resource+context."""
    canonical = {
        # Goal + policy (the authorization context)
        "goal": policy.goal_text or "",
        "allowed_scopes": sorted(policy.allowed_scopes),
        "restricted_scopes": sorted(policy.restricted_scopes),
        "protected_resources": sorted(policy.protected_resources),
        "external_communication": policy.external_communication,
        "network_allowlist": sorted(policy.network_allowlist),
        # The action itself
        "operation": action.operation.value,
        "resource_kind": action.resource.kind.value,
        "resource": action.resource.value,
        "tool": action.tool,
        "destination": action.destination or "",
        "payload_sha256": _payload_hash(action.payload),
        # Context (values hashed via canonical JSON; never stored raw here)
        "context": json.dumps(action.context, sort_keys=True, separators=(",", ":"), default=str),
    }
    blob = json.dumps(canonical, sort_keys=True, separators=(",", ":"))
    return "af_" + hashlib.sha256(blob.encode("utf-8")).hexdigest()
