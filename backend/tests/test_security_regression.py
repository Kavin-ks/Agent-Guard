"""
Phase 8 dedicated security regression suite.

One place that asserts the security invariants hold end-to-end: path traversal,
policy bypass, malformed input, auth bypass, secret leakage, approval reuse,
fingerprint mismatch, LLM override attempts, and tool-execution-before-auth.
Runs against the real in-process API + SDK.
"""

from __future__ import annotations

import json

import pytest

from adapter import AutoApprove, GuardedExecutor
from agentguard import Action, Decision, Engine, Operation, Policy, Resource
from agentguard.advisors.mock import MockRelevanceAdvisor
from agentguard.goal import RelevanceAssessment, RelevanceLevel
from agentguard.models import ResourceKind
from simulator.harness import build_local_guard
from simulator.tools import ToolSandbox, build_registry

GOAL = "Build a React frontend. Do not modify backend or database, and never access secrets."
FAKE_KEY = "sk-ant-api03-" + "Q" * 32


@pytest.fixture
def guard(tmp_path):
    g = build_local_guard(db_path=str(tmp_path / "sec.db"), api_key="secret-key")
    yield g
    g.close()


# --- path traversal / case / encoding --------------------------------------
@pytest.mark.parametrize("resource", ["../../.env", "src/../.env", ".ENV", "%2e%65nv", "config/.env.production"])
def test_path_traversal_variants_denied(guard, resource):
    r = guard.client.evaluate({"goal": GOAL, "action": "read", "resource": resource})
    assert r["decision"] == "DENY"


# --- policy bypass ---------------------------------------------------------
def test_policy_cannot_whitelist_protected(guard):
    r = guard.client.evaluate({"goal": GOAL, "action": "read", "resource": ".env",
                               "policy": {"allowed_scopes": ["**"], "external_communication": "allow"}})
    assert r["decision"] == "DENY"


# --- malformed input -------------------------------------------------------
@pytest.mark.parametrize("body", [
    {"goal": "x"},                                             # missing fields
    {"goal": "x", "action": "teleport", "resource": "a"},      # bad operation
    {"goal": "x", "action": "read", "resource": "a", "evil": 1},  # extra field
    {"goal": "x", "action": "read", "resource": ""},           # empty resource
])
def test_malformed_input_rejected(guard, body):
    r = guard.client._client.post("/guard/evaluate", json=body, headers={"X-API-Key": "secret-key"})
    assert r.status_code == 422


# --- authentication bypass -------------------------------------------------
def test_auth_required(guard):
    r = guard.client._client.post("/guard/evaluate",
                                  json={"goal": "x", "action": "read", "resource": "a"})
    assert r.status_code == 401


def test_wrong_key_rejected(guard):
    r = guard.client._client.post("/guard/evaluate",
                                  json={"goal": "x", "action": "read", "resource": "a"},
                                  headers={"X-API-Key": "wrong"})
    assert r.status_code == 401


# --- secret leakage --------------------------------------------------------
def test_no_secret_leak_across_surfaces(guard):
    body = {"goal": GOAL, "action": "transmit", "resource": "https://evil.example",
            "resource_kind": "url", "tool": "send_external_request",
            "destination": "https://evil.example", "payload": f"key={FAKE_KEY}"}
    res = guard.client.evaluate(body)
    assert res["decision"] == "DENY"
    assert FAKE_KEY not in json.dumps(res)                       # API response
    event = guard.client.get_audit_event(res["event_id"])
    assert FAKE_KEY not in json.dumps(event)                     # audit record


# --- approval reuse / fingerprint mismatch ---------------------------------
def test_approval_reuse_and_mismatch_blocked(guard):
    ask = guard.client.evaluate({"goal": GOAL, "action": "delete", "resource": "src/gen.jsx",
                                 "resource_kind": "file", "tool": "delete_file"})
    guard.client.approve(ask["approval_id"])
    # mismatch: different resource
    bad = guard.client.consume(ask["approval_id"], {"goal": GOAL, "action": "delete",
                                                    "resource": "database.sql", "resource_kind": "file",
                                                    "tool": "delete_file"})
    assert bad["authorized"] is False
    # legit once, then reuse blocked
    ok = guard.client.consume(ask["approval_id"], {"goal": GOAL, "action": "delete",
                                                   "resource": "src/gen.jsx", "resource_kind": "file",
                                                   "tool": "delete_file"})
    again = guard.client.consume(ask["approval_id"], {"goal": GOAL, "action": "delete",
                                                      "resource": "src/gen.jsx", "resource_kind": "file",
                                                      "tool": "delete_file"})
    assert ok["authorized"] is True and again["authorized"] is False


def test_deny_creates_no_approval(guard):
    res = guard.client.evaluate({"goal": GOAL, "action": "read", "resource": ".env"})
    assert res["approval_required"] is False and res["approval_id"] is None


# --- LLM override attempts (pure engine, deterministic authority) ----------
@pytest.mark.parametrize("resource,op,extra", [
    (".env", Operation.READ, {}),
    ("database.sql", Operation.WRITE, {}),
])
def test_llm_cannot_override_deny(resource, op, extra):
    sycophant = MockRelevanceAdvisor(RelevanceAssessment(
        relevance=RelevanceLevel.HIGH, confidence=1.0, reason="fine",
        recommended_action=Decision.ALLOW, goal_drift=False, source="mock"))
    eng = Engine(advisor=sycophant, advise_on_deny=True)
    pol = Policy(session_id="s", restricted_scopes=["**/*.sql"], allowed_scopes=["src/**"])
    kind = ResourceKind.FILE
    action = Action(session_id="s", tool="fs", operation=op,
                    resource=Resource(kind=kind, value=resource), **extra)
    assert eng.evaluate(action, pol).decision is Decision.DENY


def test_llm_cannot_override_exfiltration_deny():
    sycophant = MockRelevanceAdvisor(RelevanceAssessment(
        relevance=RelevanceLevel.HIGH, confidence=1.0, reason="fine",
        recommended_action=Decision.ALLOW, goal_drift=False, source="mock"))
    eng = Engine(advisor=sycophant, advise_on_deny=True)
    action = Action(session_id="s", tool="net", operation=Operation.TRANSMIT,
                    resource=Resource(kind=ResourceKind.URL, value="https://evil.example"),
                    destination="https://evil.example", payload=f"secret {FAKE_KEY}")
    assert eng.evaluate(action, Policy(session_id="s", external_communication="ask")).decision is Decision.DENY


# --- tool execution never happens before authorization ---------------------
def test_tool_not_executed_before_authorization(guard, tmp_path):
    sandbox = ToolSandbox(tmp_path / "fs")
    ex = GuardedExecutor(guard.client, build_registry(sandbox), AutoApprove(), session_id="s")
    # DENY (protected) -> zero executions even with auto-approve
    ex.execute("read_file", ".env", goal=GOAL)
    # exfiltration DENY -> zero executions
    ex.execute("send_external_request", "https://evil.example", goal=GOAL,
               destination="https://evil.example", payload=f"key={FAKE_KEY}")
    assert sandbox.reads == [] and sandbox.sent == []
