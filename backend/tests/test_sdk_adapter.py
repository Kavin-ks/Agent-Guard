"""
Phase 6 tests: the SDK adapter enforces Agent Guard decisions.

Core invariant proven here:
  "A protected tool cannot execute through the adapter until the action has been
   evaluated and authorized." Every uncertainty fails closed (tool not called).

Error/edge cases use httpx.MockTransport; enforcement cases run against the REAL
in-process Agent Guard API via the simulator harness.
"""

from __future__ import annotations

import logging

import httpx
import pytest

from adapter import AgentGuardClient, AutoApprove, AutoReject, GuardedExecutor
from simulator.harness import build_local_guard
from simulator.tools import ToolSandbox, build_registry

GOAL = "Build a React frontend. Do not modify backend or database, and never access secrets."


# ---- real-harness fixtures ------------------------------------------------
@pytest.fixture
def guard(tmp_path):
    g = build_local_guard(db_path=str(tmp_path / "sdk.db"), api_key="k")
    yield g
    g.close()


@pytest.fixture
def sandbox(tmp_path):
    return ToolSandbox(tmp_path / "fs")


def _executor(guard, sandbox, handler):
    return GuardedExecutor(guard.client, build_registry(sandbox), handler, session_id="t")


# ---- mock-transport helper (for error injection) --------------------------
def _mock_executor(sandbox, handler):
    http = httpx.Client(transport=httpx.MockTransport(handler), base_url="http://guard")
    client = AgentGuardClient(api_key="k", client=http)
    return GuardedExecutor(client, build_registry(sandbox), AutoApprove(), session_id="t")


# ========================= enforcement (real API) =========================
def test_allow_executes_tool(guard, sandbox):
    r = _executor(guard, sandbox, AutoReject()).execute("read_file", "src/App.jsx", goal=GOAL)
    assert r.decision == "ALLOW" and r.executed is True
    assert sandbox.was_called("read_file", "src/App.jsx")


def test_deny_never_executes_tool(guard, sandbox):
    r = _executor(guard, sandbox, AutoApprove()).execute("read_file", ".env", goal=GOAL)
    assert r.decision == "DENY" and r.executed is False
    assert not sandbox.reads  # tool body never ran


def test_ask_does_not_execute_without_approval(guard, sandbox):
    r = _executor(guard, sandbox, AutoReject()).execute("delete_file", "src/gen.jsx", goal=GOAL)
    assert r.decision == "ASK" and r.executed is False
    assert not sandbox.deletes


def test_approve_allows_execution(guard, sandbox):
    r = _executor(guard, sandbox, AutoApprove()).execute("delete_file", "src/gen.jsx", goal=GOAL)
    assert r.decision == "ASK" and r.executed is True and r.authorized is True
    assert sandbox.was_called("delete_file", "src/gen.jsx")


def test_reject_blocks_execution(guard, sandbox):
    r = _executor(guard, sandbox, AutoReject()).execute("delete_file", "src/gen.jsx", goal=GOAL)
    assert r.executed is False and "rejected" in r.reason


def test_tool_executes_exactly_once_after_approval(guard, sandbox):
    _executor(guard, sandbox, AutoApprove()).execute("delete_file", "src/once.jsx", goal=GOAL)
    assert sandbox.call_count("delete_file", "src/once.jsx") == 1


# ----- approval integrity (reuse / mutation) -----
def _approved_id(guard, resource="src/gen.jsx"):
    req = {"goal": GOAL, "action": "delete", "resource": resource,
           "resource_kind": "file", "tool": "delete_file", "session_id": "t"}
    dec = guard.client.evaluate(req)
    guard.client.approve(dec["approval_id"], "human")
    return dec["approval_id"]


def test_fingerprint_mismatch_blocks_execution(guard, sandbox):
    ap = _approved_id(guard, "src/gen.jsx")
    r = _executor(guard, sandbox, AutoApprove()).execute_with_existing_approval(
        ap, "delete_file", "database.sql", goal=GOAL)
    assert r.executed is False and "fingerprint" in r.reason
    assert "database.sql" not in sandbox.deletes


def test_reuse_after_consume_blocked(guard, sandbox):
    ex = _executor(guard, sandbox, AutoApprove())
    ap = _approved_id(guard, "src/reuse.jsx")
    first = ex.execute_with_existing_approval(ap, "delete_file", "src/reuse.jsx", goal=GOAL)
    second = ex.execute_with_existing_approval(ap, "delete_file", "src/reuse.jsx", goal=GOAL)
    assert first.executed is True and second.executed is False
    assert sandbox.call_count("delete_file", "src/reuse.jsx") == 1


def test_changed_goal_invalidates_approval(guard, sandbox):
    ap = _approved_id(guard, "src/g.jsx")
    r = _executor(guard, sandbox, AutoApprove()).execute_with_existing_approval(
        ap, "delete_file", "src/g.jsx", goal="A completely different goal")
    assert r.executed is False


def test_changed_resource_invalidates_approval(guard, sandbox):
    ap = _approved_id(guard, "src/r1.jsx")
    r = _executor(guard, sandbox, AutoApprove()).execute_with_existing_approval(
        ap, "delete_file", "src/r2.jsx", goal=GOAL)
    assert r.executed is False


def test_changed_operation_invalidates_approval(guard, sandbox):
    ap = _approved_id(guard, "src/op.jsx")
    # same resource, different operation (write instead of delete) -> different fingerprint
    r = _executor(guard, sandbox, AutoApprove()).execute_with_existing_approval(
        ap, "write_file", "src/op.jsx", goal=GOAL)
    assert r.executed is False
    assert "src/op.jsx" not in sandbox.writes


def test_expired_approval_blocks_execution(tmp_path, sandbox):
    guard = build_local_guard(db_path=str(tmp_path / "exp.db"), api_key="k",
                              approval_ttl_seconds=0)  # approvals expire immediately
    try:
        r = _executor(guard, sandbox, AutoApprove()).execute("delete_file", "src/exp.jsx", goal=GOAL)
        assert r.executed is False  # approve on an expired request fails closed
        assert not sandbox.deletes
    finally:
        guard.close()


# ----- audit records -----
def test_successful_execution_creates_audit_record(guard, sandbox):
    r = _executor(guard, sandbox, AutoReject()).execute("read_file", "src/App.jsx", goal=GOAL)
    ev = guard.client.get_audit_event(r.event_id)
    assert ev["execution_status"] == "REPORTED_EXECUTED"


def test_denied_execution_creates_audit_record(guard, sandbox):
    r = _executor(guard, sandbox, AutoApprove()).execute("read_file", ".env", goal=GOAL)
    ev = guard.client.get_audit_event(r.event_id)
    assert ev["decision"] == "DENY" and ev["execution_status"] == "BLOCKED"


def test_failed_execution_creates_audit_record(guard, tmp_path):
    sb = ToolSandbox(tmp_path / "fs2")
    reg = build_registry(sb)
    # Replace read_file with one that raises.
    from adapter.registry import Tool
    reg._tools["read_file"] = Tool("read_file", "read", "file",
                                   lambda **kw: (_ for _ in ()).throw(RuntimeError("boom")))
    ex = GuardedExecutor(guard.client, reg, AutoReject(), session_id="t")
    r = ex.execute("read_file", "src/App.jsx", goal=GOAL)
    assert r.executed is True and r.execution_status == "FAILED"
    ev = guard.client.get_audit_event(r.event_id)
    assert ev["execution_status"] == "REPORTED_FAILED"


# ========================= error handling (fail-closed) ===================
def test_api_unavailable_blocks_execution(sandbox):
    def handler(request):
        raise httpx.ConnectError("connection refused")
    r = _mock_executor(sandbox, handler).execute("read_file", "src/App.jsx", goal=GOAL)
    assert r.executed is False and r.decision == "ERROR"
    assert not sandbox.reads


def test_timeout_blocks_execution(sandbox):
    def handler(request):
        raise httpx.ReadTimeout("timed out")
    r = _mock_executor(sandbox, handler).execute("read_file", "src/App.jsx", goal=GOAL)
    assert r.executed is False and not sandbox.reads


def test_malformed_response_blocks_execution(sandbox):
    def handler(request):
        return httpx.Response(200, content=b"this is not json",
                              headers={"content-type": "application/json"})
    r = _mock_executor(sandbox, handler).execute("read_file", "src/App.jsx", goal=GOAL)
    assert r.executed is False and not sandbox.reads


def test_auth_failure_blocks_execution(sandbox):
    def handler(request):
        return httpx.Response(401, json={"detail": "bad key"})
    r = _mock_executor(sandbox, handler).execute("read_file", "src/App.jsx", goal=GOAL)
    assert r.executed is False and not sandbox.reads


# ========================= secrets never in SDK logs ======================
def test_secrets_never_in_sdk_logs(guard, sandbox, caplog):
    secret = "sk-ant-api03-" + "C" * 32
    with caplog.at_level(logging.DEBUG, logger="agentguard.sdk.client"):
        _executor(guard, sandbox, AutoApprove()).execute(
            "write_file", "src/config.js", goal=GOAL, payload=f"const KEY='{secret}';")
    assert secret not in caplog.text


# ========================= full simulator integration =====================
def test_full_simulator_against_real_api(guard):
    """Run all 5 scenarios through the SDK against the real in-process API."""
    from simulator.scenarios import run_all
    results = [r for r, _ in run_all(guard.client)]
    by_num = {r.number: r for r in results}
    assert by_num[1].guard_decision == "ALLOW" and by_num[1].tool_executed
    assert by_num[2].guard_decision == "DENY" and not by_num[2].tool_executed
    assert by_num[3].guard_decision == "ASK" and by_num[3].tool_executed
    assert by_num[4].guard_decision == "ASK" and not by_num[4].tool_executed
    assert not by_num[5].tool_executed  # reuse attack blocked
