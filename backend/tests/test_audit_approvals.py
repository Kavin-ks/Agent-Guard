"""
Phase 5 tests: audit logging + human approval queue.

Covers the 20 required cases, demo scenarios 1–5 (incl. the fingerprint-integrity
attack), and persistence across an application restart. The LLM is never called
(advisor forced to the offline heuristic).
"""

from __future__ import annotations

import os
import uuid

import pytest
from fastapi.testclient import TestClient

TEST_KEY = "test-key-phase5"
GOAL = "Build a React frontend. Do not modify backend or database, and never access secrets."


def _clear_caches():
    from api.config import get_settings
    from api.deps import get_approval_store, get_audit_store, get_engine, get_service, get_session_store
    for f in (get_settings, get_engine, get_audit_store, get_approval_store, get_service):
        f.cache_clear()


@pytest.fixture(scope="module")
def client(tmp_path_factory) -> TestClient:
    db = tmp_path_factory.mktemp("agentguard") / "audit.db"
    os.environ["AGENTGUARD_API_KEY"] = TEST_KEY
    os.environ["AGENTGUARD_ADVISOR"] = "heuristic"
    os.environ["AGENTGUARD_DB_PATH"] = str(db)
    _clear_caches()
    from api.main import create_app
    c = TestClient(create_app())
    c._db_path = str(db)  # type: ignore[attr-defined]
    return c


def _auth():
    return {"X-API-Key": TEST_KEY}


def _evaluate(client, **over):
    body = {"goal": GOAL, "action": "read", "resource": "src/App.jsx", "context": {}}
    body.update(over)
    return client.post("/guard/evaluate", json=body, headers=_auth())


# ===================== AUDIT =====================
def test_allow_creates_audit_event(client):
    r = _evaluate(client, action="write", resource="src/App.jsx")
    body = r.json()
    assert body["decision"] == "ALLOW"
    assert body["approval_required"] is False
    ev = client.get(f"/audit/{body['event_id']}", headers=_auth()).json()
    assert ev["decision"] == "ALLOW" and ev["execution_status"] == "NOT_EXECUTED"


def test_deny_creates_audit_event(client):
    r = _evaluate(client, action="read", resource=".env")
    body = r.json()
    assert body["decision"] == "DENY"
    assert body["execution_status"] == "BLOCKED"
    ev = client.get(f"/audit/{body['event_id']}", headers=_auth()).json()
    assert ev["decision"] == "DENY"


def test_ask_creates_audit_event_and_pending_approval(client):
    r = _evaluate(client, action="delete", resource="src/old.jsx")
    body = r.json()
    assert body["decision"] == "ASK"
    assert body["approval_required"] is True and body["approval_id"]
    ap = client.get(f"/approvals/{body['approval_id']}", headers=_auth()).json()
    assert ap["status"] == "PENDING"
    assert ap["action_fingerprint"] == body["action_fingerprint"]


def test_audit_retrieval_list(client):
    r = client.get("/audit", headers=_auth()).json()
    assert r["total"] >= 1 and isinstance(r["items"], list)


def test_audit_filtering_by_decision(client):
    r = client.get("/audit?decision=DENY", headers=_auth()).json()
    assert all(i["decision"] == "DENY" for i in r["items"])


def test_audit_pagination(client):
    page = client.get("/audit?limit=1&offset=0", headers=_auth()).json()
    assert len(page["items"]) == 1 and page["limit"] == 1


def test_sensitive_values_never_stored_in_audit(client):
    secret = "sk-ant-api03-" + "A" * 32
    r = _evaluate(client, action="execute", resource="shell", tool="shell",
                  payload=f"rm -rf build && echo {secret}")
    body = r.json()
    ev_text = client.get(f"/audit/{body['event_id']}", headers=_auth()).text
    assert secret not in ev_text
    ev = client.get(f"/audit/{body['event_id']}", headers=_auth()).json()
    assert ev["payload_contains_secret"] is True


# ===================== APPROVAL =====================
def test_approve_pending_to_approved(client):
    ap_id = _evaluate(client, action="delete", resource="src/a.jsx").json()["approval_id"]
    r = client.post(f"/approvals/{ap_id}/approve", json={"approver": "alice"}, headers=_auth())
    assert r.status_code == 200 and r.json()["status"] == "APPROVED"
    assert r.json()["approver"] == "alice"


def test_reject_pending_to_rejected(client):
    ap_id = _evaluate(client, action="delete", resource="src/b.jsx").json()["approval_id"]
    r = client.post(f"/approvals/{ap_id}/reject", json={"approver": "bob"}, headers=_auth())
    assert r.status_code == 200 and r.json()["status"] == "REJECTED"


def test_deny_creates_no_approval(client):
    body = _evaluate(client, action="read", resource=".env").json()
    assert body["approval_required"] is False and body["approval_id"] is None


def test_deny_cannot_be_approved(client):
    # There is no approval to target for a DENY; a fabricated id must 404, never
    # flip a DENY to APPROVED.
    r = client.post(f"/approvals/ap_{uuid.uuid4().hex}/approve",
                    json={"approver": "x"}, headers=_auth())
    assert r.status_code == 404


def test_already_resolved_approval_conflict(client):
    ap_id = _evaluate(client, action="delete", resource="src/c.jsx").json()["approval_id"]
    client.post(f"/approvals/{ap_id}/approve", json={"approver": "a"}, headers=_auth())
    again = client.post(f"/approvals/{ap_id}/reject", json={"approver": "a"}, headers=_auth())
    assert again.status_code == 409


def test_unauthorized_approval_rejected(client):
    ap_id = _evaluate(client, action="delete", resource="src/d.jsx").json()["approval_id"]
    r = client.post(f"/approvals/{ap_id}/approve", json={"approver": "x"})  # no key
    assert r.status_code == 401


def test_sensitive_data_never_in_approval_response(client):
    secret = "sk-ant-api03-" + "B" * 32
    ap_id = _evaluate(client, action="execute", resource="shell", tool="shell",
                      payload=f"rm -rf dist && echo {secret}").json()["approval_id"]
    ap_text = client.get(f"/approvals/{ap_id}", headers=_auth()).text
    assert secret not in ap_text


# ===================== CONSUME / INTEGRITY =====================
def _ask_and_approve(client, resource="src/old.jsx", goal=GOAL):
    ev = _evaluate(client, goal=goal, action="delete", resource=resource).json()
    client.post(f"/approvals/{ev['approval_id']}/approve",
                json={"approver": "human"}, headers=_auth())
    return ev["approval_id"]


def _consume(client, ap_id, **over):
    body = {"goal": GOAL, "action": "delete", "resource": "src/old.jsx", "context": {}}
    body.update(over)
    return client.post(f"/approvals/{ap_id}/consume", json=body, headers=_auth()).json()


def test_consume_authorizes_exact_approved_action(client):
    ap_id = _ask_and_approve(client, "src/old.jsx")
    r = _consume(client, ap_id, resource="src/old.jsx")
    assert r["authorized"] is True


def test_consume_twice_is_rejected_reuse(client):
    ap_id = _ask_and_approve(client, "src/reuse.jsx")
    assert _consume(client, ap_id, resource="src/reuse.jsx")["authorized"] is True
    assert _consume(client, ap_id, resource="src/reuse.jsx")["authorized"] is False


def test_action_modification_invalidates_approval(client):
    """SCENARIO 5: approve harmless delete, then swap resource to database.sql."""
    ap_id = _ask_and_approve(client, "src/gen.jsx")
    r = _consume(client, ap_id, resource="database.sql")
    assert r["authorized"] is False
    assert "fingerprint" in r["reason"]


def test_resource_modification_invalidates_approval(client):
    ap_id = _ask_and_approve(client, "src/x1.jsx")
    assert _consume(client, ap_id, resource="src/x2.jsx")["authorized"] is False


def test_goal_modification_invalidates_approval(client):
    ap_id = _ask_and_approve(client, "src/g1.jsx", goal=GOAL)
    r = _consume(client, ap_id, goal="Totally different goal", resource="src/g1.jsx")
    assert r["authorized"] is False


def test_unapproved_approval_cannot_be_consumed(client):
    ev = _evaluate(client, action="delete", resource="src/np.jsx").json()  # PENDING, not approved
    r = _consume(client, ev["approval_id"], resource="src/np.jsx")
    assert r["authorized"] is False and "APPROVED" in r["reason"]


# ===================== SERVICE-LEVEL: EXPIRY =====================
def test_expired_approval_cannot_be_used():
    """Direct service test with a zero-TTL so the approval is already expired."""
    from datetime import timedelta

    from agentguard import Engine
    from agentguard.advisors import HeuristicRelevanceAdvisor
    from agentguard.audit import _utcnow
    from api.schemas import EvaluateRequest
    from api.service import GuardService
    from api.store.sqlite import SqliteApprovalStore, SqliteAuditStore

    audit = SqliteAuditStore(":memory:")
    appr = SqliteApprovalStore(":memory:")
    svc = GuardService(Engine(advisor=HeuristicRelevanceAdvisor()), audit, appr,
                       approval_ttl_seconds=3600)
    out = svc.evaluate(EvaluateRequest(goal=GOAL, action="delete", resource="src/e.jsx"))
    assert out.approval is not None

    # Force expiry in the past and persist.
    ap = out.approval
    ap.expires_at = _utcnow() - timedelta(seconds=1)
    appr.update(ap)

    # Approving now must fail (get_approval marks it EXPIRED -> not PENDING).
    from api.service import ConflictError
    with pytest.raises(ConflictError):
        svc.approve(ap.approval_id, "human")
    assert svc.get_approval(ap.approval_id).status == "EXPIRED"


# ===================== PERSISTENCE ACROSS RESTART =====================
def test_audit_persists_across_restart(tmp_path):
    from agentguard.audit import AuditEvent
    from api.store.sqlite import SqliteAuditStore

    path = str(tmp_path / "persist.db")
    store1 = SqliteAuditStore(path)
    ev = AuditEvent(action_id="a1", session_id="s", operation="read", resource=".env",
                    resource_kind="file", tool="fs", decision="DENY",
                    action_fingerprint="af_test")
    store1.add(ev)
    del store1  # simulate shutdown

    store2 = SqliteAuditStore(path)  # fresh process/instance, same file
    loaded = store2.get(ev.event_id)
    assert loaded is not None and loaded.decision == "DENY"
    assert store2.count(decision="DENY") >= 1


def test_approval_persists_across_restart(tmp_path):
    from agentguard.audit import ApprovalRequest
    from api.store.sqlite import SqliteApprovalStore

    path = str(tmp_path / "persist_ap.db")
    s1 = SqliteApprovalStore(path)
    ap = ApprovalRequest(event_id="ev", action_id="a", session_id="s",
                         operation="delete", resource="src/x.jsx", tool="fs",
                         action_fingerprint="af_x")
    s1.add(ap)
    del s1
    s2 = SqliteApprovalStore(path)
    assert s2.get(ap.approval_id).status == "PENDING"
