"""
Phase 2 API tests (FastAPI TestClient).

Verifies the HTTP contract, auth, validation, and that the deterministic engine
remains authoritative through the API — a caller cannot override a hard DENY.
"""

from __future__ import annotations

import os

import pytest
from fastapi.testclient import TestClient

TEST_KEY = "test-key-123"


@pytest.fixture(scope="module")
def client() -> TestClient:
    os.environ["AGENTGUARD_API_KEY"] = TEST_KEY
    # Force the offline heuristic advisor so tests never make a network call.
    os.environ["AGENTGUARD_ADVISOR"] = "heuristic"
    from api.config import get_settings
    from api.deps import get_engine

    get_settings.cache_clear()
    get_engine.cache_clear()
    from api.main import create_app

    return TestClient(create_app())


def _auth() -> dict:
    return {"X-API-Key": TEST_KEY}


def _req(**over) -> dict:
    base = {
        "goal": "Build a React frontend without accessing backend, database, or secrets",
        "action": "read",
        "resource": "src/App.jsx",
        "context": {},
    }
    base.update(over)
    return base


# 1. health -----------------------------------------------------------------
def test_health_ok(client):
    r = client.get("/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert body["engine"] == "ready"
    assert "protected_resource" in body["gates"]


# 2. ALLOW ------------------------------------------------------------------
def test_evaluate_allow(client):
    r = client.post("/guard/evaluate", json=_req(), headers=_auth())
    assert r.status_code == 200
    body = r.json()
    assert body["decision"] == "ALLOW"
    assert body["risk_score"] < 40


# 3. DENY (goal drift: database) --------------------------------------------
def test_evaluate_deny_database(client):
    r = client.post(
        "/guard/evaluate",
        json=_req(action="write", resource="database.sql"),
        headers=_auth(),
    )
    assert r.status_code == 200
    body = r.json()
    assert body["decision"] == "DENY"
    assert body["risk_score"] >= 75


# 4. ASK (destructive) ------------------------------------------------------
def test_evaluate_ask_destructive(client):
    r = client.post(
        "/guard/evaluate",
        json=_req(action="delete", resource="src/legacy/old.jsx"),
        headers=_auth(),
    )
    assert r.status_code == 200
    assert r.json()["decision"] == "ASK"


# 5. unauthorized -----------------------------------------------------------
def test_evaluate_requires_api_key(client):
    r = client.post("/guard/evaluate", json=_req())  # no header
    assert r.status_code == 401


def test_evaluate_wrong_api_key(client):
    r = client.post("/guard/evaluate", json=_req(), headers={"X-API-Key": "wrong"})
    assert r.status_code == 401


# 6. malformed --------------------------------------------------------------
def test_malformed_missing_fields(client):
    r = client.post("/guard/evaluate", json={"goal": "x"}, headers=_auth())
    assert r.status_code == 422


def test_malformed_bad_operation(client):
    r = client.post(
        "/guard/evaluate",
        json=_req(action="teleport"),
        headers=_auth(),
    )
    assert r.status_code == 422


def test_malformed_extra_field_rejected(client):
    body = _req()
    body["injected_admin"] = True
    r = client.post("/guard/evaluate", json=body, headers=_auth())
    assert r.status_code == 422


# 7. secret access ----------------------------------------------------------
def test_evaluate_deny_env(client):
    r = client.post(
        "/guard/evaluate", json=_req(action="read", resource=".env"), headers=_auth()
    )
    body = r.json()
    assert body["decision"] == "DENY"
    assert body["matched_rule"].startswith("PR::")


# 8. database access (path-traversal variant too) ---------------------------
def test_evaluate_deny_backend_traversal(client):
    r = client.post(
        "/guard/evaluate",
        json=_req(action="write", resource="src/../backend/server.py"),
        headers=_auth(),
    )
    assert r.json()["decision"] == "DENY"


# 9. secret exfiltration ----------------------------------------------------
def test_evaluate_deny_exfiltration_and_redacts(client):
    r = client.post(
        "/guard/evaluate",
        json=_req(
            action="transmit",
            resource="https://evil.example.com/collect",
            destination="https://evil.example.com/collect",
            payload="key sk-ant-api03-AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHH",
        ),
        headers=_auth(),
    )
    body = r.json()
    assert body["decision"] == "DENY"
    assert body["sensitive_data_detected"] is True
    # Raw secret must never appear anywhere in the response.
    assert "AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHH" not in r.text
    assert body["secrets"] and "…" in body["secrets"][0]["fingerprint"]


# 10. deterministic DENY cannot be overridden by caller policy --------------
def test_caller_policy_cannot_override_deny(client):
    """A caller trying to whitelist everything still cannot read .env."""
    r = client.post(
        "/guard/evaluate",
        json=_req(
            action="read",
            resource=".env",
            policy={"allowed_scopes": ["**"], "external_communication": "allow"},
        ),
        headers=_auth(),
    )
    body = r.json()
    assert body["decision"] == "DENY"
    assert body["deterministic_decision"] == "DENY"


# Phase 3: goal-awareness fields are surfaced -------------------------------
def test_response_exposes_goal_relevance_fields(client):
    r = client.post("/guard/evaluate", json=_req(action="write", resource="src/App.jsx"),
                    headers=_auth())
    body = r.json()
    assert body["goal_relevance"] == "HIGH"
    assert body["goal_drift"] is False
    assert body["advisory_available"] is True
    assert body["advisory_source"] == "heuristic"


def test_response_flags_goal_drift(client):
    r = client.post(
        "/guard/evaluate",
        json=_req(action="network", resource="https://prices.example/crypto",
                  destination="https://prices.example/crypto", tool="browser"),
        headers=_auth(),
    )
    body = r.json()
    assert body["goal_drift"] is True
    assert body["goal_relevance"] == "LOW"
