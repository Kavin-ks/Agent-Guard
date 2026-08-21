"""
Phase 8 hardening tests: security headers, body-size limit, rate limiting,
safe error handling, SQLite concurrency, and log redaction.
"""

from __future__ import annotations

import logging
import os

import pytest
from fastapi.testclient import TestClient

KEY = "harden-key"


def _app(**env):
    os.environ["AGENTGUARD_API_KEY"] = KEY
    os.environ["AGENTGUARD_ADVISOR"] = "heuristic"
    for k, v in env.items():
        os.environ[k] = str(v)
    from api.config import get_settings
    from api.deps import get_approval_store, get_audit_store, get_engine, get_service
    for f in (get_settings, get_engine, get_audit_store, get_approval_store, get_service):
        f.cache_clear()
    from api.main import create_app
    return create_app()


@pytest.fixture
def client(tmp_path):
    os.environ.pop("AGENTGUARD_RATE_LIMIT_PER_MINUTE", None)
    app = _app(AGENTGUARD_DB_PATH=str(tmp_path / "h.db"))
    return TestClient(app, raise_server_exceptions=False)


def _auth():
    return {"X-API-Key": KEY}


def test_security_headers_present(client):
    r = client.get("/health")
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    assert r.headers["X-Frame-Options"] == "DENY"
    assert "Content-Security-Policy" in r.headers
    assert r.headers["Cache-Control"] == "no-store"


def test_body_size_limit_rejects_large(tmp_path):
    app = _app(AGENTGUARD_DB_PATH=str(tmp_path / "b.db"), AGENTGUARD_MAX_REQUEST_BYTES=2000)
    c = TestClient(app, raise_server_exceptions=False)
    big = {"goal": "x", "action": "read", "resource": "a", "payload": "P" * 5000}
    r = c.post("/guard/evaluate", json=big, headers=_auth())
    assert r.status_code == 413


def test_rate_limit_can_be_enabled(tmp_path):
    app = _app(AGENTGUARD_DB_PATH=str(tmp_path / "r.db"), AGENTGUARD_RATE_LIMIT_PER_MINUTE=3)
    c = TestClient(app, raise_server_exceptions=False)
    body = {"goal": "Build a React frontend", "action": "read", "resource": "src/App.jsx"}
    codes = [c.post("/guard/evaluate", json=body, headers=_auth()).status_code for _ in range(6)]
    assert 429 in codes
    # health stays exempt
    assert c.get("/health").status_code == 200
    os.environ.pop("AGENTGUARD_RATE_LIMIT_PER_MINUTE", None)


def test_unhandled_error_is_generic(client):
    # Force the service to raise; the response must not leak internals.
    from api.deps import get_service

    class Boom:
        def evaluate(self, *_a, **_k):
            raise RuntimeError("secret internal detail sk-ant-should-not-leak")

    client.app.dependency_overrides[get_service] = lambda: Boom()
    try:
        r = client.post("/guard/evaluate",
                        json={"goal": "x", "action": "read", "resource": "a"}, headers=_auth())
    finally:
        client.app.dependency_overrides.clear()
    assert r.status_code == 500
    assert "sk-ant" not in r.text and r.json()["detail"] == "Internal server error"


def test_log_redaction_scrubs_secrets(caplog):
    from api.logging_setup import configure_logging
    configure_logging("INFO")
    log = logging.getLogger("agentguard.test.redact")
    with caplog.at_level(logging.INFO):
        log.info("leaking key=sk-ant-api03-AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHH now")
    assert "sk-ant-api03-AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHH" not in caplog.text


def test_sqlite_concurrent_writes(tmp_path):
    """WAL + busy_timeout: concurrent writers must not error."""
    import threading
    from agentguard.audit import AuditEvent
    from api.store.sqlite import SqliteAuditStore

    store = SqliteAuditStore(str(tmp_path / "c.db"))
    errors = []

    def writer(n):
        try:
            for i in range(20):
                store.add(AuditEvent(action_id=f"{n}-{i}", session_id="s", operation="read",
                                     resource="x", resource_kind="file", tool="fs",
                                     decision="ALLOW", action_fingerprint="af"))
        except Exception as e:  # noqa: BLE001
            errors.append(e)

    threads = [threading.Thread(target=writer, args=(n,)) for n in range(4)]
    for t in threads: t.start()
    for t in threads: t.join()
    assert not errors
    assert store.count() == 80
