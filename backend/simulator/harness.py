"""
In-process harness: wires the SDK to a REAL Agent Guard API instance.

Uses httpx's ASGITransport so requests traverse the full real stack (routing,
auth, service, engine, SQLite) without opening a network socket — genuinely the
real API, just in-process. This is what the simulator and integration tests run
against.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from starlette.testclient import TestClient

from adapter.client import AgentGuardClient


@dataclass
class LocalGuard:
    app: object
    client: AgentGuardClient
    api_key: str
    db_path: str

    def close(self) -> None:
        self.client.close()


def build_local_guard(db_path: str, api_key: str = "sim-key", advisor: str = "heuristic",
                      approval_ttl_seconds: int | None = None) -> LocalGuard:
    """Create a real in-process Agent Guard app + an SDK client wired to it."""
    os.environ["AGENTGUARD_API_KEY"] = api_key
    os.environ["AGENTGUARD_ADVISOR"] = advisor      # offline; no network/LLM needed
    os.environ["AGENTGUARD_DB_PATH"] = db_path
    if approval_ttl_seconds is not None:
        os.environ["AGENTGUARD_APPROVAL_TTL_SECONDS"] = str(approval_ttl_seconds)
    else:
        os.environ.pop("AGENTGUARD_APPROVAL_TTL_SECONDS", None)

    from api.config import get_settings
    from api.deps import get_approval_store, get_audit_store, get_engine, get_service
    for f in (get_settings, get_engine, get_audit_store, get_approval_store, get_service):
        f.cache_clear()

    from api.main import create_app
    app = create_app()

    # Starlette's TestClient is a synchronous httpx.Client that drives the real
    # ASGI app in-process — the full real API stack, no network socket.
    http = TestClient(app, raise_server_exceptions=False)
    client = AgentGuardClient(api_key=api_key, client=http)
    return LocalGuard(app=app, client=client, api_key=api_key, db_path=db_path)
