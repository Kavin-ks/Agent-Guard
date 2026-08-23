"""
MCP server configuration resolution.

Makes the MCP server "just work" for the running deployment without the
Antigravity config having to get every value exactly right:

  * URL  — AGENTGUARD_URL, else the Docker reverse proxy (localhost:8080/api),
           which is always published and injects the API key server-side.
  * KEY  — AGENTGUARD_API_KEY, else read from the repo's deploy/production.env
           (single source of truth), so the key can never drift out of sync.
  * SESSION — AGENTGUARD_SESSION, else a STABLE id persisted per workspace so a
           reconnecting Antigravity reuses the same session instead of leaving a
           stale "disconnected" one behind.
"""

from __future__ import annotations

import hashlib
import json
import os
import uuid
from pathlib import Path

_DEFAULT_URL = "http://localhost:8080/api"   # Docker reverse proxy (dashboard's backend)
_STATE = Path.home() / ".agentguard" / "sessions.json"


def _repo_production_env() -> Path | None:
    for parent in Path(__file__).resolve().parents:
        cand = parent / "deploy" / "production.env"
        if cand.exists():
            return cand
    return None


def resolve_url() -> str:
    return os.environ.get("AGENTGUARD_URL") or _DEFAULT_URL


def resolve_api_key() -> str:
    key = os.environ.get("AGENTGUARD_API_KEY")
    if key:
        return key
    envf = _repo_production_env()
    if envf:
        for line in envf.read_text(errors="replace").splitlines():
            line = line.strip()
            if line.startswith("AGENTGUARD_API_KEY=") and not line.startswith("#"):
                return line.split("=", 1)[1].strip()
    return ""


def resolve_agent_name() -> str:
    return os.environ.get("AGENTGUARD_AGENT", "Antigravity")


def resolve_workspace() -> str:
    return os.environ.get("AGENTGUARD_WORKSPACE", "./mcp-workspace")


def resolve_session_id(workspace: str) -> str:
    """A stable session id for this workspace, reused across reconnects."""
    env = os.environ.get("AGENTGUARD_SESSION")
    if env:
        return env
    ws_key = hashlib.sha1(str(Path(workspace).resolve()).encode()).hexdigest()[:8]
    try:
        data = json.loads(_STATE.read_text()) if _STATE.exists() else {}
    except Exception:
        data = {}
    if ws_key in data:
        return data[ws_key]
    sid = f"mcp-{uuid.uuid4().hex[:12]}"
    data[ws_key] = sid
    try:
        _STATE.parent.mkdir(parents=True, exist_ok=True)
        _STATE.write_text(json.dumps(data))
    except Exception:
        pass  # non-fatal: fall back to an in-memory id for this run
    return sid
