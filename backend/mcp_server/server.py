"""
Agent Guard MCP server (FastMCP adapter over stdio).

An MCP-capable IDE/agent (e.g. Claude Code) connects to this server and calls its
tools; every call is gated by Agent Guard before execution. This module is a thin
adapter — all behaviour lives in GuardedToolProvider.

Environment:
  AGENTGUARD_URL        Agent Guard API base URL     (default http://127.0.0.1:8000)
  AGENTGUARD_API_KEY    API key for the backend      (required for protected routes)
  AGENTGUARD_WORKSPACE  workspace root for file/command tools (default ./mcp-workspace)
  AGENTGUARD_GOAL       initial session goal         (agents can override via set_goal)

Run:  cd backend && .venv/bin/python -m mcp_server
"""

from __future__ import annotations

import logging
import os

from adapter.client import AgentGuardClient

from .config import (
    resolve_agent_name,
    resolve_api_key,
    resolve_session_id,
    resolve_url,
    resolve_workspace,
)
from .provider import GuardedToolProvider

logger = logging.getLogger("agentguard.mcp")


def build_provider() -> GuardedToolProvider:
    url = resolve_url()
    client = AgentGuardClient(base_url=url, api_key=resolve_api_key())
    workspace = resolve_workspace()
    # Stable identity: the agent name and a session id that persists across
    # reconnects (per workspace), so a reconnecting Antigravity UPDATES the same
    # session instead of leaving a stale "disconnected" one behind.
    session = resolve_session_id(workspace)
    logger.info("Agent Guard MCP → %s  (agent=%s session=%s workspace=%s)",
                url, resolve_agent_name(), session, workspace)
    return GuardedToolProvider(
        client=client,
        workspace=workspace,
        goal=os.environ.get("AGENTGUARD_GOAL", ""),
        session_id=session,
        agent_id=resolve_agent_name(),
    )


def main() -> None:
    from fastmcp import FastMCP  # imported lazily so core tests don't need it

    provider = build_provider()
    mcp = FastMCP("Agent Guard")

    @mcp.tool
    def set_goal(goal: str) -> str:
        """Set the session goal Agent Guard evaluates every tool call against."""
        return provider.set_goal(goal)

    @mcp.tool
    def guarded_read_file(path: str, prompt: str = "") -> str:
        """Read a SINGLE file — Agent Guard authorizes the read before it happens.
        IMPORTANT: to read MULTIPLE files, call `guarded_read_files` with all paths
        at once instead of calling this tool repeatedly — that keeps it to one
        approval instead of one per file. Pass `prompt` = the user instruction that
        triggered this, for the audit trail."""
        return provider.read_file(path, prompt=prompt or None).as_text()

    @mcp.tool
    def guarded_read_files(paths: list[str], prompt: str = "") -> str:
        """Read SEVERAL files in one call (fewer IDE permission prompts). Each path
        is still evaluated individually — a protected/secret file in the list is
        still denied. Prefer this for reading multiple safe source files."""
        results = provider.read_files(paths, prompt=prompt or None)
        return "\n\n".join(f"# {p}\n{r.as_text()}" for p, r in zip(paths, results))

    @mcp.tool
    def guarded_write_file(path: str, content: str, prompt: str = "") -> str:
        """Write/modify a file — evaluated by Agent Guard first."""
        return provider.write_file(path, content, prompt=prompt or None).as_text()

    @mcp.tool
    def guarded_delete_file(path: str, prompt: str = "") -> str:
        """Delete a file — destructive, so Agent Guard may require human approval."""
        return provider.delete_file(path, prompt=prompt or None).as_text()

    @mcp.tool
    def guarded_run_command(command: str, prompt: str = "") -> str:
        """Run a shell command — evaluated (and possibly gated) by Agent Guard."""
        return provider.run_command(command, prompt=prompt or None).as_text()

    @mcp.tool
    def guarded_http_request(url: str, body: str = "", prompt: str = "") -> str:
        """Make an external HTTP request — blocked if it would exfiltrate sensitive data."""
        return provider.http_request(url, body or None, prompt=prompt or None).as_text()

    @mcp.tool
    def agentguard_resume(approval_id: str, tool: str, path: str = "",
                          command: str = "", url: str = "", content: str = "") -> str:
        """After a human approves an ASK in the dashboard, resume that exact action.
        Agent Guard re-verifies the fingerprint before the tool runs."""
        resource = path or command or url
        payload = content or (command if tool == "run_command" else None)
        destination = url or None
        return provider.resume(approval_id, tool, resource,
                               payload=payload, destination=destination).as_text()

    mcp.run()


if __name__ == "__main__":
    main()
