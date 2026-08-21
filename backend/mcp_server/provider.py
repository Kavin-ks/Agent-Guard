"""
GuardedToolProvider — framework-agnostic core of the MCP server.

Every method routes a proposed tool call through the SDK's GuardedExecutor (which
calls the real Agent Guard API) BEFORE the tool runs:

  ALLOW → execute once, return output.
  DENY  → never execute, return the block reason.
  ASK   → leave a PENDING approval, return approval_id; the human approves in the
          dashboard, then the agent calls `resume` (fingerprint-verified consume).

This class has no MCP dependency, so it is fully unit-testable against a real
in-process Agent Guard. It duplicates NO security logic.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from adapter.client import AgentGuardClient
from adapter.executor import ExecutionResult, GuardedExecutor

from .realtools import Workspace, build_registry


@dataclass
class ToolResult:
    status: str                 # executed | blocked | approval_required | error
    decision: str
    reason: str
    output: str | None = None
    approval_id: str | None = None
    event_id: str | None = None
    extra: dict = field(default_factory=dict)

    def as_text(self) -> str:
        if self.status == "executed":
            return f"[ALLOW] executed.\n{self.output or ''}"
        if self.status == "approval_required":
            return (f"[ASK] Human approval required before this action can run.\n"
                    f"reason: {self.reason}\n"
                    f"approval_id: {self.approval_id}\n"
                    f"Approve it in the Agent Guard dashboard (Approval Queue), then call "
                    f"`agentguard_resume` with this approval_id and the same arguments.")
        if self.status == "blocked":
            return f"[DENY] Blocked by Agent Guard — tool NOT executed.\nreason: {self.reason}"
        return f"[ERROR] {self.reason}"


def _from_execution(r: ExecutionResult) -> ToolResult:
    if r.executed:
        return ToolResult("executed", r.decision, r.reason, output=str(r.output),
                          event_id=r.event_id)
    if r.decision == "ASK":
        return ToolResult("approval_required", "ASK", r.reason,
                          approval_id=r.approval_id, event_id=r.event_id)
    if r.decision == "DENY":
        return ToolResult("blocked", "DENY", r.reason, event_id=r.event_id)
    return ToolResult("error", r.decision, r.reason, event_id=r.event_id)


class GuardedToolProvider:
    def __init__(
        self,
        client: AgentGuardClient,
        workspace: str,
        goal: str = "",
        session_id: str = "mcp",
        agent_id: str = "mcp-agent",
    ) -> None:
        self.ws = Workspace(workspace)
        self._executor = GuardedExecutor(
            client, build_registry(self.ws), session_id=session_id, agent_id=agent_id
        )
        self.goal = goal or "Assist with the current task within the authorized scope."

    def set_goal(self, goal: str) -> str:
        self.goal = goal
        return f"Session goal set. Agent Guard will evaluate every tool call against: {goal!r}"

    # -- guarded tool calls (ALLOW executes, DENY blocks, ASK defers) -------
    def _guarded(self, tool: str, resource: str, payload=None, destination=None) -> ToolResult:
        r = self._executor.execute(tool, resource, goal=self.goal, payload=payload,
                                   destination=destination, on_ask="defer")
        return _from_execution(r)

    def read_file(self, path: str) -> ToolResult:
        return self._guarded("read_file", path)

    def write_file(self, path: str, content: str) -> ToolResult:
        return self._guarded("write_file", path, payload=content)

    def delete_file(self, path: str) -> ToolResult:
        return self._guarded("delete_file", path)

    def run_command(self, command: str) -> ToolResult:
        return self._guarded("run_command", command, payload=command)

    def http_request(self, url: str, body: str | None = None) -> ToolResult:
        return self._guarded("http_request", url, payload=body, destination=url)

    # -- resume an approved ASK (fingerprint re-verified by the backend) ----
    def resume(self, approval_id: str, tool: str, resource: str,
               payload: str | None = None, destination: str | None = None) -> ToolResult:
        r = self._executor.execute_with_existing_approval(
            approval_id, tool, resource, goal=self.goal,
            payload=payload, destination=destination)
        # resume is terminal: it either executes or is blocked (no further ASK).
        if r.executed:
            return ToolResult("executed", r.decision, r.reason, output=str(r.output),
                              event_id=r.event_id)
        return ToolResult("blocked", r.decision, r.reason, approval_id=approval_id,
                          event_id=r.event_id)
