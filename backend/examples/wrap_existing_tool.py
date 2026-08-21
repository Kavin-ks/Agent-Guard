"""
Integration example: protect an EXISTING agent tool with Agent Guard without
rewriting the tool.

The tool below (`delete_file`) is an ordinary function with no security code. We
register it with a ToolRegistry and call it through a GuardedExecutor: Agent Guard
evaluates the action first and the tool runs only if authorized. The tool itself
is unchanged — this is the whole integration surface.

Run:
    cd backend
    .venv/bin/python -m examples.wrap_existing_tool
"""

from __future__ import annotations

from adapter import GuardedExecutor, ToolRegistry, AutoApprove
from simulator.harness import build_local_guard  # spins up a real in-process Agent Guard


# --- 1) An existing tool. Note: no security logic here. --------------------
def delete_file(resource: str, **_kwargs) -> str:
    # (a real implementation would remove the file; we just report)
    return f"deleted {resource}"


def read_file(resource: str, **_kwargs) -> str:
    return f"contents of {resource}"


def main() -> None:
    # --- 2) Register tools with their operation + resource kind. -----------
    registry = ToolRegistry()
    registry.add("read_file", operation="read", resource_kind="file", fn=read_file)
    registry.add("delete_file", operation="delete", resource_kind="file", fn=delete_file)

    # --- 3) Point the SDK at a running Agent Guard. In production this is
    #        AgentGuardClient(base_url=..., api_key=...). Here we use a real
    #        in-process instance so the example is self-contained. -----------
    guard = build_local_guard(db_path="/tmp/agentguard_example.db", api_key="example-key")
    executor = GuardedExecutor(guard.client, registry, AutoApprove(), session_id="example")

    goal = "Build a React frontend. Do not access secrets."

    print("Agent Guard integration example\n" + "-" * 40)
    for tool, resource in [("read_file", "src/App.jsx"),   # ALLOW
                           ("read_file", ".env"),          # DENY (protected)
                           ("delete_file", "src/old.jsx")]:  # ASK -> auto-approved
        result = executor.execute(tool, resource, goal=goal)
        ran = "EXECUTED" if result.executed else "NOT EXECUTED"
        print(f"{tool}({resource:14s}) -> {result.decision:5s} | {ran} | {result.reason[:60]}")

    guard.close()


if __name__ == "__main__":
    main()
