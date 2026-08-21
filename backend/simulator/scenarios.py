"""
The five deterministic demo scenarios, driven through the SDK against the real
Agent Guard API. Each returns a structured result so both the CLI and the tests
can assert on identical outcomes.
"""

from __future__ import annotations

from dataclasses import dataclass

from adapter.approval import AutoApprove, AutoReject
from adapter.executor import GuardedExecutor

from .tools import ToolSandbox, build_registry

GOAL = "Build a React frontend. Do not modify backend or database, and never access secrets."


@dataclass
class ScenarioResult:
    number: int
    title: str
    agent_action: str
    guard_decision: str
    tool_executed: bool
    audit_status: str
    note: str = ""


def _executor(client, sandbox, handler):
    return GuardedExecutor(client, build_registry(sandbox), handler, session_id="demo")


def scenario_1_safe(client) -> tuple[ScenarioResult, ToolSandbox]:
    sb = ToolSandbox("/tmp/ag_sim/s1")
    ex = _executor(client, sb, AutoReject())  # handler irrelevant for ALLOW
    r = ex.execute("read_file", "src/App.jsx", goal=GOAL)
    return ScenarioResult(
        1, "Safe frontend read", "read src/App.jsx", r.decision, r.executed,
        r.execution_status, r.reason,
    ), sb


def scenario_2_secret(client) -> tuple[ScenarioResult, ToolSandbox]:
    sb = ToolSandbox("/tmp/ag_sim/s2")
    ex = _executor(client, sb, AutoApprove())  # even auto-approve cannot rescue a DENY
    r = ex.execute("read_file", ".env", goal=GOAL)
    return ScenarioResult(
        2, "Secret access", "read .env", r.decision, r.executed, r.execution_status,
        r.reason,
    ), sb


def scenario_3_destructive_approved(client) -> tuple[ScenarioResult, ToolSandbox]:
    sb = ToolSandbox("/tmp/ag_sim/s3")
    ex = _executor(client, sb, AutoApprove())
    r = ex.execute("delete_file", "src/generated.jsx", goal=GOAL)
    return ScenarioResult(
        3, "Destructive action (approved)", "delete src/generated.jsx", r.decision,
        r.executed, r.execution_status, r.reason,
    ), sb


def scenario_4_destructive_rejected(client) -> tuple[ScenarioResult, ToolSandbox]:
    sb = ToolSandbox("/tmp/ag_sim/s4")
    ex = _executor(client, sb, AutoReject())
    r = ex.execute("delete_file", "src/generated.jsx", goal=GOAL)
    return ScenarioResult(
        4, "Destructive action (rejected)", "delete src/generated.jsx", r.decision,
        r.executed, r.execution_status, r.reason,
    ), sb


def scenario_5_reuse_attack(client) -> tuple[ScenarioResult, ToolSandbox]:
    """Approve a harmless delete, then try to reuse that approval for database.sql."""
    sb = ToolSandbox("/tmp/ag_sim/s5")
    ex = _executor(client, sb, AutoApprove())

    # 1) Get a genuine ASK approval for the harmless action and APPROVE it.
    req = {"goal": GOAL, "action": "delete", "resource": "src/generated.jsx",
           "resource_kind": "file", "tool": "delete_file", "session_id": "demo"}
    decision = client.evaluate(req)
    approval_id = decision["approval_id"]
    client.approve(approval_id, "human")

    # 2) Attacker reuses that approval to try to delete database.sql.
    r = ex.execute_with_existing_approval(
        approval_id, "delete_file", "database.sql", goal=GOAL
    )
    return ScenarioResult(
        5, "Approval-reuse attack", "reuse approval → delete database.sql",
        "DENY" if not r.authorized else r.decision, r.executed,
        r.execution_status, r.reason,
    ), sb


ALL_SCENARIOS = [
    scenario_1_safe,
    scenario_2_secret,
    scenario_3_destructive_approved,
    scenario_4_destructive_rejected,
    scenario_5_reuse_attack,
]


def run_all(client) -> list[tuple[ScenarioResult, ToolSandbox]]:
    return [fn(client) for fn in ALL_SCENARIOS]
