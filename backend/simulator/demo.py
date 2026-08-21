"""
CLI demonstration of Agent Guard runtime enforcement.

Runs the five scenarios through the SDK against a real in-process Agent Guard API
and prints, for each: what the agent tried, what the Guard decided, whether the
tool actually executed, and the audit status. Makes the enforcement obvious.

Run:
    cd backend
    .venv/bin/python -m simulator.demo
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from .harness import build_local_guard
from .scenarios import run_all

_GREEN = "\033[32m"
_RED = "\033[31m"
_YELLOW = "\033[33m"
_DIM = "\033[2m"
_BOLD = "\033[1m"
_RESET = "\033[0m"


def _decision_color(decision: str) -> str:
    return {"ALLOW": _GREEN, "ASK": _YELLOW, "DENY": _RED}.get(decision, _RED)


def _exec_line(executed: bool) -> str:
    return f"{_GREEN}EXECUTED{_RESET}" if executed else f"{_RED}NOT EXECUTED{_RESET}"


def main() -> int:
    print(f"\n{_BOLD}AGENT GUARD DEMO — runtime enforcement{_RESET}")
    print("─" * 52)
    print(f"{_DIM}Agent Guard evaluates & authorizes · the adapter enforces · "
          f"the tool performs the action.{_RESET}\n")

    tmp = Path(tempfile.mkdtemp(prefix="ag_demo_"))
    guard = build_local_guard(db_path=str(tmp / "demo.db"))

    blocked_ok = True
    executed_ok = True
    try:
        for result, sandbox in run_all(guard.client):
            dc = _decision_color(result.guard_decision)
            print(f"[{result.number}] {_BOLD}{result.title}{_RESET}")
            print(f"    Agent  → {result.agent_action}")
            print(f"    Guard  → {dc}{result.guard_decision}{_RESET}")
            print(f"    Tool   → {_exec_line(result.tool_executed)}")
            print(f"    Audit  → {result.audit_status}")
            if result.note:
                print(f"    {_DIM}{result.note}{_RESET}")
            print()

            # Sanity: the security invariants the demo is meant to prove.
            if result.number in (2, 4, 5, 6) and result.tool_executed:
                blocked_ok = False
            if result.number in (1, 3) and not result.tool_executed:
                executed_ok = False

        print("─" * 52)
        ok = blocked_ok and executed_ok
        verdict = f"{_GREEN}PASS{_RESET}" if ok else f"{_RED}FAIL{_RESET}"
        print(f"Enforcement invariants: {verdict}")
        print(f"{_DIM}  DENY / rejected / reuse-attack tools never executed: "
              f"{'yes' if blocked_ok else 'NO'}{_RESET}")
        print(f"{_DIM}  ALLOW / approved tools executed exactly once: "
              f"{'yes' if executed_ok else 'NO'}{_RESET}\n")
        return 0 if ok else 1
    finally:
        guard.close()


if __name__ == "__main__":
    raise SystemExit(main())
