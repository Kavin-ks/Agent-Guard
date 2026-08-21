# Agent Guard

**Runtime Goal-Aware Authorization Firewall for Autonomous AI Agents**

Traditional permission systems decide *what* tools an agent may use. They do not
continuously check whether **each individual action still matches the user's
original goal and security constraints**. Agent Guard sits between an autonomous
agent and its tools and answers one question for every proposed action:

> *Given the user's goal, policy, this resource, this payload, and the risk — should this specific action execute right now?*

The answer is one of three decisions, each with an explainable reason:

| Decision | Meaning |
|----------|---------|
| **ALLOW** | Relevant to the goal, in-scope, low risk. |
| **ASK**   | Possibly legitimate but sensitive/destructive — needs a human. |
| **DENY**  | Violates goal, scope, a protected resource, or leaks a secret. |

```
USER GOAL → AI AGENT → AGENT GUARD → [goal + policy + risk + secret eval] → ALLOW / ASK / DENY → TOOL
```

## Core principle: deterministic gates have authority; the LLM only advises

Agent Guard combines **deterministic security controls** with **goal-aware AI
reasoning**, and the ordering of authority is deliberate and enforced in code:

- **Hard gates** (glob matches, secret detection, destructive-command patterns)
  can force `DENY`/`ASK` on their own.
- The **LLM** contributes a goal-relevance *opinion*. It is sanitized so it can
  escalate a borderline `ALLOW` to `ASK` but can **never** create nor override a
  hard `DENY`. (`agentguard/pipeline.py::_sanitize_advisory`,
  `agentguard/risk.py` deterministic-score guard.)

This is why an LLM is never the only thing between an agent and your `.env`.

## What's in this repo (Phase 1 — engine core)

```
backend/agentguard/            # PURE engine — no I/O, no action execution
  models.py                    # Pydantic v2: Action, Resource, Policy, Signal, DecisionResult
  paths.py                     # traversal/case/encoding-safe path + glob matching
  detectors/secrets.py         # deterministic secret detection (regex + entropy), redacted
  gates/                       # secret_exfil, protected_resource, policy_scope, destructive, external_comm
  risk.py                      # two-tier risk aggregation → ALLOW / ASK / DENY
  pipeline.py                  # ordered gate runner + LLM-advisory sanitizer
  constants.py                 # built-in protected globs, destructive patterns, risk weights
backend/tests/                 # pytest security suite (44 tests)
```

## Run the tests

```bash
cd backend
python3 -m venv .venv && .venv/bin/pip install pydantic pytest
.venv/bin/python -m pytest -q
```

## Security properties (Phase 1)

- Raw secrets are **never** logged, stored, or returned — only redacted
  fingerprints (`sk-…HHHH`) plus a type and entropy.
- Built-in protected resources (`.env`, keys, credentials, `.ssh`, …) **cannot
  be re-enabled by a user policy**, even one that allows `**`.
- Path traversal (`../../.env`), case variation (`.ENV`), and URL-encoding are
  normalized before matching.
- The engine **only evaluates**; it never executes the agent's action.
- No `eval`, no shell execution of agent input. Malformed actions are rejected
  by strict Pydantic validation.
- Fail-closed: a gate that errors escalates to `ASK`, never `ALLOW`.

## Real vs. simulated (honest disclosure)

**Genuinely functional:** the evaluation engine, all deterministic gates, secret
detection, risk scoring, and the full test suite. **Simulated for the demo:** the
"autonomous agent" will be our own SDK caller / scenario simulator (Phase 6), not
a third-party agent auto-hooked into its internals. Agent Guard exposes a clean
integration boundary (SDK now, MCP server designed-for) that a real agent *could*
adopt; we do not claim silent interception of closed agents.

## Roadmap

1. ✅ Engine core (models, gates, risk) — **this phase**
2. Action interception API (`/guard/evaluate`, FastAPI)
3. Goal → policy compiler (deterministic + Claude)
4. Extended risk + sensitive-data detection
5. Audit log + approval queue
6. Agent adapter SDK + 5-scenario simulator
7. Professional React/TS dashboard
8. Expanded automated tests
9. Docker / deployment / docs
