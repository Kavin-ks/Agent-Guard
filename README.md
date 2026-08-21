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

---

## 1. What Agent Guard is

A security layer an AI agent calls **before** it executes a tool action. Agent
Guard evaluates the action and returns `ALLOW` / `ASK` / `DENY` with a risk score
and reason. **It never executes the action itself** — the agent honors the
verdict. This makes it a reusable authorization firewall any tool-using agent can
put in front of its file, network, shell, and database operations.

## 2. Architecture

```
AI AGENT
   │  proposes an action
   ▼
AGENT ADAPTER  ──HTTP──►  AGENT GUARD API  (FastAPI)
                              │
                              ▼
                       SECURITY ENGINE  (pure, deterministic)
                              │  ordered gates + risk scoring
                              ▼
                    ALLOW  /  ASK  /  DENY   (+ reason, signals)
   ◄──────────────────────────┘
   agent executes ONLY on ALLOW (ASK -> ask a human)
```

Deterministic gates run in authority order:
`secret_exfil → protected_resource → policy_scope → destructive → external_comm`.

```
backend/
  agentguard/          # PURE engine (Phase 1) — no I/O, never executes actions
    models.py          # Action, Resource, Policy, Signal, DecisionResult
    gates/             # the 5 deterministic gates
    detectors/secrets.py
    paths.py risk.py pipeline.py goal_compiler.py constants.py
  api/                 # HTTP service (Phase 2)
    main.py            # app startup:  uvicorn api.main:app
    config.py          # env-driven settings (pydantic-settings)
    auth.py            # X-API-Key auth (constant-time)
    schemas.py         # request/response contract (extra fields forbidden)
    deps.py            # engine singleton + request→engine bridge
    routes/            # health.py, guard.py
  tests/               # 57 tests (engine + API)
```

## 3. Install

```bash
git clone https://github.com/Kavin-ks/Agent-Guard.git
cd Agent-Guard/backend
python3 -m venv .venv
.venv/bin/pip install -r requirements-dev.txt
```

## 4. Configure environment variables

Copy the example and set an API key (never commit the real `.env`):

```bash
cp ../.env.example ./.env
```

| Variable | Required | Purpose |
|----------|----------|---------|
| `AGENTGUARD_API_KEY` | **yes** | Shared key required on `/guard/*`. If unset, the API **fails closed** (rejects all protected requests). |
| `ANTHROPIC_API_KEY` | no (Phase 3) | LLM goal reasoning. The engine/tests do not need it. |

```bash
export AGENTGUARD_API_KEY="choose-a-strong-key"
```

## 5. Start the API

```bash
cd backend
.venv/bin/uvicorn api.main:app --reload --port 8000
```

Interactive docs: `http://127.0.0.1:8000/docs`.

## 6. API examples

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| `GET`  | `/health` | none | service + engine status, gate list |
| `POST` | `/guard/evaluate` | `X-API-Key` | evaluate a proposed action → decision |

Request body (`POST /guard/evaluate`):

```json
{
  "goal": "Build a React frontend without accessing backend, database, or secrets",
  "action": "read",              // read|write|delete|execute|network|transmit
  "resource": ".env",
  "resource_kind": "file",       // optional; inferred if omitted
  "tool": "fs",                  // optional
  "payload": null,               // content being written/sent (scanned, never stored raw)
  "destination": null,           // for network/transmit
  "context": {},
  "session_id": "default",       // optional
  "policy": null                 // optional explicit scope overrides (can only tighten protections)
}
```

### 7. Example — ALLOW

```bash
curl -s -X POST http://127.0.0.1:8000/guard/evaluate \
  -H "X-API-Key: $AGENTGUARD_API_KEY" -H "Content-Type: application/json" \
  -d '{"goal":"Build a React frontend, no backend/database/secrets","action":"write","resource":"src/Navbar.jsx"}'
```
```json
{ "decision": "ALLOW", "risk_score": 14,
  "reason": "Action is within the authorized goal scope and assessed as low risk.",
  "sensitive_data_detected": false, "signals": [] }
```

### 8. Example — ASK

```bash
curl -s -X POST http://127.0.0.1:8000/guard/evaluate \
  -H "X-API-Key: $AGENTGUARD_API_KEY" -H "Content-Type: application/json" \
  -d '{"goal":"Build a React frontend","action":"delete","resource":"src/legacy/old.jsx"}'
```
```json
{ "decision": "ASK", "risk_score": 60,
  "reason": "Destructive or irreversible action detected (delete of 'src/legacy/old.jsx'); human approval is required before execution.",
  "matched_rule": "DESTRUCTIVE::approval-required" }
```

### 9. Example — DENY

```bash
curl -s -X POST http://127.0.0.1:8000/guard/evaluate \
  -H "X-API-Key: $AGENTGUARD_API_KEY" -H "Content-Type: application/json" \
  -d '{"goal":"Build a React frontend, no backend/database/secrets","action":"read","resource":".env"}'
```
```json
{ "decision": "DENY", "risk_score": 94, "matched_rule": "PR::**/.env",
  "reason": "Access to protected resource '.env' is not authorized and may expose sensitive credentials or secrets." }
```

Exfiltration (secret redacted in the response):
```json
{ "decision": "DENY", "risk_score": 100, "sensitive_data_detected": true,
  "secrets": [ { "type": "anthropic_api_key", "fingerprint": "sk-…HHHH", "entropy": 4.6 } ] }
```

## 10. Security model

- **Deterministic gates are authoritative.** Hard gates (glob matches, secret
  detection, destructive patterns) can force `DENY`/`ASK`. The LLM advisor (Phase 3)
  is sanitized so it can escalate a borderline `ALLOW` to `ASK` but can **never**
  create nor override a hard `DENY` — enforced in `risk.py` (a DENY must be
  reachable from deterministic points alone) and `pipeline.py::_sanitize_advisory`.
- **A caller/policy can only tighten, never loosen** built-in protections. A
  request that whitelists `**` still cannot read `.env`.
- **Secrets are never logged, stored, or returned raw** — only redacted
  fingerprints (`sk-…HHHH`) + type + entropy.
- **Auth**: `X-API-Key` (constant-time compare), read from env, never echoed.
  Missing key on the server ⇒ fail-closed (401 on all protected routes).
- **Strict validation**: unknown/extra fields and bad operations ⇒ `422`.
- **Traversal/case/encoding-safe** path matching (`../../.env`, `.ENV`, `%2e…`).
- Agent Guard **only evaluates**; it never runs the agent's action. No `eval`,
  no shell execution of caller input. A gate that errors escalates to `ASK`.

## 11. Current limitations

- Enforcement is advisory to the caller: not-executing-on-DENY is the agent/
  adapter's responsibility (the SDK lands in Phase 6).
- Goal→policy compilation is currently deterministic/keyword-based; the LLM
  compiler is Phase 3 (built-in protections apply regardless).
- Secret detection is pattern/entropy-based → possible false negatives on exotic
  formats. It's a control, not a guarantee.
- No persistence/audit store or approval queue yet (Phase 5). Single shared API
  key (no per-agent identity/rate-limiting) — prototype-grade auth.

## 12. Example integration flow for an AI agent

```python
import requests

def guarded_execute(goal, action, resource, run_tool, **kw):
    resp = requests.post(
        "http://127.0.0.1:8000/guard/evaluate",
        headers={"X-API-Key": API_KEY},
        json={"goal": goal, "action": action, "resource": resource, **kw},
        timeout=5,
    ).json()

    if resp["decision"] == "ALLOW":
        return run_tool()                       # agent proceeds
    if resp["decision"] == "ASK":
        if ask_human(resp["reason"]):           # human-in-the-loop
            return run_tool()
        return None
    # DENY
    raise PermissionError(resp["reason"])       # agent must not execute
```

## Run the tests

```bash
cd backend
.venv/bin/python -m pytest -q      # 57 tests: engine + API
```

## Roadmap

1. ✅ Engine core (models, gates, risk)
2. ✅ Action interception API (`/guard/evaluate`, auth, validation) — **this phase**
3. Goal → policy compiler (deterministic + Claude)
4. Extended risk + sensitive-data detection
5. Audit log + approval queue
6. Agent adapter SDK + 5-scenario simulator
7. Professional React/TS dashboard
8. Expanded automated tests
9. Docker / deployment / docs
