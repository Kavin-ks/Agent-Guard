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
          ┌────────────────── SECURITY ENGINE ───────────────────┐
          │                                                       │
          │  (1) DETERMINISTIC GATES  ── the security authority   │
          │      secret_exfil → protected_resource →              │
          │      policy_scope → destructive → external_comm       │
          │              │                                        │
          │              ▼  deterministic decision                │
          │  (2) LLM RELEVANCE ADVISOR  ── advisory only          │
          │      goal ↔ action semantic fit  (Claude / heuristic) │
          │      may escalate ALLOW→ASK; NEVER creates/cancels DENY│
          │              │                                        │
          │              ▼  final = max-severity(det, advisory)   │
          └───────────────────────────────────────────────────────┘
                              │
                    ALLOW  /  ASK  /  DENY   (+ reason, relevance, signals)
   ◄──────────────────────────┘
   agent executes ONLY on ALLOW (ASK -> ask a human; DENY -> block)
```

Deterministic gates run in authority order:
`secret_exfil → protected_resource → policy_scope → destructive → external_comm`.
The relevance advisor runs *after* them and only ever adds advisory risk.

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
    deps.py bridge.py service.py   # DI, request->engine bridge, workflow service
    store/             # AuditStore/ApprovalStore interfaces + SQLite impl (persistent)
    routes/            # health.py, guard.py, audit.py, approvals.py
  adapter/             # SDK (Phase 6): client, executor (enforcement), registry, approval
  simulator/           # mock tools + 5-scenario CLI demo (python -m simulator.demo)
  tests/               # 121 backend tests
frontend/              # Dashboard (Phase 7): React + TS + Vite, 13 tests
  src/api/client.ts    # centralized API layer (same-origin /api; key injected by proxy)
  src/pages/           # Dashboard, Approvals, Audit, Live Demo
  src/components/      # pipeline diagram, risk meter, action detail, activity
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
| `ANTHROPIC_API_KEY` | no | Enables the Claude relevance advisor. Without it, the offline heuristic advisor is used — goal-awareness still works. Tests never need it. |
| `AGENTGUARD_ADVISOR` | no | `auto` (default: Claude if key present, else heuristic), `llm`, `heuristic`, or `off`. |
| `AGENTGUARD_ADVISOR_MODEL` | no | Advisor model (default `claude-opus-5`). |

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
| `POST` | `/guard/evaluate` | `X-API-Key` | evaluate a proposed action → decision (+ audit record; +approval if ASK) |
| `GET`  | `/audit` | `X-API-Key` | list audit events (filter: decision, session, resource, min_risk, goal_drift, approval_status, since/until; paginated) |
| `GET`  | `/audit/{event_id}` | `X-API-Key` | one redacted audit event |
| `POST` | `/audit/{event_id}/execution` | `X-API-Key` | record the agent's self-reported execution outcome |
| `GET`  | `/approvals` | `X-API-Key` | list approval requests (filter by status) |
| `GET`  | `/approvals/{id}` | `X-API-Key` | one approval request |
| `POST` | `/approvals/{id}/approve` | `X-API-Key` | approve a PENDING ASK |
| `POST` | `/approvals/{id}/reject` | `X-API-Key` | reject a PENDING ASK |
| `POST` | `/approvals/{id}/consume` | `X-API-Key` | **fingerprint-verified pre-execution gate** — authorizes the exact approved action only |

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

## Goal-aware intelligence (Phase 3)

Agent Guard understands the **semantic relationship** between the user's goal and
each proposed action — catching actions that are technically permitted but don't
serve the objective (goal drift).

**Deterministic vs. AI responsibilities**

| Layer | Does | Authority |
|-------|------|-----------|
| Deterministic gates | secrets, protected files, scope, destructive, external comms | **Decides** — can force ALLOW/ASK/DENY |
| Goal compiler | goal → inspectable `GoalRepresentation` + `Policy` (keyword-based) | Deterministic; can only *add* restrictions |
| LLM relevance advisor | rates goal↔action fit (HIGH/MEDIUM/LOW), flags drift | **Advises only** — can escalate ALLOW→ASK, never create/cancel a DENY |

The advisor (`ClaudeRelevanceAdvisor`, default model `claude-opus-5`, configurable)
returns a structured `{relevance, confidence, goal_drift, recommended_action, reason}`.
Its authority is bounded in three places: `pipeline.py::_sanitize_advisory` caps
advisory severity at ASK; `risk.py` excludes advisory points from the DENY
threshold (a DENY must be reachable from **deterministic** points alone); and the
pipeline reports `deterministic_decision` alongside the `final` decision so the two
are always comparable.

**Goal-drift detection.** An action with LOW goal relevance and no topical
connection to the objective (e.g. "search unrelated cryptocurrency prices" during
"build a React frontend") is flagged `goal_drift: true` and escalated to ASK/DENY
per policy — with an explainable reason.

**Data minimization — exactly what the LLM receives.** The advisor is given ONLY
a minimized `AdvisorRequest` (`advisors/base.py::build_advisor_request`):

- ✅ sent: the goal text, operation, resource path/URL, tool name, destination,
  `payload_present` (bool), `payload_contains_secret` (bool), and context **keys**.
- ❌ never sent: the raw payload, file contents, any secret value, or context values.

Secret presence is detected locally and passed as a boolean. This is verified by a
test that routes a real secret through the engine and asserts it never appears in
what the advisor received.

**Failure behavior (never fail-open).** If the LLM is unavailable, times out, or
returns malformed JSON, the advisor falls back to the deterministic offline
heuristic; if even that is bypassed, the advisory layer contributes nothing and the
**deterministic decision stands**. The advisory layer can only ever *raise*
restriction, so its absence can never turn a DENY/ASK into an ALLOW. The response
distinguishes `deterministic_decision`, `advisory_*`, and the final `decision`.

## Human-in-the-loop workflow (Phase 5)

Every decision is **persisted** to SQLite (survives restarts) as a redacted audit
event. `ASK` decisions create a **human approval request**; the approved action is
bound to an integrity fingerprint so an approval can never be reused for a
different action.

```
POST /guard/evaluate
   ├─ ALLOW → audit event                          → agent may proceed
   ├─ DENY  → audit event (execution=BLOCKED)       → no approval possible
   └─ ASK   → audit event + PENDING approval        → human decides
                 POST /approvals/{id}/approve|reject
                 POST /approvals/{id}/consume  ← re-checks fingerprint before execution
```

- **Example 1 — normal frontend action.** `write src/App.jsx` → **ALLOW**, audit
  record created.
- **Example 2 — `.env` access.** `read .env` → **DENY**, audit record created,
  `execution_status=BLOCKED`, **no approval possible**.
- **Example 3 — destructive action.** `delete src/generated.jsx` → **ASK**,
  approval request created; human `POST …/approve` → `APPROVED`, recorded.
- **Example 4 — human rejects.** `POST …/reject` → `REJECTED`; a later
  `consume` returns `authorized: false`.

**Approval security model — the queue is not a bypass.** (1) A `DENY` never creates
an approval, so it can never become `APPROVED`. (2) Approvals exist only for `ASK`.
(3) Each approval is bound to an **action fingerprint** = SHA-256 over goal + policy
+ operation + resource + destination + payload-hash + context. (4) `consume`
re-derives the fingerprint from the action the agent actually intends to run; any
change (action, resource, goal, policy, context) → mismatch → **not authorized**.
(5) Consumed and (6) expired approvals are refused. (7) The final state is always
derived from server-side stored data — a client-provided decision is never trusted.

**Action-integrity attack (blocked, tested).** Approve a harmless
`delete src/generated.jsx`, then try to `consume` it as `delete database.sql`:

```json
{ "authorized": false,
  "reason": "action fingerprint mismatch — the goal, policy, action, resource, or context changed since approval; the approval does not apply." }
```

**Trust boundary (decision ≠ execution).** Agent Guard evaluates and records; it
**never executes** the action. Responses carry `execution_status` and an
`execution_note` saying so. `POST /audit/{id}/execution` lets the agent *report*
what it actually did — clearly labeled as agent-reported, never asserted by Agent
Guard.

## Agent Guard SDK — real execution enforcement (Phase 6)

Phases 1–5 *decide*. The SDK (`backend/adapter/`) *enforces*: it sits between an
agent and its tools and **will not invoke a tool until the action has been
evaluated and authorized**.

```
AI AGENT → GuardedExecutor.execute(tool, resource, goal=…)
              │
              ├─ POST /guard/evaluate  (FIRST — before any tool call)
              │
              ├─ ALLOW → run tool → record execution
              ├─ DENY  → tool NEVER called → audit BLOCKED
              └─ ASK   → human approve/reject → consume (fingerprint re-checked)
                              └─ authorized → run tool (exactly once)
                              └─ refused / mismatch / expired / error → tool NEVER called
```

**Division of responsibility (say it exactly):**
Agent Guard **evaluates and authorizes**. The adapter **enforces** the decision.
The external tool **performs** the actual action. Agent Guard never executes tools.

**Fail-closed.** Any uncertainty — API unavailable, timeout, malformed response,
auth failure, expired approval, rejection, fingerprint mismatch — results in the
tool **not** being called (`decision: ERROR/DENY/ASK`, `executed: false`).

**Tool registry.** A tool is registered once with its operation + resource kind
and a callable; the executor builds the evaluate request from that metadata, so
tool authors write no security code:

```python
from adapter import AgentGuardClient, GuardedExecutor, ToolRegistry, AutoApprove

reg = ToolRegistry()
reg.add("read_file", operation="read", resource_kind="file", fn=my_read_file)
reg.add("delete_file", operation="delete", resource_kind="file", fn=my_delete_file)

client = AgentGuardClient(base_url="http://127.0.0.1:8000", api_key=API_KEY)
guard = GuardedExecutor(client, reg, approval_handler=AutoApprove())  # or a human prompt

# Instead of calling delete_file(path) directly, the agent calls:
result = guard.execute("delete_file", "src/generated.jsx",
                       goal="Build a React frontend")
if result.executed:
    use(result.output)      # tool ran, and only because Guard authorized it
```

This is **framework-neutral** — it wraps any callable, so an Anthropic/OpenAI/
Google/LangChain/custom agent integrates the same way. No provider is hard-coded.

**Trust boundary (explicit).** The adapter can only enforce tools invoked
**through it**. If an agent bypasses the adapter and calls its tool directly,
Agent Guard cannot stop that — integration is required. We do not claim to
magically control an arbitrary agent.

**Simulator + CLI demo.** A deterministic simulator with mock tools (`read_file`,
`write_file`, `delete_file`, `send_external_request` — the last only *records*
that it would have sent, never a real network call) drives the five scenarios
through the **real** API. Run it:

```bash
cd backend
.venv/bin/python -m simulator.demo
```

| # | Scenario | Guard | Tool | Proven |
|---|----------|-------|------|--------|
| 1 | `read src/App.jsx` | ALLOW | **executed** | safe action runs |
| 2 | `read .env` | DENY | **not executed** | secret access blocked |
| 3 | `delete src/generated.jsx` → approve | ASK→AUTH | **executed once** | HITL approval |
| 4 | `delete src/generated.jsx` → reject | ASK | **not executed** | rejection blocks |
| 5 | reuse approval → `delete database.sql` | **refused** | **not executed** | fingerprint integrity |

## Dashboard (Phase 7)

A professional React + TypeScript + Vite security console in `frontend/`. It is a
**visualization/control layer only** — it holds no authorization logic and treats
backend state as authoritative. Four pages:

- **Dashboard** — summary stats (Total / Allowed / Awaiting Approval / Blocked /
  High Risk), a live auto-refreshing activity stream, the Agent→Guard→Decision
  pipeline, and the goal-awareness panel. Click any row for a full redacted detail.
- **Approval Queue** — pending ASK cards with **Approve / Reject** that call the
  real backend (never simulated in React).
- **Audit Log** — filter by decision / risk / goal-drift, paginated, click-through detail.
- **Live Demo** — runs the five scenarios against the real API; the browser acts
  as the agent adapter (evaluate → approve → fingerprint-verified consume) and
  only reports execution after authorization.

### Run the dashboard

```bash
# 1) backend (terminal A)
cd backend
AGENTGUARD_API_KEY=demo-key AGENTGUARD_ADVISOR=heuristic \
  .venv/bin/uvicorn api.main:app --port 8000

# 2) frontend (terminal B)
cd frontend
npm install
cp .env.example .env      # set AGENTGUARD_API_KEY to match the backend
AGENTGUARD_API_KEY=demo-key npm run dev   # http://localhost:5173
```

### API key handling (no secret in the browser)

The browser bundle **never** contains the API key. In dev, the Vite proxy
(`vite.config.ts`) forwards `/api/*` to the backend and injects the `X-API-Key`
header **server-side** from `AGENTGUARD_API_KEY` (a Node-process env var, not a
`VITE_`-prefixed one, so it is never bundled). In production, a reverse proxy /
BFF performs the same injection. The frontend only ever calls same-origin `/api`.
Verified: a POST through the proxy with no client-side key still returns a real
`DENY` from the backend.

### Frontend tests / build

```bash
cd frontend
npm test        # 13 Vitest + React Testing Library tests
npm run build   # type-check + production build -> dist/
```

## 10. Security model

- **Deterministic gates are authoritative.** Hard gates (glob matches, secret
  detection, destructive patterns) can force `DENY`/`ASK`. The LLM advisor is
  sanitized so it can escalate a borderline `ALLOW` to `ASK` but can **never**
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
.venv/bin/python -m pytest -q      # 121 tests
```

## Roadmap

1. ✅ Engine core (models, gates, risk)
2. ✅ Action interception API (`/guard/evaluate`, auth, validation)
3. ✅ Goal-aware intelligence (goal representation, relevance advisor, drift) — **this phase**
4. Extended risk + sensitive-data detection
5. ✅ Audit log + approval queue (persistent, human-in-the-loop) — **this phase**
6. ✅ Agent adapter SDK + execution enforcement + 5-scenario simulator — **this phase**
7. ✅ Professional React/TS dashboard (real backend integration) — **this phase**
8. Expanded automated tests
9. Docker / deployment / docs
