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
    detectors/         # modular sensitive-data detection: secrets, pii, financial, scan (Phase 4)
    paths.py risk.py pipeline.py goal_compiler.py fingerprint.py constants.py
  api/                 # HTTP service (Phase 2)
    main.py            # app startup:  uvicorn api.main:app
    config.py          # env-driven settings (pydantic-settings)
    auth.py            # X-API-Key auth (constant-time)
    schemas.py         # request/response contract (extra fields forbidden)
    deps.py bridge.py service.py   # DI, request->engine bridge, workflow service
    store/             # AuditStore/ApprovalStore interfaces + SQLite impl (persistent)
    routes/            # health.py, guard.py, audit.py, approvals.py
  adapter/             # SDK (Phase 6): client, executor (enforcement), registry, approval
  simulator/           # mock tools + 6-scenario CLI demo (python -m simulator.demo)
  examples/            # integration example (wrap an existing tool)
  benchmark/           # evaluation latency benchmark
  mcp_server/          # MCP integration: guarded tools over Model Context Protocol (Phase 10)
  tests/               # 180 backend tests
  Dockerfile           # backend + frontend images (Phase 9)
frontend/              # Dashboard (light-theme, Phase 7+10): React + TS + Vite, 16 tests
  src/api/client.ts    # centralized API layer (same-origin /api; key injected by proxy)
  src/pages/           # Dashboard, Approvals, Audit, Live Demo
  src/components/      # pipeline diagram, risk meter, action detail, activity
```

## Quick start — Docker (one command)

The whole stack (backend + dashboard + reverse proxy) runs with one command. The
nginx proxy serves the dashboard and forwards `/api/*` to the backend, injecting
the `X-API-Key` header **server-side** — the browser never sees the key.

```bash
git clone https://github.com/Kavin-ks/Agent-Guard.git
cd Agent-Guard
cp deploy/production.env.example deploy/production.env   # set AGENTGUARD_API_KEY (gitignored)
docker compose up --build                                # → http://localhost:8080
```

Then verify the full flow end-to-end (the client sends **no** API key — the proxy injects it):

```bash
deploy/demo_check.sh            # ALLOW→execute · DENY→blocked · ASK→approve→execute ·
                                # exfiltration→blocked · approval-reuse→blocked
```

The audit trail persists in the `agentguard-data` volume across restarts. Set
`ANTHROPIC_API_KEY` in `deploy/production.env` to enable the Claude advisor
(otherwise the offline heuristic is used). For local development without Docker,
use the manual setup below.

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

## Sensitive-data & exfiltration protection (Phase 4)

Agent Guard detects sensitive information **locally** and prevents an agent from
leaking it through an unauthorized external action.

**Modular detectors** (`agentguard/detectors/`, not one giant regex file):

| Module | Categories | Technique |
|--------|-----------|-----------|
| `secrets.py` | SECRET / AUTHENTICATION — API keys, AWS/GitHub/Slack/Stripe, JWT, private keys, bearer, `key=value` | regex + Shannon entropy |
| `pii.py` | PII — email, phone, Aadhaar, PAN | regex + **Verhoeff** checksum (Aadhaar) |
| `financial.py` | FINANCIAL — card numbers, IFSC | regex + **Luhn** checksum (cards) |
| `scan.py` | unifies all three, confidence-filtered | — |

**Structured, always-redacted findings** — every finding carries
`{category, subtype, severity (LOW/MEDIUM/HIGH/CRITICAL), confidence, fingerprint, location}`
and **never** the raw value (`sk-…1234`, `••••1111`). Checksums keep false
positives low: a random 16-digit string is not a card; a 12-digit number is not
an Aadhaar unless Verhoeff passes.

**Exfiltration rule** (the `secret_exfil` gate — highest authority): for an
outbound action to an **external** destination —
- a protected/secret file, or any **HIGH/CRITICAL** sensitive datum in the payload → **DENY**;
- **MEDIUM**-only (e.g. a lone email) → **ASK** (nuance: not every sensitive datum is a hard block);
- reading a secret locally is already denied by the protected-resource gate.

**LLM data-minimization** — the advisor receives only booleans + category labels
(`payload_contains_sensitive_data`, `sensitive_categories: ["SECRET","PII"]`),
never the payload or any value. Basic detection is deterministic and local; the
LLM is never responsible for secret detection.

**Deterministic authority preserved** — an exfiltration DENY can never be
overridden by the LLM, and an exfiltration DENY **creates no approval** (so there
is no DENY→APPROVE→EXECUTE path). Enforced end-to-end: `GuardedExecutor` never
calls the tool on DENY.

**Verified end-to-end** (live, with fake credentials): sending a simulated secret
+ email to `external.example` → `DENY`, `execution=BLOCKED`, no approval, and the
raw value appears **zero times** in the API response, the audit record, and the
SQLite file on disk.

```
SENSITIVE DATA → EXTERNAL ACTION → AGENT GUARD → DENY → TOOL NEVER EXECUTES → REDACTED AUDIT
```

**Honest limitation:** this is a heuristic defense layer, not a mathematical
guarantee. Novel/obfuscated encodings, split payloads, or unusual formats can
evade detection; the deterministic protected-resource, scope, and destination
gates remain the backstop. Known false positives (a benign email flagged PII →
ASK on egress) are handled by severity/confidence, not hard blocks.

## Production hardening (Phase 8)

Additive hardening around the unchanged authoritative engine:

- **Transport/HTTP**: security headers on every response (`X-Content-Type-Options`,
  `X-Frame-Options: DENY`, strict `Content-Security-Policy`, `Referrer-Policy`,
  `Cache-Control: no-store`); configurable **CORS** (default: no cross-origin);
  **request body-size limit** (413); **opt-in rate limiting** per API-key/IP (429
  with `Retry-After`, `/health` exempt; `0` = off so it never affects tests).
- **Safe errors**: an unhandled exception returns a generic `500` — internals,
  stack traces, and any secret-looking text never reach the client.
- **Log redaction**: a root logging filter scrubs secret-looking substrings, so
  even an accidental `logger.info(payload)` cannot leak a credential.
- **SQLite**: WAL + `busy_timeout=5000` + a process write-lock — concurrent writers
  don't error (tested with 4 threads × 20 writes).
- **Auth**: constant-time `X-API-Key`, read from env, fail-closed when unset.

### Security guarantees (what the tests enforce)

| Guarantee | Enforced by |
|-----------|-------------|
| Deterministic **DENY** always wins; LLM can never override it | `risk.py` (advisory excluded from DENY threshold) + `pipeline.py::_sanitize_advisory` |
| Raw secrets/PII/payloads never reach the LLM, response, audit, or DB | `advisors/base.py::build_advisor_request` (categories only) + redacted findings |
| A protected tool never runs before authorization | `GuardedExecutor` — tool called only on ALLOW / approved-consumed ASK |
| An approval can't be reused or applied to a different action | fingerprint (`fingerprint.py`) re-verified at `consume` |
| Exfiltration DENY creates no approval (no DENY→APPROVE→EXECUTE) | `service.py` (approval only for ASK) |
| LLM timeout/unavailable/malformed fails safe | `advisors/claude.py` → heuristic fallback; deterministic decision stands |

A dedicated suite (`tests/test_security_regression.py`) asserts these against the
real API+SDK: path traversal, policy bypass, malformed input, auth bypass, secret
leakage, approval reuse, fingerprint mismatch, LLM override attempts, and
tool-execution-before-authorization.

### Integration example

Wrap an existing tool without changing it (`backend/examples/wrap_existing_tool.py`):

```python
from adapter import GuardedExecutor, ToolRegistry, AutoApprove

def delete_file(resource, **_): ...        # your existing tool — no security code

reg = ToolRegistry()
reg.add("delete_file", operation="delete", resource_kind="file", fn=delete_file)
guard = GuardedExecutor(client, reg, AutoApprove())

result = guard.execute("delete_file", "src/old.jsx", goal="Build a React frontend")
if result.executed:            # runs only because Agent Guard authorized it
    ...
```

### Benchmark (deterministic engine, offline advisor)

`python -m benchmark.latency` — measured on this machine (n=20,000):

| avg | p50 | p95 | p99 | throughput |
|-----|-----|-----|-----|------------|
| 0.046 ms | 0.043 ms | 0.102 ms | 0.111 ms | ~21,700 evals/sec (1 thread) |

(An LLM advisory pass adds network round-trip latency; the deterministic gates —
the security-critical path — are sub-millisecond.)

### Production limitations (honest)

- Single shared API key; no per-agent identity / RBAC / rotation. Front with a
  real IdP/BFF for production.
- SQLite + a process lock suits a single node; use PostgreSQL behind the existing
  `AuditStore`/`ApprovalStore` interfaces for multi-node.
- Rate limiting is in-memory per process (not shared across replicas).
- Detection is heuristic (see Phase 4 limitations); the deterministic gates are
  the backstop.

## Agent & IDE integration via MCP (Phase 10)

Any MCP-capable IDE/agent (e.g. Claude Code) can connect its tools to the **Agent
Guard MCP server** (`backend/mcp_server/`). Every tool call is routed through the
existing `GuardedExecutor` → Agent Guard engine **before** it executes — no
security logic is duplicated. Guarded tools exposed over MCP: `guarded_read_file`,
`guarded_write_file`, `guarded_delete_file`, `guarded_run_command`,
`guarded_http_request`, plus `set_goal` and `agentguard_resume`.

**Flow:** `ALLOW` → the tool runs once. `DENY` → the tool never runs. `ASK` → the
call returns an `approval_id` and leaves a PENDING approval; a human approves in
the dashboard, then the agent calls `agentguard_resume` with the same arguments —
Agent Guard **re-verifies the fingerprint** before the tool runs.

**Setup (Claude Code):**
```bash
pip install -r backend/requirements-mcp.txt         # fastmcp + mcp
# copy deploy/claude_code_mcp.json into your project's .mcp.json and fill in:
#   AGENTGUARD_URL, AGENTGUARD_API_KEY, AGENTGUARD_WORKSPACE, AGENTGUARD_GOAL
```
The server runs as `python -m mcp_server` (stdio). The **Integration** page in the
dashboard shows connected agents, MCP status, connection instructions, and recent
guarded calls.

**Generic path (any agent):** use the SDK (`GuardedExecutor` — see
`examples/wrap_existing_tool.py`) or call `POST /guard/evaluate` directly and honor
the decision. The deterministic engine remains the sole authority.

**Trust boundary (unchanged, honest):** Agent Guard governs tool calls made
**through** the MCP server or SDK. It does not, and cannot, silently intercept an
IDE's own internal tools — the agent must connect its tools to Agent Guard.

> **UI:** the dashboard is a light-theme enterprise console (Dashboard, Approval
> Queue, Audit Log, Integration, Live Demo) — all fed by the real backend.

## Real agent activity, sessions & prompt history (Phase 11)

The dashboard shows **real connected-agent activity**, cleanly separated from demo
scenarios:

- **Origin tagging** — every evaluation carries a `source` (`agent` | `demo` |
  `sdk`). The Dashboard, Integration, and Audit "Live" views exclude `demo`; the
  Live Demo page is the only place demo scenarios appear (tagged `source=demo`).
- **Real sessions** — an agent (e.g. Antigravity over MCP) registers a **stable
  session** once per connection (`POST /agents/register`); every guarded call
  updates its `last_seen` and allow/ask/deny counts. `GET /agents` returns the
  registry with `connected`/`disconnected` status. Repeated calls reuse the one
  session — no duplicates. Demo activity is never registered as an agent.
- **Prompt → action → decision → result history** — each event stores the user
  `prompt` (secrets **redacted** to `[REDACTED]`), the proposed action, the
  decision + signals, approval status, and execution status. The Action detail
  drawer shows the full chain, including the redacted prompt and origin.

**The "many permission popups" problem (honest):** those dialogs are the IDE's
own per-tool-call / per-file confirmations — Agent Guard **cannot** suppress an
IDE's internal prompts (claiming otherwise would be dishonest). What we reduced:
a single stable MCP session (no re-registration per call) and a batch tool
`guarded_read_files([...])` that reads several files in **one** MCP invocation —
each path still evaluated individually, so a secret file in the batch is still
denied. Dangerous ops (write/delete/command/network) remain individually
evaluated. No security rule was weakened to cut prompts.

**What Agent Guard can/cannot intercept:** it governs tool calls routed **through**
the MCP server or SDK. It cannot silently intercept an IDE's built-in tools — the
agent must connect its tools to Agent Guard.

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
4. ✅ Sensitive-data detection + exfiltration prevention — **this phase**
5. ✅ Audit log + approval queue (persistent, human-in-the-loop)
6. ✅ Agent adapter SDK + execution enforcement + 5-scenario simulator — **this phase**
7. ✅ Professional React/TS dashboard (real backend integration) — **this phase**
8. Expanded automated tests
9. ✅ Docker Compose one-command deployment + demo packaging
10. ✅ Real MCP agent/IDE integration + light-theme production UI — **this phase**
