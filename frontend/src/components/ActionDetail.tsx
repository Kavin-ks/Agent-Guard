import type { AuditEvent } from "../types";
import { DecisionBadge } from "./common";
import { RiskMeter } from "./RiskMeter";
import { formatDateTime } from "../lib/format";

// Slide-over detail for one audit event. Sensitive values are never shown —
// only redacted secret fingerprints the backend already produced.
export function ActionDetail({ event, onClose }: { event: AuditEvent; onClose: () => void }) {
  const isExfil = (event.matched_rule ?? "").startsWith("EXFIL");
  return (
    <>
      <div className="overlay" onClick={onClose} />
      <aside className="drawer" role="dialog" aria-label="Action detail">
        <div className="drawer-head">
          <div>
            <div style={{ fontWeight: 640, fontSize: 15 }}>Action detail</div>
            <div className="faint mono" style={{ fontSize: 12 }}>{event.event_id}</div>
          </div>
          <button className="close-x" onClick={onClose} aria-label="Close">×</button>
        </div>
        <div className="drawer-body">
          <div style={{ display: "flex", gap: 10, alignItems: "center", margin: "6px 0 14px", flexWrap: "wrap" }}>
            <DecisionBadge decision={event.decision} />
            {event.goal_drift && <span className="badge deny">GOAL DRIFT</span>}
            {event.sensitive_data_detected && <span className="badge ask">SENSITIVE DATA</span>}
            {isExfil && <span className="badge deny">EXFILTRATION BLOCKED</span>}
          </div>

          {event.sensitive_data_detected && (
            <>
              <div className="section-label">Sensitive data</div>
              <div className="kv"><span className="k">Detected</span><span className="v">DETECTED</span></div>
              <div className="kv">
                <span className="k">Categories</span>
                <span className="v">{event.sensitive_categories.join(", ") || "—"}</span>
              </div>
              {isExfil && (
                <div className="kv"><span className="k">Exfiltration</span>
                  <span className="v" style={{ color: "var(--deny)", fontWeight: 640 }}>BLOCKED — outbound to external destination</span></div>
              )}
              {event.sensitive.map((s, i) => (
                <div className="kv" key={i}>
                  <span className="k">{s.category} · {s.subtype}</span>
                  <span className="v mono">{s.fingerprint} · {s.severity} · {Math.round(s.confidence * 100)}%</span>
                </div>
              ))}
            </>
          )}

          <RiskMeter score={event.risk_score} signals={event.signals} />

          {event.prompt && (
            <>
              <div className="section-label">User prompt (redacted)</div>
              <div className="muted" style={{ fontSize: 13 }}>{event.prompt}</div>
            </>
          )}

          <div className="section-label">Goal</div>
          <div className="muted" style={{ fontSize: 13 }}>{event.goal_text || "—"}</div>

          <div className="section-label">Proposed action</div>
          <div className="kv"><span className="k">Operation</span><span className="v mono">{event.operation}</span></div>
          <div className="kv"><span className="k">Resource</span><span className="v mono">{event.resource}</span></div>
          <div className="kv"><span className="k">Tool</span><span className="v mono">{event.tool}</span></div>
          <div className="kv"><span className="k">Destination</span><span className="v mono">{event.destination ?? "—"}</span></div>
          <div className="kv"><span className="k">Agent</span><span className="v">{event.agent_id}</span></div>
          <div className="kv"><span className="k">Session</span><span className="v mono">{event.session_id}</span></div>
          <div className="kv"><span className="k">Origin</span><span className="v">{event.source}</span></div>

          <div className="section-label">Decision</div>
          <div className="kv"><span className="k">Final</span><span className="v"><DecisionBadge decision={event.decision} /></span></div>
          <div className="kv"><span className="k">Deterministic</span><span className="v">{event.deterministic_decision ?? "—"}</span></div>
          <div className="kv"><span className="k">Risk score</span><span className="v mono">{event.risk_score}/100</span></div>
          <div className="kv"><span className="k">Matched rule</span><span className="v mono">{event.matched_rule ?? "—"}</span></div>
          <div className="kv"><span className="k">Goal relevance</span><span className="v">{event.goal_relevance ?? "—"}</span></div>
          <div className="kv"><span className="k">Goal drift</span><span className="v">{event.goal_drift ? "Detected" : "None"}</span></div>
          <div className="kv"><span className="k">Explanation</span><span className="v">{event.reason}</span></div>

          <div className="section-label">Workflow</div>
          <div className="kv"><span className="k">Approval status</span><span className="v">{event.approval_status ?? "—"}</span></div>
          <div className="kv"><span className="k">Execution status</span><span className="v mono">{event.execution_status}</span></div>
          <div className="kv"><span className="k">Timestamp</span><span className="v">{formatDateTime(event.created_at)}</span></div>
          <div className="kv"><span className="k">Fingerprint</span><span className="v mono" style={{ fontSize: 11 }}>{event.action_fingerprint}</span></div>

          {event.secrets.length > 0 && (
            <>
              <div className="section-label">Detected secrets (redacted)</div>
              {event.secrets.map((s, i) => (
                <div className="kv" key={i}>
                  <span className="k">{s.type}</span>
                  <span className="v mono">{s.fingerprint} · entropy {s.entropy}</span>
                </div>
              ))}
            </>
          )}

          <div className="section-label">Security signals</div>
          {event.signals.length === 0 && <div className="faint">No signals — clean, in-scope action.</div>}
          {event.signals.map((s, i) => (
            <div className="signal" key={i}>
              <div className="signal-top">
                <span className="signal-gate">{s.gate}{s.advisory ? " · advisory" : ""}</span>
                <span className={`badge ${s.severity === "deny" ? "deny" : s.severity === "ask" ? "ask" : "muted"}`}>{s.severity} · +{s.risk_points}</span>
              </div>
              <div className="signal-reason">{s.reason}</div>
            </div>
          ))}
        </div>
      </aside>
    </>
  );
}
