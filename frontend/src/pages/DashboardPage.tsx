import { useCallback, useEffect, useState } from "react";
import { api, ApiError } from "../api/client";
import type { AgentOut, AuditEvent } from "../types";
import { StatCard, Loading, ErrorState, Empty } from "../components/common";
import { ActivityHeader, ActivityRow } from "../components/ActivityRow";
import { PipelineDiagram } from "../components/PipelineDiagram";
import { ActionDetail } from "../components/ActionDetail";
import { formatTime } from "../lib/format";

export function DashboardPage() {
  const [events, setEvents] = useState<AuditEvent[] | null>(null);
  const [agents, setAgents] = useState<AgentOut[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [selected, setSelected] = useState<AuditEvent | null>(null);

  const load = useCallback(async () => {
    try {
      // LIVE agent activity only — demo scenarios are excluded from the monitor.
      const [audit, ag] = await Promise.all([
        api.listAudit({ exclude_source: "demo", limit: 100 }),
        api.listAgents().catch(() => []),
      ]);
      setEvents(audit.items);
      setAgents(ag);
      setError(null);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Failed to load activity");
    }
  }, []);

  useEffect(() => {
    load();
    const id = setInterval(load, 4000);
    return () => clearInterval(id);
  }, [load]);

  if (error && !events) return <ErrorState message={error} />;
  if (!events) return <Loading label="Connecting to Agent Guard…" />;

  const total = events.length;
  const allowed = events.filter((e) => e.decision === "ALLOW").length;
  const asked = events.filter((e) => e.decision === "ASK").length;
  const blocked = events.filter((e) => e.decision === "DENY").length;
  const highRisk = events.filter((e) => e.risk_score >= 60).length;
  const latest = events[0] ?? null;

  const connected = agents.filter((a) => a.status === "connected");
  const primary = connected[0] ?? agents[0] ?? null;
  const status = latest && latest.approval_status === "PENDING" ? "Waiting for approval"
    : latest && latest.decision === "DENY" ? "Blocked last action"
    : connected.length ? "Healthy" : "Idle";

  return (
    <>
      {/* Connected agent banner — real session, not demo */}
      <div className="panel" style={{ marginBottom: 18, display: "flex", flexWrap: "wrap",
        alignItems: "center", gap: 28, padding: "14px 18px" }}>
        <div>
          <div className="stat-label">Connected agent</div>
          <div style={{ display: "flex", alignItems: "center", gap: 8, fontWeight: 640, fontSize: 15, marginTop: 3 }}>
            <span className={`dot ${primary && primary.status === "connected" ? "ok" : "off"}`} />
            {primary ? primary.agent_name : "None connected"}
            {primary && <span className="faint" style={{ fontWeight: 400, fontSize: 12 }}>
              · {primary.status}</span>}
          </div>
        </div>
        <div>
          <div className="stat-label">Session</div>
          <div className="mono" style={{ fontSize: 13, marginTop: 4 }}>{primary?.session_id ?? "—"}</div>
        </div>
        <div>
          <div className="stat-label">Connection</div>
          <div style={{ fontSize: 13, marginTop: 4 }}>MCP / Agent Guard</div>
        </div>
        <div>
          <div className="stat-label">Status</div>
          <div style={{ fontSize: 13, marginTop: 4 }}>{status}</div>
        </div>
        {primary && (
          <div style={{ marginLeft: "auto" }} className="faint">
            last seen {formatTime(primary.last_seen)}
          </div>
        )}
      </div>

      <div className="stat-grid">
        <StatCard label="Guarded Calls" value={total} />
        <StatCard label="Allowed" value={allowed} tone="allow" />
        <StatCard label="Asked" value={asked} tone="ask" />
        <StatCard label="Denied" value={blocked} tone="deny" />
        <StatCard label="High Risk" value={highRisk} tone="crit" />
      </div>

      <div className="grid-2">
        <div className="panel">
          <div className="panel-head">
            <span className="panel-title">Recent activity</span>
            <span className="faint" style={{ fontSize: 12 }}>
              <span className="dot" style={{ background: "var(--allow)", display: "inline-block", marginRight: 6 }} />
              live · auto-refreshing
            </span>
          </div>
          <div className="panel-body">
            {total === 0 ? (
              <Empty message="No live agent activity yet. Connect an agent via Integration, or run the Live Demo." />
            ) : (
              <>
                <ActivityHeader />
                {events.slice(0, 40).map((e) => (
                  <ActivityRow key={e.event_id} e={e} onClick={() => setSelected(e)} />
                ))}
              </>
            )}
          </div>
        </div>

        <div className="panel">
          <div className="panel-head"><span className="panel-title">Security flow</span></div>
          <PipelineDiagram decision={latest?.decision ?? null} activeStage={latest ? "decision" : undefined} />
        </div>
      </div>

      {selected && <ActionDetail event={selected} onClose={() => setSelected(null)} />}
    </>
  );
}
