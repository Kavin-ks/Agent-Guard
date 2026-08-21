import { useCallback, useEffect, useState } from "react";
import { api, ApiError } from "../api/client";
import type { AuditEvent } from "../types";
import { StatCard, Loading, ErrorState, Empty } from "../components/common";
import { ActivityHeader, ActivityRow } from "../components/ActivityRow";
import { PipelineDiagram } from "../components/PipelineDiagram";
import { GoalAwarenessCard } from "../components/GoalAwarenessCard";
import { ActionDetail } from "../components/ActionDetail";

export function DashboardPage() {
  const [events, setEvents] = useState<AuditEvent[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [selected, setSelected] = useState<AuditEvent | null>(null);

  const load = useCallback(async () => {
    try {
      const res = await api.listAudit({ limit: 100 });
      setEvents(res.items);
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
  const pending = events.filter((e) => e.approval_status === "PENDING").length;
  const blocked = events.filter((e) => e.decision === "DENY").length;
  const highRisk = events.filter((e) => e.risk_score >= 60).length;
  const latest = events[0] ?? null;

  return (
    <>
      <div className="stat-grid">
        <StatCard label="Total Actions" value={total} />
        <StatCard label="Allowed" value={allowed} tone="allow" />
        <StatCard label="Awaiting Approval" value={pending} tone="ask" />
        <StatCard label="Blocked" value={blocked} tone="deny" />
        <StatCard label="High Risk" value={highRisk} tone="crit" />
      </div>

      <div className="grid-2">
        <div className="panel">
          <div className="panel-head">
            <span className="panel-title">Live activity</span>
            <span className="faint" style={{ fontSize: 12 }}>
              <span className="dot" style={{ background: "var(--allow)", display: "inline-block", marginRight: 6 }} />
              auto-refreshing
            </span>
          </div>
          <div className="panel-body">
            {total === 0 ? (
              <Empty message="No actions yet. Open Live Demo to run the scenarios." />
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

        <div style={{ display: "flex", flexDirection: "column", gap: 18 }}>
          <div className="panel">
            <div className="panel-head"><span className="panel-title">Security flow</span></div>
            <PipelineDiagram decision={latest?.decision ?? null} activeStage={latest ? "decision" : undefined} />
          </div>
          <GoalAwarenessCard event={latest} />
        </div>
      </div>

      {selected && <ActionDetail event={selected} onClose={() => setSelected(null)} />}
    </>
  );
}
