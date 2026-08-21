import { useCallback, useEffect, useState } from "react";
import { api, ApiError, type AuditFilters } from "../api/client";
import type { AuditEvent } from "../types";
import { Loading, ErrorState, Empty, DecisionBadge, RiskTag } from "../components/common";
import { ActionDetail } from "../components/ActionDetail";
import { formatTime } from "../lib/format";

const PAGE = 15;

export function AuditPage() {
  const [decision, setDecision] = useState("");
  const [risk, setRisk] = useState("");
  const [drift, setDrift] = useState("");
  const [offset, setOffset] = useState(0);
  const [data, setData] = useState<{ items: AuditEvent[]; total: number } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [selected, setSelected] = useState<AuditEvent | null>(null);

  const load = useCallback(async () => {
    const f: AuditFilters = { limit: PAGE, offset };
    if (decision) f.decision = decision;
    if (drift) f.goal_drift = drift === "drift";
    if (risk) f.min_risk = risk === "critical" ? 85 : risk === "high" ? 60 : risk === "medium" ? 40 : 0;
    try {
      setData(await api.listAudit(f));
      setError(null);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Failed to load audit log");
    }
  }, [decision, risk, drift, offset]);

  useEffect(() => { load(); }, [load]);
  useEffect(() => { setOffset(0); }, [decision, risk, drift]);

  if (error && !data) return <ErrorState message={error} />;
  if (!data) return <Loading label="Loading audit log…" />;

  const pages = Math.max(1, Math.ceil(data.total / PAGE));
  const page = Math.floor(offset / PAGE) + 1;

  return (
    <>
      <div className="filters">
        <div className="filter">
          <label>Decision</label>
          <select className="select" value={decision} onChange={(e) => setDecision(e.target.value)}>
            <option value="">All</option><option>ALLOW</option><option>ASK</option><option>DENY</option>
          </select>
        </div>
        <div className="filter">
          <label>Min risk</label>
          <select className="select" value={risk} onChange={(e) => setRisk(e.target.value)}>
            <option value="">All</option>
            <option value="medium">Medium+ (40)</option>
            <option value="high">High+ (60)</option>
            <option value="critical">Critical (85)</option>
          </select>
        </div>
        <div className="filter">
          <label>Goal drift</label>
          <select className="select" value={drift} onChange={(e) => setDrift(e.target.value)}>
            <option value="">All</option><option value="drift">Drift only</option><option value="nodrift">No drift</option>
          </select>
        </div>
        <div style={{ flex: 1 }} />
        <span className="faint" style={{ fontSize: 12 }}>{data.total} events</span>
      </div>

      <div className="panel">
        <div className="panel-body">
          {data.items.length === 0 ? (
            <Empty message="No audit events match these filters." />
          ) : (
            <>
              <div className="row head" style={{ gridTemplateColumns: "84px 1fr 90px 84px 120px" }}>
                <div>Time</div><div>Action / Resource</div><div>Decision</div><div className="right">Risk</div><div className="right">Status</div>
              </div>
              {data.items.map((e) => (
                <div className="row" key={e.event_id} style={{ gridTemplateColumns: "84px 1fr 90px 84px 120px" }}
                  onClick={() => setSelected(e)}>
                  <div className="cell-time">{formatTime(e.created_at)}</div>
                  <div className="cell-res">
                    <div className="res-main">{e.operation} {e.resource}</div>
                    <div className="res-sub">{e.goal_drift ? "⚠ goal drift · " : ""}{e.execution_status}</div>
                  </div>
                  <div><DecisionBadge decision={e.decision} /></div>
                  <div className="right"><RiskTag score={e.risk_score} /></div>
                  <div className="right"><span className="faint" style={{ fontSize: 12 }}>{e.approval_status ?? "—"}</span></div>
                </div>
              ))}
            </>
          )}
        </div>
      </div>

      <div style={{ display: "flex", gap: 10, alignItems: "center", justifyContent: "flex-end", marginTop: 14 }}>
        <button className="btn sm ghost" disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - PAGE))}>Prev</button>
        <span className="faint" style={{ fontSize: 12 }}>Page {page} / {pages}</span>
        <button className="btn sm ghost" disabled={page >= pages} onClick={() => setOffset(offset + PAGE)}>Next</button>
      </div>

      {selected && <ActionDetail event={selected} onClose={() => setSelected(null)} />}
    </>
  );
}
