import type { AuditEvent } from "../types";
import { DecisionBadge, RiskTag } from "./common";
import { formatTime } from "../lib/format";

export function ActivityHeader() {
  return (
    <div className="row head">
      <div>Time</div>
      <div>Resource / Agent</div>
      <div>Decision</div>
      <div className="col-risk right">Risk</div>
      <div className="col-rel right">Relevance / Status</div>
    </div>
  );
}

export function ActivityRow({ e, onClick }: { e: AuditEvent; onClick: () => void }) {
  const status =
    e.approval_status === "PENDING" ? "Awaiting approval" :
    e.approval_status ? e.approval_status :
    e.execution_status === "BLOCKED" ? "Blocked" :
    e.execution_status.startsWith("REPORTED") ? e.execution_status.replace("REPORTED_", "") :
    "—";
  return (
    <div className="row" onClick={onClick} role="button" aria-label={`${e.operation} ${e.resource} ${e.decision}`}>
      <div className="cell-time">{formatTime(e.created_at)}</div>
      <div className="cell-res">
        <div className="res-main">{e.operation} {e.resource}</div>
        <div className="res-sub">{e.agent_id} · {e.tool}</div>
      </div>
      <div><DecisionBadge decision={e.decision} /></div>
      <div className="col-risk right"><RiskTag score={e.risk_score} /></div>
      <div className="col-rel right">
        <div style={{ fontSize: 12 }}>{e.goal_relevance ?? "—"}{e.goal_drift ? " · drift" : ""}</div>
        <div className="res-sub">{status}</div>
      </div>
    </div>
  );
}
