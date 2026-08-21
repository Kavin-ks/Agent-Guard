import { useCallback, useEffect, useState } from "react";
import { api, ApiError } from "../api/client";
import type { ApprovalRequest } from "../types";
import { Loading, ErrorState, Empty, RiskTag } from "../components/common";
import { formatTime } from "../lib/format";

export function ApprovalsPage() {
  const [items, setItems] = useState<ApprovalRequest[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const res = await api.listApprovals();
      setItems(res.items);
      setError(null);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Failed to load approvals");
    }
  }, []);

  useEffect(() => {
    load();
    const id = setInterval(load, 4000);
    return () => clearInterval(id);
  }, [load]);

  async function resolve(id: string, action: "approve" | "reject") {
    setBusy(id);
    try {
      // Calls the REAL backend — the decision is never simulated in React.
      if (action === "approve") await api.approve(id);
      else await api.reject(id);
      await load();
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Action failed");
    } finally {
      setBusy(null);
    }
  }

  if (error && !items) return <ErrorState message={error} />;
  if (!items) return <Loading label="Loading approval queue…" />;

  const pending = items.filter((a) => a.status === "PENDING");
  const recent = items.filter((a) => a.status !== "PENDING").slice(0, 8);

  return (
    <>
      <p className="pageintro">
        ASK decisions require explicit human approval before the agent may proceed. Approving here
        calls the backend; the action is then re-verified by fingerprint at execution time.
      </p>

      {pending.length === 0 ? (
        <Empty message="No pending approvals. Trigger a destructive action in Live Demo to populate this queue." />
      ) : (
        <div className="approval-grid">
          {pending.map((a) => (
            <div className="approval-card" key={a.approval_id}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                <span className="badge ask"><span className="dot ask" />ASK</span>
                <RiskTag score={a.risk_score} />
              </div>
              <div className="mono" style={{ fontSize: 14, marginTop: 12 }}>{a.operation} {a.resource}</div>
              <div className="goal">Goal: {a.goal_text || "—"}</div>
              <div style={{ fontSize: 12.5 }} className="muted">{a.reason}</div>
              <div style={{ display: "flex", justifyContent: "space-between", marginTop: 10, fontSize: 12 }} className="faint">
                <span>Relevance: {a.goal_relevance ?? "—"}{a.goal_drift ? " · drift" : ""}</span>
                <span>{formatTime(a.created_at)}</span>
              </div>
              <div className="approval-actions">
                <button className="btn approve" disabled={busy === a.approval_id}
                  onClick={() => resolve(a.approval_id, "approve")}>Approve</button>
                <button className="btn reject" disabled={busy === a.approval_id}
                  onClick={() => resolve(a.approval_id, "reject")}>Reject</button>
              </div>
            </div>
          ))}
        </div>
      )}

      {recent.length > 0 && (
        <div className="panel" style={{ marginTop: 24 }}>
          <div className="panel-head"><span className="panel-title">Recently resolved</span></div>
          <div className="panel-body">
            {recent.map((a) => (
              <div className="row" key={a.approval_id} style={{ cursor: "default", gridTemplateColumns: "88px 1fr 120px" }}>
                <div className="cell-time">{formatTime(a.resolved_at ?? a.created_at)}</div>
                <div className="res-main">{a.operation} {a.resource}</div>
                <div className="right">
                  <span className={`badge ${a.status === "APPROVED" ? "allow" : "deny"}`}>{a.status}</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </>
  );
}
