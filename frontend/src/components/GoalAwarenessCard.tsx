import type { AuditEvent } from "../types";
import { DecisionBadge } from "./common";

// Highlights the differentiating feature: the decision is made relative to the
// user's goal. Renders the most recent goal-relevant event.
export function GoalAwarenessCard({ event }: { event: AuditEvent | null }) {
  return (
    <div className="panel">
      <div className="panel-head"><span className="panel-title">Goal awareness</span></div>
      <div style={{ padding: 16 }}>
        <div className="section-label" style={{ marginTop: 0 }}>User goal</div>
        <div className="muted" style={{ fontSize: 13 }}>
          {event?.goal_text || "Run an action to see goal-relative evaluation."}
        </div>

        {event && (
          <>
            <div className="section-label">Current action</div>
            <div className="mono" style={{ fontSize: 13 }}>{event.operation} {event.resource}</div>

            <div className="goalcard" style={{ marginTop: 16 }}>
              <div>
                <div className="section-label" style={{ marginTop: 0 }}>Goal relevance</div>
                <div style={{ fontSize: 18, fontWeight: 700 }}>{event.goal_relevance ?? "—"}</div>
              </div>
              <div>
                <div className="section-label" style={{ marginTop: 0 }}>Goal drift</div>
                <div style={{ fontSize: 18, fontWeight: 700, color: event.goal_drift ? "var(--deny)" : "var(--text-dim)" }}>
                  {event.goal_drift ? "DETECTED" : "None"}
                </div>
              </div>
            </div>

            <div className="section-label">Security decision</div>
            <DecisionBadge decision={event.decision} />
          </>
        )}
      </div>
    </div>
  );
}
