import type { Decision } from "../types";
import { decisionClass, riskBand, riskClass } from "../lib/format";

export function DecisionBadge({ decision }: { decision: Decision | string }) {
  const c = decisionClass(decision);
  return (
    <span className={`badge ${c}`}>
      <span className={`dot ${c}`} />
      {decision}
    </span>
  );
}

export function RiskTag({ score }: { score: number }) {
  return (
    <span className={`risk-tag ${riskClass(score)}`}>
      {score} · {riskBand(score)}
    </span>
  );
}

export function StatCard({ label, value, tone }: { label: string; value: number | string; tone?: string }) {
  return (
    <div className="stat">
      <div className="stat-label">{label}</div>
      <div className={`stat-value ${tone ?? ""}`}>{value}</div>
    </div>
  );
}

export function Loading({ label = "Loading…" }: { label?: string }) {
  return (
    <div className="state" role="status">
      <div className="spinner" />
      {label}
    </div>
  );
}

export function ErrorState({ message }: { message: string }) {
  return (
    <div className="state err" role="alert">
      ⚠ {message}
    </div>
  );
}

export function Empty({ message }: { message: string }) {
  return <div className="state">{message}</div>;
}
