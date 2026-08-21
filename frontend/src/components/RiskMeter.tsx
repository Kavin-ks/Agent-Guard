import type { Signal } from "../types";
import { riskBand, riskClass } from "../lib/format";

// Risk visualization driven entirely by backend values: the numeric score, its
// band, and the top contributing signals (deterministic first).
export function RiskMeter({ score, signals }: { score: number; signals: Signal[] }) {
  const top = [...signals]
    .sort((a, b) => Number(a.advisory) - Number(b.advisory) || b.risk_points - a.risk_points)
    .slice(0, 4);
  return (
    <div>
      <div style={{ display: "flex", alignItems: "baseline", gap: 10, marginBottom: 8 }}>
        <span className={`risk-tag ${riskClass(score)}`} style={{ fontSize: 26 }}>{score}</span>
        <span className={`risk-tag ${riskClass(score)}`}>{riskBand(score).toUpperCase()}</span>
      </div>
      <div className="meter" aria-label={`risk ${score} of 100`}>
        <span className={`meter-fill ${riskClass(score)}`} style={{ width: `${Math.min(100, score)}%` }} />
      </div>
      {top.length > 0 && (
        <div style={{ marginTop: 12 }}>
          <div className="section-label" style={{ margin: "0 0 6px" }}>Contributing signals</div>
          {top.map((s, i) => (
            <div key={i} style={{ display: "flex", justifyContent: "space-between", padding: "3px 0", fontSize: 12.5 }}>
              <span className="mono">{s.gate}{s.advisory ? " (advisory)" : ""}</span>
              <span className="faint">+{s.risk_points}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
