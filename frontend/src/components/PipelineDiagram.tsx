import type { Decision } from "../types";
import { decisionClass } from "../lib/format";

// The architecture-at-a-glance diagram. `activeStage` highlights how far a given
// action progressed; `decision` colors the final node.
export type Stage = "agent" | "action" | "guard" | "decision" | "execution";

const GATES = ["secret_exfil", "protected_resource", "policy_scope", "destructive", "external_comm"];

export function PipelineDiagram({
  decision,
  activeStage,
}: {
  decision?: Decision | null;
  activeStage?: Stage;
}) {
  const on = (s: Stage) => (activeStage === s ? " active" : "");
  const dcls = decision ? decisionClass(decision) : "";
  return (
    <div className="pipeline">
      <div className={`pipe-node${on("agent")}`}>
        <div className="pipe-title">AI Agent</div>
        <div className="pipe-sub">Autonomous coding / tool-using agent</div>
      </div>
      <div className="pipe-arrow">↓</div>
      <div className={`pipe-node${on("action")}`}>
        <div className="pipe-title">Proposed Action</div>
        <div className="pipe-sub">operation · resource · payload · goal</div>
      </div>
      <div className="pipe-arrow">↓</div>
      <div className={`pipe-node${on("guard")}`}>
        <div className="pipe-title">Agent Guard</div>
        <div className="pipe-sub">Goal analysis · policy · secret detection · risk</div>
        <div className="gates-inline">
          {GATES.map((g) => <span className="chip" key={g}>{g}</span>)}
        </div>
      </div>
      <div className="pipe-arrow">↓</div>
      <div className={`pipe-node ${dcls}${on("decision")}`}>
        <div className="pipe-title">
          Decision {decision ? `— ${decision}` : ""}
        </div>
        <div className="pipe-sub">ALLOW · ASK (human approval) · DENY</div>
      </div>
      <div className="pipe-arrow">↓</div>
      <div className={`pipe-node${on("execution")}`}>
        <div className="pipe-title">Tool Execution</div>
        <div className="pipe-sub">Runs only if authorized · every step audited</div>
      </div>
    </div>
  );
}
