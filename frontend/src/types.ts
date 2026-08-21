// Types mirroring the Agent Guard backend contract. The frontend never invents
// security fields — every value here is produced by the backend.

export type Decision = "ALLOW" | "ASK" | "DENY";
export type ApprovalStatus = "PENDING" | "APPROVED" | "REJECTED" | "EXPIRED";

export interface Signal {
  gate: string;
  severity: string;
  risk_points: number;
  reason: string;
  rule_id: string | null;
  advisory: boolean;
}

export interface SecretMatch {
  type: string;
  fingerprint: string; // redacted, e.g. "sk-…HHHH" — never a raw secret
  entropy: number;
}

export interface EvaluateResponse {
  decision: Decision;
  risk_score: number;
  reason: string;
  matched_rule: string | null;
  sensitive_data_detected: boolean;
  secrets: SecretMatch[];
  signals: Signal[];
  deterministic_decision: Decision | null;
  goal_relevance: string | null;
  goal_relevance_confidence: number | null;
  goal_drift: boolean;
  advisory_recommendation: string | null;
  advisory_available: boolean;
  advisory_source: string | null;
  advisory_reason: string | null;
  event_id: string;
  action_fingerprint: string;
  approval_required: boolean;
  approval_id: string | null;
  execution_status: string;
  execution_note: string;
  action_id: string;
  latency_ms: number;
}

export interface AuditEvent {
  event_id: string;
  created_at: string;
  action_id: string;
  session_id: string;
  agent_id: string;
  operation: string;
  resource: string;
  resource_kind: string;
  tool: string;
  destination: string | null;
  goal_text: string;
  context_keys: string[];
  decision: Decision;
  deterministic_decision: Decision | null;
  risk_score: number;
  reason: string;
  matched_rule: string | null;
  goal_relevance: string | null;
  goal_drift: boolean;
  advisory_available: boolean;
  sensitive_data_detected: boolean;
  payload_present: boolean;
  payload_contains_secret: boolean;
  secrets: SecretMatch[];
  signals: Signal[];
  action_fingerprint: string;
  approval_status: ApprovalStatus | null;
  approval_id: string | null;
  execution_status: string;
}

export interface ApprovalRequest {
  approval_id: string;
  event_id: string;
  action_id: string;
  session_id: string;
  created_at: string;
  expires_at: string | null;
  resolved_at: string | null;
  operation: string;
  resource: string;
  tool: string;
  destination: string | null;
  goal_text: string;
  reason: string;
  risk_score: number;
  goal_relevance: string | null;
  goal_drift: boolean;
  signals: Signal[];
  action_fingerprint: string;
  status: ApprovalStatus;
  approver: string | null;
  consumed: boolean;
  consumed_at: string | null;
}

export interface ConsumeResponse {
  authorized: boolean;
  reason: string;
  decision: string;
  approval_status: string;
}

export interface Paginated<T> {
  items: T[];
  total: number;
  limit: number;
  offset: number;
}

export interface EvaluateRequest {
  goal: string;
  action: string;
  resource: string;
  resource_kind?: string;
  tool?: string;
  payload?: string;
  destination?: string;
  session_id?: string;
  agent_id?: string;
  context?: Record<string, unknown>;
}
