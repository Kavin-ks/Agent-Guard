// Centralized API client — the ONLY place the dashboard talks to the backend.
// No component calls fetch() directly. The base URL defaults to same-origin
// "/api" (the dev proxy / prod reverse-proxy injects the X-API-Key header so the
// browser never holds the key).

import type {
  AgentOut,
  ApprovalRequest,
  AuditEvent,
  ConsumeResponse,
  EvaluateRequest,
  EvaluateResponse,
  Paginated,
} from "../types";

const BASE = (import.meta.env.VITE_API_BASE_URL as string | undefined) ?? "/api";

export class ApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
    readonly kind: "unauthorized" | "network" | "server" | "notfound",
  ) {
    super(message);
  }
}

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  let resp: Response;
  try {
    resp = await fetch(`${BASE}${path}`, {
      method,
      headers: body ? { "Content-Type": "application/json" } : {},
      body: body ? JSON.stringify(body) : undefined,
    });
  } catch {
    throw new ApiError("Cannot reach Agent Guard backend", 0, "network");
  }

  if (resp.status === 401 || resp.status === 403) {
    throw new ApiError("Unauthorized — backend rejected the API key", resp.status, "unauthorized");
  }
  if (resp.status === 404) {
    throw new ApiError("Not found", 404, "notfound");
  }
  if (!resp.ok) {
    throw new ApiError(`Backend error (${resp.status})`, resp.status, "server");
  }
  return (await resp.json()) as T;
}

export interface AuditFilters {
  decision?: string;
  goal_drift?: boolean;
  min_risk?: number;
  approval_status?: string;
  source?: string;
  exclude_source?: string;
  limit?: number;
  offset?: number;
}

function query(params: Record<string, unknown>): string {
  const q = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== null && v !== "") q.set(k, String(v));
  }
  const s = q.toString();
  return s ? `?${s}` : "";
}

export const api = {
  health: () => request<{ status: string; service: string; version: string; gates: string[] }>("GET", "/health"),

  evaluate: (req: EvaluateRequest) => request<EvaluateResponse>("POST", "/guard/evaluate", req),

  listAudit: (f: AuditFilters = {}) =>
    request<Paginated<AuditEvent>>("GET", `/audit${query({ ...f })}`),

  getAudit: (id: string) => request<AuditEvent>("GET", `/audit/${id}`),

  listApprovals: (status?: string, limit = 50, offset = 0) =>
    request<Paginated<ApprovalRequest>>("GET", `/approvals${query({ status, limit, offset })}`),

  approve: (id: string, approver = "reviewer") =>
    request<ApprovalRequest>("POST", `/approvals/${id}/approve`, { approver }),

  reject: (id: string, approver = "reviewer") =>
    request<ApprovalRequest>("POST", `/approvals/${id}/reject`, { approver }),

  consume: (id: string, req: EvaluateRequest) =>
    request<ConsumeResponse>("POST", `/approvals/${id}/consume`, req),

  reportExecution: (eventId: string, status: string) =>
    request<AuditEvent>("POST", `/audit/${eventId}/execution`, { status }),

  listAgents: () => request<AgentOut[]>("GET", "/agents"),
};
