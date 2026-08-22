"""
API request/response schemas.

These are the wire contract, kept separate from the engine's internal models.
All request models forbid unexpected fields (``extra="forbid"``) so malformed or
injected payloads are rejected with 422 before reaching the engine.
"""

from __future__ import annotations

from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from agentguard.audit import ApprovalRequest, AuditEvent
from agentguard.models import Operation, ResourceKind

# Explicit trust-boundary note included on every evaluate response.
EXECUTION_NOTE = (
    "Agent Guard evaluates and records decisions only; it never executes the "
    "action. Honoring this decision is the calling agent's responsibility."
)


class PolicyOverride(BaseModel):
    """Optional explicit policy fields. Any provided field overrides the
    goal-derived default. Note: ``protected_resources`` can only ADD protections;
    the engine always unions built-ins and never removes them."""

    model_config = ConfigDict(extra="forbid")

    allowed_scopes: list[str] | None = None
    restricted_scopes: list[str] | None = None
    protected_resources: list[str] | None = None
    external_communication: Literal["deny", "ask", "allow"] | None = None
    network_allowlist: list[str] | None = None
    destructive_requires_approval: bool | None = None


class EvaluateRequest(BaseModel):
    """A proposed agent action submitted for evaluation BEFORE execution."""

    model_config = ConfigDict(extra="forbid")

    goal: str = Field(..., min_length=1, max_length=4000)
    action: Operation = Field(..., description="Normalized operation, e.g. 'read','write','transmit'")
    resource: str = Field(..., min_length=1, max_length=8192)
    resource_kind: ResourceKind | None = Field(
        default=None, description="Optional; inferred from operation/resource if omitted"
    )
    tool: str = Field(default="generic", max_length=128)
    payload: str | None = Field(default=None, max_length=1_000_000)
    destination: str | None = Field(default=None, max_length=8192)
    context: dict = Field(default_factory=dict)
    session_id: str = Field(default="default", min_length=1, max_length=256)
    agent_id: str = Field(default="unknown-agent", max_length=256)
    # Origin: "agent" (real MCP/SDK agent), "demo" (Live Demo page), "sdk", "system".
    source: str = Field(default="sdk", max_length=32)
    # The user prompt/instruction (redacted server-side before it is stored).
    prompt: str | None = Field(default=None, max_length=4000)
    policy: PolicyOverride | None = None


class SignalOut(BaseModel):
    gate: str
    severity: str
    risk_points: int
    reason: str
    rule_id: str | None = None
    advisory: bool = False


class SecretOut(BaseModel):
    """Redacted secret finding. Never contains the raw value."""

    type: str
    fingerprint: str
    entropy: float


class SensitiveOut(BaseModel):
    """Redacted sensitive-data finding. Never contains the raw value."""

    category: str
    subtype: str
    severity: str
    confidence: float
    fingerprint: str
    location: str


class AppliedPolicy(BaseModel):
    """Summary of the policy actually enforced, echoed back for transparency."""

    session_id: str
    allowed_scopes: list[str]
    restricted_scopes: list[str]
    external_communication: str
    builtin_protections_enforced: bool = True


class EvaluateResponse(BaseModel):
    decision: Literal["ALLOW", "ASK", "DENY"]        # the FINAL decision
    risk_score: int
    reason: str
    matched_rule: str | None = None
    sensitive_data_detected: bool = False
    secrets: list[SecretOut] = Field(default_factory=list)
    sensitive: list[SensitiveOut] = Field(default_factory=list)
    sensitive_categories: list[str] = Field(default_factory=list)
    signals: list[SignalOut] = Field(default_factory=list)

    # --- deterministic vs. advisory transparency (Phase 3) ---
    deterministic_decision: str | None = None
    goal_relevance: str | None = None            # HIGH | MEDIUM | LOW
    goal_relevance_confidence: float | None = None
    goal_drift: bool = False
    advisory_recommendation: str | None = None   # advisory only
    advisory_available: bool = False
    advisory_source: str | None = None
    advisory_reason: str | None = None

    # --- workflow (Phase 5) ---
    event_id: str
    action_fingerprint: str
    approval_required: bool = False        # True only when decision == ASK
    approval_id: str | None = None
    execution_status: str
    source: str = "sdk"
    prompt: str = ""                       # redacted
    execution_note: str = EXECUTION_NOTE

    policy: AppliedPolicy
    action_id: UUID
    latency_ms: float


class ResolveRequest(BaseModel):
    """Body for approve/reject. The approver is recorded in the audit trail."""

    model_config = ConfigDict(extra="forbid")
    approver: str = Field(default="human", min_length=1, max_length=256)


class ConsumeResponse(BaseModel):
    """Result of the fingerprint-verified pre-execution gate."""

    authorized: bool
    reason: str
    decision: str
    approval_status: str


class ExecutionReportRequest(BaseModel):
    """Agent-reported execution outcome (Agent Guard does not execute)."""

    model_config = ConfigDict(extra="forbid")
    status: Literal["REPORTED_EXECUTED", "REPORTED_FAILED", "REPORTED_SKIPPED"]


class AuditListResponse(BaseModel):
    items: list[AuditEvent]
    total: int
    limit: int
    offset: int


class ApprovalListResponse(BaseModel):
    items: list[ApprovalRequest]
    total: int
    limit: int
    offset: int


class RegisterAgentRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    session_id: str = Field(..., min_length=1, max_length=256)
    agent_name: str = Field(default="agent", max_length=128)
    source: str = Field(default="agent", max_length=32)


class AgentOut(BaseModel):
    session_id: str
    agent_name: str
    source: str
    status: str            # connected | disconnected
    connected_at: str
    last_seen: str
    calls: int
    allowed: int
    asked: int
    denied: int
    last_decision: str | None = None


class HealthResponse(BaseModel):
    status: Literal["ok"]
    service: str
    version: str
    engine: Literal["ready"]
    gates: list[str]
