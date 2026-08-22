"""
Audit & approval domain models.

These are the persisted, ALWAYS-REDACTED records of the runtime security
workflow. They never contain raw secrets, payloads, tokens, or credentials —
only decisions, metadata, and redacted secret fingerprints.

Three distinct concepts are kept explicit (see README "trust boundary"):
  * decision   — what Agent Guard decided (ALLOW/ASK/DENY)
  * approval   — whether a human approved an ASK
  * execution  — whether the external agent actually executed (agent-reported;
                 Agent Guard never executes anything itself)
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field

from .models import SecretMatch, SensitiveMatch, Signal


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class ApprovalStatus(str, Enum):
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXPIRED = "EXPIRED"


class ExecutionStatus(str, Enum):
    NOT_EXECUTED = "NOT_EXECUTED"      # default — nothing has run
    BLOCKED = "BLOCKED"               # decision was DENY; agent must not execute
    AUTHORIZED = "AUTHORIZED"         # approval consumed; agent may proceed
    REPORTED_EXECUTED = "REPORTED_EXECUTED"   # agent reported it executed
    REPORTED_FAILED = "REPORTED_FAILED"       # agent reported execution failed
    REPORTED_SKIPPED = "REPORTED_SKIPPED"     # agent reported it skipped


class AuditEvent(BaseModel):
    """A redacted, persisted record of one evaluated action."""

    model_config = ConfigDict(extra="forbid")

    event_id: str = Field(default_factory=lambda: "ev_" + uuid4().hex)
    created_at: datetime = Field(default_factory=_utcnow)

    action_id: str
    session_id: str
    agent_id: str = "unknown-agent"
    # Origin of the action: "agent" (real MCP/SDK agent), "demo" (Live Demo page),
    # "sdk", or "system". The dashboard separates live agent activity from demo.
    source: str = "sdk"
    # The user prompt / instruction that led to this action, REDACTED. Never raw.
    prompt: str = ""

    # Action metadata (safe)
    operation: str
    resource: str
    resource_kind: str
    tool: str
    destination: str | None = None
    goal_text: str = ""
    context_keys: list[str] = Field(default_factory=list)

    # Decision (from the engine)
    decision: str
    deterministic_decision: str | None = None
    risk_score: int = 0
    reason: str = ""
    matched_rule: str | None = None
    goal_relevance: str | None = None
    goal_drift: bool = False
    advisory_available: bool = False

    # Sensitive-data indicators (redacted only)
    sensitive_data_detected: bool = False
    payload_present: bool = False
    payload_contains_secret: bool = False
    secrets: list[SecretMatch] = Field(default_factory=list)  # redacted fingerprints only
    # Phase 4: broader sensitive-data metadata (redacted; never raw values).
    sensitive_categories: list[str] = Field(default_factory=list)
    sensitive: list[SensitiveMatch] = Field(default_factory=list)
    signals: list[Signal] = Field(default_factory=list)

    # Integrity + workflow
    action_fingerprint: str
    approval_status: str | None = None          # None if not an ASK
    approval_id: str | None = None
    execution_status: str = ExecutionStatus.NOT_EXECUTED.value


class AgentSession(BaseModel):
    """A connected agent session (e.g. Antigravity over MCP). Real, not demo."""

    model_config = ConfigDict(extra="forbid")

    session_id: str
    agent_name: str = "agent"
    source: str = "agent"                 # agent | sdk | mcp
    connected_at: datetime = Field(default_factory=_utcnow)
    last_seen: datetime = Field(default_factory=_utcnow)
    calls: int = 0
    allowed: int = 0
    asked: int = 0
    denied: int = 0
    last_decision: str | None = None

    def status(self, now: datetime | None = None, idle_seconds: int = 120) -> str:
        now = now or _utcnow()
        return "connected" if (now - self.last_seen).total_seconds() <= idle_seconds else "disconnected"


class ApprovalRequest(BaseModel):
    """A human-in-the-loop approval request created for an ASK decision."""

    model_config = ConfigDict(extra="forbid")

    approval_id: str = Field(default_factory=lambda: "ap_" + uuid4().hex)
    event_id: str
    action_id: str
    session_id: str
    created_at: datetime = Field(default_factory=_utcnow)
    expires_at: datetime | None = None
    resolved_at: datetime | None = None

    # Context for the human reviewer (safe)
    operation: str
    resource: str
    tool: str
    destination: str | None = None
    goal_text: str = ""
    reason: str = ""
    risk_score: int = 0
    goal_relevance: str | None = None
    goal_drift: bool = False
    signals: list[Signal] = Field(default_factory=list)

    # Integrity binding
    action_fingerprint: str

    status: str = ApprovalStatus.PENDING.value
    approver: str | None = None
    consumed: bool = False
    consumed_at: datetime | None = None

    def is_expired(self, now: datetime | None = None) -> bool:
        if self.expires_at is None:
            return False
        return (now or _utcnow()) >= self.expires_at
