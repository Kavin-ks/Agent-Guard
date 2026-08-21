"""
Pydantic v2 data models for Agent Guard.

These types form the contract between an AI agent, the Agent Guard engine, and
the audit trail. They are pure data — no evaluation logic lives here.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field

from .constants import (
    DEFAULT_ASK_THRESHOLD,
    DEFAULT_DENY_THRESHOLD,
)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Operation(str, Enum):
    """Normalized operation categories. Every concrete tool maps to one of these."""

    READ = "read"
    WRITE = "write"
    DELETE = "delete"
    EXECUTE = "execute"
    NETWORK = "network"
    TRANSMIT = "transmit"


class ResourceKind(str, Enum):
    FILE = "file"
    URL = "url"
    DB = "db"
    PROCESS = "process"
    OTHER = "other"


class Decision(str, Enum):
    ALLOW = "ALLOW"
    ASK = "ASK"
    DENY = "DENY"


class Severity(str, Enum):
    """Signal severity, ordered least -> most restrictive."""

    INFO = "info"
    ELEVATE = "elevate"  # raise suspicion / risk, but not a verdict on its own
    ASK = "ask"
    DENY = "deny"


# Ordering used to compute "max severity wins".
_SEVERITY_ORDER = {
    Severity.INFO: 0,
    Severity.ELEVATE: 1,
    Severity.ASK: 2,
    Severity.DENY: 3,
}


def severity_rank(sev: Severity) -> int:
    return _SEVERITY_ORDER[sev]


class Resource(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: ResourceKind = ResourceKind.OTHER
    value: str = Field(..., min_length=1, max_length=8192)


class Action(BaseModel):
    """A single proposed agent action to be evaluated BEFORE execution."""

    model_config = ConfigDict(extra="forbid")

    action_id: UUID = Field(default_factory=uuid4)
    session_id: str = Field(..., min_length=1, max_length=256)
    agent_id: str = Field(default="unknown-agent", max_length=256)

    tool: str = Field(..., min_length=1, max_length=128)
    operation: Operation
    resource: Resource

    # Content being written or transmitted. Scanned for secrets, never persisted raw.
    payload: str | None = Field(default=None, max_length=1_000_000)
    # For network/transmit: the external endpoint (URL or host).
    destination: str | None = Field(default=None, max_length=8192)

    context: dict = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=_utcnow)


class Signal(BaseModel):
    """An explainable finding emitted by a gate. Decisions are built from signals."""

    model_config = ConfigDict(extra="forbid")

    gate: str
    severity: Severity
    risk_points: int = 0
    reason: str
    rule_id: str | None = None
    advisory: bool = False  # True => came from the LLM; can never force a hard DENY


class SecretMatch(BaseModel):
    """Redacted secret finding surfaced on a decision. Never holds the raw value."""

    model_config = ConfigDict(extra="forbid")

    type: str
    fingerprint: str
    entropy: float


class Policy(BaseModel):
    """Machine-readable runtime policy compiled from a user goal."""

    model_config = ConfigDict(extra="forbid")

    session_id: str
    goal_text: str = ""
    allowed_scopes: list[str] = Field(default_factory=list)
    restricted_scopes: list[str] = Field(default_factory=list)
    # User additions ONLY; the engine always unions this with the built-in
    # protected globs and never lets the policy remove a built-in protection.
    protected_resources: list[str] = Field(default_factory=list)
    allowed_operations: list[Operation] = Field(
        default_factory=lambda: list(Operation)
    )
    external_communication: str = "ask"  # "deny" | "ask" | "allow"
    network_allowlist: list[str] = Field(default_factory=list)
    destructive_requires_approval: bool = True
    ask_threshold: int = DEFAULT_ASK_THRESHOLD
    deny_threshold: int = DEFAULT_DENY_THRESHOLD


class DecisionResult(BaseModel):
    """The verdict returned to the agent. Fully explainable via ``signals``."""

    model_config = ConfigDict(extra="forbid")

    action_id: UUID
    session_id: str
    decision: Decision                    # the FINAL decision
    risk_score: int = Field(ge=0, le=100)
    reason: str
    matched_rule: str | None = None
    sensitive_data_detected: bool = False
    secrets: list[SecretMatch] = Field(default_factory=list)
    signals: list[Signal] = Field(default_factory=list)

    # --- deterministic vs. advisory transparency (Phase 3) ---
    # The decision the deterministic gates alone would reach. The final decision
    # is never LESS restrictive than this — the advisory layer can only escalate.
    deterministic_decision: Decision | None = None
    deterministic_risk_score: int | None = None
    goal_relevance: str | None = None            # HIGH | MEDIUM | LOW
    goal_relevance_confidence: float | None = None
    goal_drift: bool = False
    advisory_recommendation: str | None = None   # ALLOW | ASK | DENY (advisory only)
    advisory_available: bool = False
    advisory_source: str | None = None
    advisory_reason: str | None = None

    latency_ms: float = 0.0
    evaluated_at: datetime = Field(default_factory=_utcnow)
