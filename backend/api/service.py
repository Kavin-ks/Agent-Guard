"""
Application/service layer — the human-in-the-loop security workflow.

Orchestrates: engine evaluation -> audit record -> (for ASK) approval request ->
human approve/reject -> fingerprint-verified consume before execution. Depends
only on the engine and the store *interfaces*; contains no DB code and no gate
logic. The deterministic engine remains the sole security authority — this layer
can never turn a DENY into anything else.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta

from agentguard import Engine
from agentguard.audit import (
    AgentSession,
    ApprovalRequest,
    ApprovalStatus,
    AuditEvent,
    ExecutionStatus,
    _utcnow,
)
from agentguard.fingerprint import action_fingerprint
from agentguard.models import Decision
from agentguard.redaction import redact_text

from .bridge import build_action, build_policy
from .schemas import EvaluateRequest
from .store.base import ApprovalStore, AuditStore, SessionStore

# Sources that represent a real connected agent (recorded in the session registry).
_AGENT_SOURCES = {"agent", "mcp", "sdk"}


class ServiceError(Exception):
    """Base for service errors mapped to HTTP codes in the routes."""

    http_status = 400


class NotFoundError(ServiceError):
    http_status = 404


class ConflictError(ServiceError):
    http_status = 409


@dataclass
class EvaluationOutcome:
    result: object          # DecisionResult
    event: AuditEvent
    approval: ApprovalRequest | None


@dataclass
class ConsumeResult:
    authorized: bool
    reason: str
    decision: str
    approval_status: str


class GuardService:
    def __init__(
        self,
        engine: Engine,
        audit_store: AuditStore,
        approval_store: ApprovalStore,
        approval_ttl_seconds: int = 3600,
        session_store: SessionStore | None = None,
    ) -> None:
        self._engine = engine
        self._audit = audit_store
        self._approvals = approval_store
        self._ttl = approval_ttl_seconds
        self._sessions = session_store

    # -- evaluate ----------------------------------------------------------
    def evaluate(self, req: EvaluateRequest) -> EvaluationOutcome:
        policy = build_policy(req)
        action = build_action(req)
        fingerprint = action_fingerprint(action, policy)

        result = self._engine.evaluate(action, policy)
        decision = result.decision

        exec_status = (
            ExecutionStatus.BLOCKED.value if decision is Decision.DENY
            else ExecutionStatus.NOT_EXECUTED.value
        )

        event = AuditEvent(
            action_id=str(result.action_id),
            session_id=req.session_id,
            agent_id=req.agent_id,
            source=req.source,
            prompt=redact_text(req.prompt),   # user prompt, secrets scrubbed
            operation=action.operation.value,
            resource=action.resource.value,
            resource_kind=action.resource.kind.value,
            tool=action.tool,
            destination=action.destination,
            goal_text=policy.goal_text,
            context_keys=sorted(action.context.keys()) if action.context else [],
            decision=decision.value,
            deterministic_decision=(
                result.deterministic_decision.value if result.deterministic_decision else None
            ),
            risk_score=result.risk_score,
            reason=result.reason,
            matched_rule=result.matched_rule,
            goal_relevance=result.goal_relevance,
            goal_drift=result.goal_drift,
            advisory_available=result.advisory_available,
            sensitive_data_detected=result.sensitive_data_detected,
            payload_present=action.payload is not None,
            payload_contains_secret=bool(result.secrets),
            secrets=result.secrets,          # redacted fingerprints only
            sensitive_categories=result.sensitive_categories,
            sensitive=result.sensitive,      # redacted; never raw values
            signals=result.signals,
            action_fingerprint=fingerprint,
            execution_status=exec_status,
        )

        approval: ApprovalRequest | None = None
        if decision is Decision.ASK:
            approval = ApprovalRequest(
                event_id=event.event_id,
                action_id=event.action_id,
                session_id=req.session_id,
                expires_at=_utcnow() + timedelta(seconds=self._ttl),
                operation=action.operation.value,
                resource=action.resource.value,
                tool=action.tool,
                destination=action.destination,
                goal_text=policy.goal_text,
                reason=result.reason,
                risk_score=result.risk_score,
                goal_relevance=result.goal_relevance,
                goal_drift=result.goal_drift,
                signals=result.signals,
                action_fingerprint=fingerprint,
                status=ApprovalStatus.PENDING.value,
            )
            event.approval_status = ApprovalStatus.PENDING.value
            event.approval_id = approval.approval_id

        self._audit.add(event)
        if approval is not None:
            self._approvals.add(approval)

        # Record the connected-agent session (real agents only; never demo).
        if self._sessions is not None and req.source in _AGENT_SOURCES:
            self._sessions.record_call(req.session_id, req.agent_id, req.source, decision.value)

        return EvaluationOutcome(result=result, event=event, approval=approval)

    # -- agent sessions ----------------------------------------------------
    def register_session(self, session_id: str, agent_name: str, source: str = "agent") -> AgentSession:
        if self._sessions is None:
            raise ServiceError("session registry not configured")
        existing = self._sessions.get(session_id)
        session = existing or AgentSession(session_id=session_id, agent_name=agent_name, source=source)
        session.agent_name = agent_name or session.agent_name
        session.source = source or session.source
        session.last_seen = _utcnow()
        self._sessions.upsert(session)
        return session

    def list_sessions(self) -> list[AgentSession]:
        return self._sessions.list() if self._sessions is not None else []

    def get_session(self, session_id: str) -> AgentSession:
        s = self._sessions.get(session_id) if self._sessions is not None else None
        if s is None:
            raise NotFoundError(f"session '{session_id}' not found")
        return s

    # -- audit reads -------------------------------------------------------
    def get_event(self, event_id: str) -> AuditEvent:
        event = self._audit.get(event_id)
        if event is None:
            raise NotFoundError(f"audit event '{event_id}' not found")
        return event

    def list_events(self, **filters) -> tuple[list[AuditEvent], int]:
        limit = filters.get("limit", 50)
        offset = filters.get("offset", 0)
        count = self._audit.count(**{k: v for k, v in filters.items()
                                     if k not in ("limit", "offset")})
        return self._audit.list(**filters), count

    # -- approvals ---------------------------------------------------------
    def _refresh_expiry(self, approval: ApprovalRequest) -> ApprovalRequest:
        if approval.status == ApprovalStatus.PENDING.value and approval.is_expired():
            approval.status = ApprovalStatus.EXPIRED.value
            approval.resolved_at = _utcnow()
            self._approvals.update(approval)
            self._audit.set_approval_status(approval.event_id, approval.status, approval.approval_id)
        return approval

    def get_approval(self, approval_id: str) -> ApprovalRequest:
        approval = self._approvals.get(approval_id)
        if approval is None:
            raise NotFoundError(f"approval '{approval_id}' not found")
        return self._refresh_expiry(approval)

    def list_approvals(self, **filters) -> tuple[list[ApprovalRequest], int]:
        items = [self._refresh_expiry(a) for a in self._approvals.list(**filters)]
        return items, len(items)

    def _resolve(self, approval_id: str, new_status: ApprovalStatus, approver: str) -> ApprovalRequest:
        approval = self.get_approval(approval_id)
        # An approval only ever exists for an ASK; a DENY never created one, so
        # this path can never approve a deterministic DENY.
        if approval.status != ApprovalStatus.PENDING.value:
            raise ConflictError(
                f"approval '{approval_id}' is {approval.status}, not PENDING; cannot change."
            )
        approval.status = new_status.value
        approval.approver = approver
        approval.resolved_at = _utcnow()
        self._approvals.update(approval)
        self._audit.set_approval_status(approval.event_id, approval.status, approval.approval_id)
        return approval

    def approve(self, approval_id: str, approver: str) -> ApprovalRequest:
        return self._resolve(approval_id, ApprovalStatus.APPROVED, approver)

    def reject(self, approval_id: str, approver: str) -> ApprovalRequest:
        return self._resolve(approval_id, ApprovalStatus.REJECTED, approver)

    # -- consume (fingerprint-verified gate before execution) --------------
    def consume(self, approval_id: str, req: EvaluateRequest) -> ConsumeResult:
        approval = self.get_approval(approval_id)

        if approval.status != ApprovalStatus.APPROVED.value:
            return ConsumeResult(False, f"approval is {approval.status}, not APPROVED",
                                 "N/A", approval.status)
        if approval.is_expired():
            return ConsumeResult(False, "approval has expired", "N/A", ApprovalStatus.EXPIRED.value)
        if approval.consumed:
            return ConsumeResult(False, "approval was already used", "N/A", approval.status)

        # Re-derive the fingerprint from the action the agent now intends to run.
        policy = build_policy(req)
        action = build_action(req)
        fingerprint = action_fingerprint(action, policy)

        if fingerprint != approval.action_fingerprint:
            return ConsumeResult(
                False,
                "action fingerprint mismatch — the goal, policy, action, resource, "
                "or context changed since approval; the approval does not apply.",
                "N/A", approval.status,
            )

        # Defensive re-evaluation: identical action must still not be a DENY.
        result = self._engine.evaluate(action, policy)
        if result.decision is Decision.DENY:
            return ConsumeResult(False, "action is now denied by the security engine",
                                 result.decision.value, approval.status)

        approval.consumed = True
        approval.consumed_at = _utcnow()
        self._approvals.update(approval)
        self._audit.set_execution_status(approval.event_id, ExecutionStatus.AUTHORIZED.value)
        return ConsumeResult(True, "approved and verified; agent may execute this exact action",
                             result.decision.value, approval.status)

    # -- execution reporting (agent-reported; Agent Guard never executes) --
    def report_execution(self, event_id: str, status: ExecutionStatus) -> AuditEvent:
        event = self.get_event(event_id)
        self._audit.set_execution_status(event_id, status.value)
        return self.get_event(event_id)
