"""
Core interception endpoint: POST /guard/evaluate.

Runs the action through the security engine via the service layer, persists an
audit record, and (for ASK) creates a human approval request. Agent Guard does
NOT execute the action — the response makes that trust boundary explicit.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends

from ..auth import require_api_key
from ..deps import get_service
from ..schemas import (
    AppliedPolicy,
    EvaluateRequest,
    EvaluateResponse,
    SecretOut,
    SensitiveOut,
    SignalOut,
)
from ..service import GuardService
from ..bridge import build_policy

router = APIRouter(prefix="/guard", tags=["guard"])


@router.post(
    "/evaluate",
    response_model=EvaluateResponse,
    dependencies=[Depends(require_api_key)],
)
def evaluate(
    req: EvaluateRequest,
    service: GuardService = Depends(get_service),
) -> EvaluateResponse:
    outcome = service.evaluate(req)
    result = outcome.result
    event = outcome.event
    policy = build_policy(req)  # for the applied-policy echo (deterministic, cheap)

    return EvaluateResponse(
        decision=result.decision.value,
        risk_score=result.risk_score,
        reason=result.reason,
        matched_rule=result.matched_rule,
        sensitive_data_detected=result.sensitive_data_detected,
        secrets=[SecretOut(type=s.type, fingerprint=s.fingerprint, entropy=s.entropy)
                 for s in result.secrets],
        sensitive=[SensitiveOut(category=s.category, subtype=s.subtype, severity=s.severity,
                                confidence=s.confidence, fingerprint=s.fingerprint, location=s.location)
                   for s in result.sensitive],
        sensitive_categories=result.sensitive_categories,
        signals=[SignalOut(gate=s.gate, severity=s.severity.value, risk_points=s.risk_points,
                           reason=s.reason, rule_id=s.rule_id, advisory=s.advisory)
                 for s in result.signals],
        deterministic_decision=(
            result.deterministic_decision.value if result.deterministic_decision else None
        ),
        goal_relevance=result.goal_relevance,
        goal_relevance_confidence=result.goal_relevance_confidence,
        goal_drift=result.goal_drift,
        advisory_recommendation=result.advisory_recommendation,
        advisory_available=result.advisory_available,
        advisory_source=result.advisory_source,
        advisory_reason=result.advisory_reason,
        event_id=event.event_id,
        action_fingerprint=event.action_fingerprint,
        approval_required=outcome.approval is not None,
        approval_id=outcome.approval.approval_id if outcome.approval else None,
        execution_status=event.execution_status,
        policy=AppliedPolicy(
            session_id=policy.session_id,
            allowed_scopes=policy.allowed_scopes,
            restricted_scopes=policy.restricted_scopes,
            external_communication=policy.external_communication,
        ),
        action_id=result.action_id,
        latency_ms=result.latency_ms,
    )
