"""
The core interception endpoint: POST /guard/evaluate.

Receives a proposed agent action, runs it through the Phase 1 security engine,
and returns ALLOW / ASK / DENY with an explainable reason. Agent Guard does NOT
execute the action — the caller is responsible for honoring the verdict.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends

from agentguard import Engine

from ..auth import require_api_key
from ..deps import build_action, build_policy, get_engine
from ..schemas import (
    AppliedPolicy,
    EvaluateRequest,
    EvaluateResponse,
    SecretOut,
    SignalOut,
)

router = APIRouter(prefix="/guard", tags=["guard"])


@router.post(
    "/evaluate",
    response_model=EvaluateResponse,
    dependencies=[Depends(require_api_key)],
)
def evaluate(
    req: EvaluateRequest,
    engine: Engine = Depends(get_engine),
) -> EvaluateResponse:
    policy = build_policy(req)
    action = build_action(req)

    # The deterministic engine is authoritative. Nothing in this layer can
    # upgrade a DENY to ALLOW.
    result = engine.evaluate(action, policy)

    return EvaluateResponse(
        decision=result.decision.value,
        risk_score=result.risk_score,
        reason=result.reason,
        matched_rule=result.matched_rule,
        sensitive_data_detected=result.sensitive_data_detected,
        secrets=[
            SecretOut(type=s.type, fingerprint=s.fingerprint, entropy=s.entropy)
            for s in result.secrets
        ],
        signals=[
            SignalOut(
                gate=s.gate,
                severity=s.severity.value,
                risk_points=s.risk_points,
                reason=s.reason,
                rule_id=s.rule_id,
                advisory=s.advisory,
            )
            for s in result.signals
        ],
        policy=AppliedPolicy(
            session_id=policy.session_id,
            allowed_scopes=policy.allowed_scopes,
            restricted_scopes=policy.restricted_scopes,
            external_communication=policy.external_communication,
        ),
        action_id=result.action_id,
        latency_ms=result.latency_ms,
    )
