"""Audit endpoints: list, get, and agent-reported execution status."""

from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query

from agentguard.audit import AuditEvent, ExecutionStatus

from ..auth import require_api_key
from ..deps import get_service
from ..schemas import AuditListResponse, ExecutionReportRequest
from ..service import GuardService, ServiceError

router = APIRouter(prefix="/audit", tags=["audit"], dependencies=[Depends(require_api_key)])


@router.get("", response_model=AuditListResponse)
def list_audit(
    service: GuardService = Depends(get_service),
    decision: str | None = Query(None, pattern="^(ALLOW|ASK|DENY)$"),
    session_id: str | None = None,
    resource_contains: str | None = None,
    min_risk: int | None = Query(None, ge=0, le=100),
    goal_drift: bool | None = None,
    approval_status: str | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
) -> AuditListResponse:
    items, total = service.list_events(
        decision=decision, session_id=session_id, resource_contains=resource_contains,
        min_risk=min_risk, goal_drift=goal_drift, approval_status=approval_status,
        since=since, until=until, limit=limit, offset=offset,
    )
    return AuditListResponse(items=items, total=total, limit=limit, offset=offset)


@router.get("/{event_id}", response_model=AuditEvent)
def get_audit(event_id: str, service: GuardService = Depends(get_service)) -> AuditEvent:
    try:
        return service.get_event(event_id)
    except ServiceError as exc:
        raise HTTPException(status_code=exc.http_status, detail=str(exc))


@router.post("/{event_id}/execution", response_model=AuditEvent)
def report_execution(
    event_id: str,
    body: ExecutionReportRequest,
    service: GuardService = Depends(get_service),
) -> AuditEvent:
    """Record the agent's self-reported execution outcome (Agent Guard never executes)."""
    try:
        return service.report_execution(event_id, ExecutionStatus(body.status))
    except ServiceError as exc:
        raise HTTPException(status_code=exc.http_status, detail=str(exc))
