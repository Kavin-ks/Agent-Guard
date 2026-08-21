"""
Approval endpoints: list, get, approve, reject, and the fingerprint-verified
consume gate. Approval applies ONLY to ASK decisions and can never turn a
deterministic DENY into an allowed action (a DENY never creates an approval).
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query

from agentguard.audit import ApprovalRequest

from ..auth import require_api_key
from ..deps import get_service
from ..schemas import (
    ApprovalListResponse,
    ConsumeResponse,
    EvaluateRequest,
    ResolveRequest,
)
from ..service import GuardService, ServiceError

router = APIRouter(prefix="/approvals", tags=["approvals"],
                   dependencies=[Depends(require_api_key)])


@router.get("", response_model=ApprovalListResponse)
def list_approvals(
    service: GuardService = Depends(get_service),
    status: str | None = Query(None, pattern="^(PENDING|APPROVED|REJECTED|EXPIRED)$"),
    session_id: str | None = None,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
) -> ApprovalListResponse:
    items, total = service.list_approvals(
        status=status, session_id=session_id, limit=limit, offset=offset
    )
    return ApprovalListResponse(items=items, total=total, limit=limit, offset=offset)


@router.get("/{approval_id}", response_model=ApprovalRequest)
def get_approval(approval_id: str, service: GuardService = Depends(get_service)) -> ApprovalRequest:
    try:
        return service.get_approval(approval_id)
    except ServiceError as exc:
        raise HTTPException(status_code=exc.http_status, detail=str(exc))


@router.post("/{approval_id}/approve", response_model=ApprovalRequest)
def approve(approval_id: str, body: ResolveRequest,
            service: GuardService = Depends(get_service)) -> ApprovalRequest:
    try:
        return service.approve(approval_id, body.approver)
    except ServiceError as exc:
        raise HTTPException(status_code=exc.http_status, detail=str(exc))


@router.post("/{approval_id}/reject", response_model=ApprovalRequest)
def reject(approval_id: str, body: ResolveRequest,
           service: GuardService = Depends(get_service)) -> ApprovalRequest:
    try:
        return service.reject(approval_id, body.approver)
    except ServiceError as exc:
        raise HTTPException(status_code=exc.http_status, detail=str(exc))


@router.post("/{approval_id}/consume", response_model=ConsumeResponse)
def consume(approval_id: str, req: EvaluateRequest,
            service: GuardService = Depends(get_service)) -> ConsumeResponse:
    """Verify an approved action before execution: the action the agent presents
    must fingerprint-match the approved one, or authorization is refused."""
    try:
        r = service.consume(approval_id, req)
    except ServiceError as exc:
        raise HTTPException(status_code=exc.http_status, detail=str(exc))
    return ConsumeResponse(authorized=r.authorized, reason=r.reason,
                           decision=r.decision, approval_status=r.approval_status)
