"""
Connected-agent endpoints. Real agents (e.g. Antigravity over MCP) register a
session and are tracked with live counts and connected/disconnected status.
Demo activity is never recorded here.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from agentguard.audit import AgentSession

from ..auth import require_api_key
from ..deps import get_service
from ..schemas import AgentOut, RegisterAgentRequest
from ..service import GuardService, ServiceError

router = APIRouter(prefix="/agents", tags=["agents"], dependencies=[Depends(require_api_key)])


def _to_out(s: AgentSession) -> AgentOut:
    return AgentOut(
        session_id=s.session_id, agent_name=s.agent_name, source=s.source,
        status=s.status(), connected_at=s.connected_at.isoformat(),
        last_seen=s.last_seen.isoformat(), calls=s.calls, allowed=s.allowed,
        asked=s.asked, denied=s.denied, last_decision=s.last_decision,
    )


@router.post("/register", response_model=AgentOut)
def register(body: RegisterAgentRequest, service: GuardService = Depends(get_service)) -> AgentOut:
    try:
        return _to_out(service.register_session(body.session_id, body.agent_name, body.source))
    except ServiceError as exc:
        raise HTTPException(status_code=exc.http_status, detail=str(exc))


@router.get("", response_model=list[AgentOut])
def list_agents(service: GuardService = Depends(get_service)) -> list[AgentOut]:
    return [_to_out(s) for s in service.list_sessions()]


@router.get("/{session_id}", response_model=AgentOut)
def get_agent(session_id: str, service: GuardService = Depends(get_service)) -> AgentOut:
    try:
        return _to_out(service.get_session(session_id))
    except ServiceError as exc:
        raise HTTPException(status_code=exc.http_status, detail=str(exc))
