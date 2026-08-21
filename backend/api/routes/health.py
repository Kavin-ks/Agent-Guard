"""Health endpoint (unauthenticated liveness/readiness)."""

from __future__ import annotations

from fastapi import APIRouter, Depends

from agentguard.gates import DEFAULT_GATES

from ..config import Settings, get_settings
from ..schemas import HealthResponse

router = APIRouter(tags=["system"])


@router.get("/health", response_model=HealthResponse)
def health(settings: Settings = Depends(get_settings)) -> HealthResponse:
    return HealthResponse(
        status="ok",
        service=settings.service_name,
        version=settings.version,
        engine="ready",
        gates=[g.name for g in DEFAULT_GATES],
    )
