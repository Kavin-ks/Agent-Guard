"""
Application startup.

Assembles the FastAPI app from the modular pieces (config, auth, routes). Run:

    cd backend
    uvicorn api.main:app --reload
"""

from __future__ import annotations

import logging

from fastapi import FastAPI

from .config import get_settings
from .routes import approvals, audit, guard, health

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("agentguard.api")


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title="Agent Guard",
        version=settings.version,
        description=(
            "Runtime Goal-Aware Authorization Firewall for Autonomous AI Agents. "
            "Evaluates a proposed agent action as ALLOW / ASK / DENY before "
            "execution. Agent Guard never executes the action itself."
        ),
    )

    app.include_router(health.router)
    app.include_router(guard.router)
    app.include_router(audit.router)
    app.include_router(approvals.router)

    if not settings.api_key:
        logger.warning(
            "AGENTGUARD_API_KEY is not set — protected routes will reject all "
            "requests (fail-closed). Set it in the environment to enable access."
        )

    return app


app = create_app()
