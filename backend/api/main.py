"""
Application startup.

Assembles the FastAPI app from the modular pieces (config, auth, routes) plus the
Phase 8 hardening layer (CORS, security headers, body-size limit, optional rate
limiting, safe error handling, log redaction). Run:

    cd backend
    uvicorn api.main:app --reload
"""

from __future__ import annotations

import logging

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from starlette.responses import JSONResponse

from .config import get_settings
from .logging_setup import configure_logging
from .middleware import (
    BodySizeLimitMiddleware,
    RateLimitMiddleware,
    SecurityHeadersMiddleware,
)
from .routes import approvals, audit, guard, health

logger = logging.getLogger("agentguard.api")


def create_app() -> FastAPI:
    settings = get_settings()
    configure_logging(settings.log_level)

    app = FastAPI(
        title="Agent Guard",
        version=settings.version,
        description=(
            "Runtime Goal-Aware Authorization Firewall for Autonomous AI Agents. "
            "Evaluates a proposed agent action as ALLOW / ASK / DENY before "
            "execution. Agent Guard never executes the action itself."
        ),
    )

    # --- hardening middleware (safe defaults) ---
    origins = [o.strip() for o in settings.cors_origins.split(",") if o.strip()]
    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,                 # empty => no cross-origin access
        allow_credentials=False,
        allow_methods=["GET", "POST"],
        allow_headers=["Content-Type", "X-API-Key"],
    )
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(BodySizeLimitMiddleware, max_bytes=settings.max_request_bytes)
    app.add_middleware(RateLimitMiddleware, per_minute=settings.rate_limit_per_minute)

    # --- safe error handling: never leak internals ---
    @app.exception_handler(Exception)
    async def _unhandled(_request: Request, exc: Exception):  # noqa: ANN001
        logger.error("Unhandled error: %s", type(exc).__name__)  # type only, no payload
        return JSONResponse({"detail": "Internal server error"}, status_code=500)

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
