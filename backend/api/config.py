"""
Configuration for the Agent Guard API.

All settings come from environment variables (optionally a local .env file).
Secrets are NEVER hardcoded here. ``get_settings`` is cached; tests can call
``get_settings.cache_clear()`` after mutating the environment.
"""

from __future__ import annotations

from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="AGENTGUARD_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Prototype auth: a single shared API key required on protected routes.
    # Read from AGENTGUARD_API_KEY. Empty => the API fails closed (rejects all
    # protected requests) rather than running unauthenticated.
    api_key: str = ""

    service_name: str = "agent-guard"
    version: str = "0.8.0"

    # --- Hardening (Phase 8). Safe defaults; all configurable via env. ---
    # Comma-separated allowed CORS origins. Empty => no cross-origin access.
    cors_origins: str = ""
    # Reject request bodies larger than this (bytes). 0 disables the check.
    max_request_bytes: int = 2_000_000
    # Lightweight in-memory rate limit per client. 0 disables (default: off, so
    # it never interferes with tests/benchmarks; enable in production).
    rate_limit_per_minute: int = 0
    log_level: str = "INFO"

    # LLM key for the goal-relevance advisor (Phase 3). Read from ANTHROPIC_API_KEY.
    anthropic_api_key: str = Field(default="", alias="ANTHROPIC_API_KEY")

    # Advisor selection (AGENTGUARD_ADVISOR):
    #   auto      -> Claude if a key is present, else the offline heuristic
    #   llm       -> Claude advisor (falls back to heuristic if the LLM fails)
    #   heuristic -> deterministic offline advisor only (no network)
    #   off       -> no advisory layer (deterministic gates only)
    advisor: str = "auto"
    advisor_model: str = "claude-opus-5"
    advisor_timeout_s: float = 8.0

    # Persistence (Phase 5). SQLite by default so the audit trail survives restarts.
    db_path: str = "./data/agentguard.db"
    approval_ttl_seconds: int = 3600


@lru_cache
def get_settings() -> Settings:
    return Settings()
