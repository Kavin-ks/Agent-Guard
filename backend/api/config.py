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
    version: str = "0.2.0"

    # LLM key (Phase 3). Not used yet; kept out of the AGENTGUARD_ prefix.
    anthropic_api_key: str = Field(default="", alias="ANTHROPIC_API_KEY")


@lru_cache
def get_settings() -> Settings:
    return Settings()
