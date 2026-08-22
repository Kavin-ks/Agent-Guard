"""
Dependency wiring: engine, persistent stores, and the guard service.

All singletons are cached; tests clear the caches after pointing configuration at
a temporary database. No security logic lives here.
"""

from __future__ import annotations

from functools import lru_cache

from agentguard import Engine
from agentguard.advisors import ClaudeRelevanceAdvisor, HeuristicRelevanceAdvisor

from .config import get_settings
from .service import GuardService
from .store.base import ApprovalStore, AuditStore, SessionStore
from .store.sqlite import SqliteApprovalStore, SqliteAuditStore, SqliteSessionStore


@lru_cache
def get_engine() -> Engine:
    """Shared, stateless engine with the configured goal-relevance advisor.

    The advisor is advisory only — the deterministic gates remain authoritative.
    """
    s = get_settings()
    mode = (s.advisor or "auto").lower()

    if mode == "off":
        advisor = None
    elif mode == "heuristic":
        advisor = HeuristicRelevanceAdvisor()
    elif mode == "llm" or (mode == "auto" and s.anthropic_api_key):
        advisor = ClaudeRelevanceAdvisor(
            model=s.advisor_model,
            timeout_s=s.advisor_timeout_s,
            fallback=HeuristicRelevanceAdvisor(),
        )
    else:  # auto without a key -> offline heuristic (goal-awareness still works)
        advisor = HeuristicRelevanceAdvisor()

    return Engine(advisor=advisor)


@lru_cache
def get_audit_store() -> AuditStore:
    return SqliteAuditStore(get_settings().db_path)


@lru_cache
def get_approval_store() -> ApprovalStore:
    return SqliteApprovalStore(get_settings().db_path)


@lru_cache
def get_session_store() -> SessionStore:
    return SqliteSessionStore(get_settings().db_path)


@lru_cache
def get_service() -> GuardService:
    s = get_settings()
    return GuardService(
        engine=get_engine(),
        audit_store=get_audit_store(),
        approval_store=get_approval_store(),
        approval_ttl_seconds=s.approval_ttl_seconds,
        session_store=get_session_store(),
    )
