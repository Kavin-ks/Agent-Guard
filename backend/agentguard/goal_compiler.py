"""
Goal -> Policy compilation.

Phase 2 ships a *deterministic, keyword-based* compiler so the API is usable
standalone: it maps a natural-language goal into allowed/restricted scopes and an
external-communication posture. Phase 3 will layer an LLM-assisted compiler on
top of (never replacing) this deterministic baseline — the built-in protected
resources are always enforced by the engine regardless of what any compiler
produces, so a weak or wrong goal parse can never expose secrets.

This module performs NO I/O and calls NO LLM.
"""

from __future__ import annotations

from .models import Policy

# Keyword -> scope rules. Deliberately conservative.
_FRONTEND_HINTS = ("react", "frontend", "front-end", "website", "portfolio",
                   "ui", "css", "component", "landing page", "web app", "vue", "svelte")
_FRONTEND_ALLOW = ["src/**", "components/**", "public/**", "assets/**",
                   "*.css", "*.scss", "*.html", "*.jsx", "*.tsx", "*.js", "*.ts", "*.json"]

_BACKEND_HINTS = ("backend", "back-end", "server", "server-side")
_BACKEND_RESTRICT = ["backend/**", "server/**", "api/**"]

_DB_HINTS = ("database", "db", "sql", "postgres", "mysql", "mongo")
_DB_RESTRICT = ["database/**", "db/**", "migrations/**", "**/*.sql"]

_NO_EXTERNAL_HINTS = ("no external", "do not access the internet", "offline",
                      "no network", "do not send", "no outbound", "without accessing the internet")


def compile_goal(goal: str, session_id: str = "default") -> Policy:
    """Deterministically derive a runtime ``Policy`` from a goal string."""
    text = (goal or "").lower()

    allowed: list[str] = []
    restricted: list[str] = []

    if any(h in text for h in _FRONTEND_HINTS):
        allowed.extend(_FRONTEND_ALLOW)
    if any(h in text for h in _BACKEND_HINTS):
        restricted.extend(_BACKEND_RESTRICT)
    if any(h in text for h in _DB_HINTS):
        restricted.extend(_DB_RESTRICT)

    external = "deny" if any(h in text for h in _NO_EXTERNAL_HINTS) else "ask"

    # De-duplicate while preserving order.
    allowed = list(dict.fromkeys(allowed))
    restricted = list(dict.fromkeys(restricted))

    return Policy(
        session_id=session_id,
        goal_text=goal or "",
        allowed_scopes=allowed,
        restricted_scopes=restricted,
        external_communication=external,
        destructive_requires_approval=True,
    )
