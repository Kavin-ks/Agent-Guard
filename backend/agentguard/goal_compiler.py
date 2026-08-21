"""
Goal -> Policy / GoalRepresentation compilation (deterministic).

Phase 3 ships a deterministic, keyword-based compiler that produces BOTH:
  * an inspectable ``GoalRepresentation`` (objective, topics, scopes, constraints), and
  * a runtime ``Policy`` used by the deterministic gates.

Design rule — do NOT blindly trust natural-language instructions. Extracted
constraints can only ADD restrictions; allowed scopes are drawn from recognized
project types, and the engine always unions the built-in protected resources on
top. A weak or adversarial goal parse therefore can never expose secrets.

An optional LLM compiler may enrich this later, but it layers on top of — never
replaces — this deterministic baseline. This module performs NO I/O and calls NO LLM.
"""

from __future__ import annotations

import re

from .constants import DEFAULT_PROTECTED_GLOBS
from .goal import GoalRepresentation
from .models import Operation, Policy

# --- topic / scope keyword tables -----------------------------------------
_FRONTEND_HINTS = ("react", "frontend", "front-end", "website", "portfolio", "ui",
                   "css", "component", "landing page", "web app", "vue", "svelte", "next.js")
_FRONTEND_ALLOW = ["src/**", "components/**", "public/**", "assets/**",
                   "*.css", "*.scss", "*.html", "*.jsx", "*.tsx", "*.js", "*.ts", "*.json"]
_FRONTEND_TOOLS = ["filesystem", "package_manager", "test_runner", "build_tool"]

_BACKEND_HINTS = ("backend", "back-end", "server", "server-side")
_BACKEND_RESTRICT = ["backend/**", "server/**", "api/**"]

_DB_HINTS = ("database", "db", "sql", "postgres", "mysql", "mongo", "schema")
_DB_RESTRICT = ["database/**", "db/**", "migrations/**", "**/*.sql"]

_NO_EXTERNAL_HINTS = ("no external", "do not access the internet", "offline",
                      "no network", "do not send", "no outbound",
                      "without accessing the internet", "no internet")

# Human-readable prohibition extraction: "do not X", "never X", "don't X".
_PROHIBITION_RE = re.compile(
    r"(?i)\b(?:do not|don't|never|avoid|must not|no)\b[^.;\n]{0,80}"
)

# A compact set of built-in sensitive resource labels for the representation.
_SENSITIVE_LABELS = [".env", "credentials", "private keys (*.pem/*.key)",
                     ".ssh", "service accounts", "secrets"]


def _topics(text: str) -> list[str]:
    topics: list[str] = []
    for group, label in ((_FRONTEND_HINTS, "frontend"), (_BACKEND_HINTS, "backend"),
                         (_DB_HINTS, "database")):
        if any(h in text for h in group):
            topics.append(label)
    # Also surface the concrete matched keywords (useful for relevance scoring).
    for h in _FRONTEND_HINTS + _DB_HINTS:
        if h in text and h not in topics:
            topics.append(h)
    return list(dict.fromkeys(topics))


def compile_goal_representation(goal: str) -> GoalRepresentation:
    """Deterministically derive an inspectable representation of the goal."""
    text = (goal or "").lower()

    allowed: list[str] = []
    restricted: list[str] = []
    tool_categories: list[str] = []

    is_frontend = any(h in text for h in _FRONTEND_HINTS)
    if is_frontend:
        allowed.extend(_FRONTEND_ALLOW)
        tool_categories.extend(_FRONTEND_TOOLS)
    if any(h in text for h in _BACKEND_HINTS):
        restricted.extend(_BACKEND_RESTRICT)
    if any(h in text for h in _DB_HINTS):
        restricted.extend(_DB_RESTRICT)

    no_external = any(h in text for h in _NO_EXTERNAL_HINTS)

    constraints = [m.group(0).strip() for m in _PROHIBITION_RE.finditer(goal or "")]
    if no_external:
        constraints.append("external communication is prohibited")

    prohibited_ops: list[Operation] = []

    return GoalRepresentation(
        objective=(goal or "").strip(),
        topics=_topics(text),
        allowed_resources=list(dict.fromkeys(allowed)),
        restricted_resources=list(dict.fromkeys(restricted)),
        sensitive_resources=list(_SENSITIVE_LABELS),
        allowed_operations=list(Operation),
        prohibited_operations=prohibited_ops,
        expected_tool_categories=list(dict.fromkeys(tool_categories)),
        constraints=list(dict.fromkeys(constraints)),
    )


def compile_goal(goal: str, session_id: str = "default") -> Policy:
    """Derive a runtime ``Policy`` from a goal string (via the representation)."""
    rep = compile_goal_representation(goal)
    text = (goal or "").lower()
    external = "deny" if any(h in text for h in _NO_EXTERNAL_HINTS) else "ask"

    return Policy(
        session_id=session_id,
        goal_text=goal or "",
        allowed_scopes=rep.allowed_resources,
        restricted_scopes=rep.restricted_resources,
        external_communication=external,
        destructive_requires_approval=True,
    )


# Exposed for callers/tests that want to see the always-on protected set.
BUILTIN_PROTECTED = list(DEFAULT_PROTECTED_GLOBS)
