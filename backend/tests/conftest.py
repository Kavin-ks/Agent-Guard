"""Shared fixtures for the Agent Guard engine tests."""

from __future__ import annotations

import pytest

from agentguard import Engine, Policy


@pytest.fixture
def engine() -> Engine:
    """A pure engine with the default deterministic gates and no LLM advisor."""
    return Engine()


@pytest.fixture
def react_policy() -> Policy:
    """The canonical demo goal:

    "Build a React portfolio website. You may modify frontend files. Do not
    access backend files, databases, secrets, or credentials."
    """
    return Policy(
        session_id="demo-session",
        goal_text=(
            "Build a React portfolio website. You may modify frontend files. "
            "Do not access backend files, databases, secrets, or credentials."
        ),
        allowed_scopes=["src/**", "components/**", "public/**", "*.css", "*.jsx", "*.tsx"],
        restricted_scopes=["backend/**", "database/**", "**/*.sql", "db/**", "server/**"],
        external_communication="deny",
        network_allowlist=[],
        destructive_requires_approval=True,
    )
