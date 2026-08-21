"""
Goal representation and advisory data types.

`GoalRepresentation` is an inspectable, structured view of what the user asked
for — objective, topics, allowed/restricted resources, operations, expected tool
categories, and constraints. It is produced deterministically by the goal
compiler and is what makes "goal awareness" explainable rather than a black box.

`AdvisorRequest` is the ONLY data an LLM advisor ever receives. It carries action
metadata and goal text — never the payload, never a secret value. See
`advisors/base.py::build_advisor_request` for how it is constructed and
`README.md` for the data-minimization contract.
"""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, ConfigDict, Field

from .models import Decision, Operation


class RelevanceLevel(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class GoalRepresentation(BaseModel):
    """Structured, inspectable representation of the user's goal."""

    model_config = ConfigDict(extra="forbid")

    objective: str
    topics: list[str] = Field(default_factory=list)
    allowed_resources: list[str] = Field(default_factory=list)
    restricted_resources: list[str] = Field(default_factory=list)
    sensitive_resources: list[str] = Field(default_factory=list)
    allowed_operations: list[Operation] = Field(default_factory=list)
    prohibited_operations: list[Operation] = Field(default_factory=list)
    expected_tool_categories: list[str] = Field(default_factory=list)
    constraints: list[str] = Field(default_factory=list)


class AdvisorRequest(BaseModel):
    """The minimal, redacted payload sent to a relevance advisor (incl. any LLM).

    Contains NO raw payload text and NO secret values — only booleans/metadata.
    """

    model_config = ConfigDict(extra="forbid")

    goal: str
    operation: str
    resource_kind: str
    resource: str            # a path or URL (not a secret value)
    tool: str
    destination: str | None = None
    payload_present: bool = False
    payload_contains_secret: bool = False  # boolean only; the value is never sent
    context_keys: list[str] = Field(default_factory=list)


class RelevanceAssessment(BaseModel):
    """Structured output of a relevance advisor. Purely advisory."""

    model_config = ConfigDict(extra="forbid")

    relevance: RelevanceLevel
    confidence: float = Field(ge=0.0, le=1.0)
    reason: str
    recommended_action: Decision  # advisory only; cannot force/override a hard DENY
    goal_drift: bool = False
    available: bool = True         # False => advisor could not run (LLM down, etc.)
    source: str = "heuristic"      # "llm:claude-…" | "heuristic" | "mock" | ...
