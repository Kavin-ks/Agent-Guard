"""
Agent Guard — Runtime Goal-Aware Authorization engine.

Public surface for embedding the engine in another program or service:

    from agentguard import Engine, Action, Policy, Resource, Operation

    engine = Engine()
    decision = engine.evaluate(action, policy)

The engine is pure: it evaluates a proposed action and returns ALLOW / ASK /
DENY with an explainable reason. It never executes the action itself.
"""

from .models import (
    Action,
    Decision,
    DecisionResult,
    Operation,
    Policy,
    Resource,
    ResourceKind,
    SecretMatch,
    Severity,
    Signal,
)
from .pipeline import Engine

__all__ = [
    "Engine",
    "Action",
    "Resource",
    "ResourceKind",
    "Operation",
    "Policy",
    "Decision",
    "DecisionResult",
    "Signal",
    "Severity",
    "SecretMatch",
]

__version__ = "0.2.0"
