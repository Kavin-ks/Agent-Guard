"""
Agent Guard SDK / adapter.

Sits between an AI agent and its tools: the agent asks the adapter to run a tool,
the adapter evaluates the action through the Agent Guard API FIRST, and only
invokes the wrapped tool if the decision authorizes it. This is what turns a
security *decision* into real *enforcement*.

Trust boundary: the adapter can only enforce tools invoked THROUGH it. If an
agent bypasses the adapter and calls its tool directly, Agent Guard cannot stop
that — integration is required (see README "trust boundary").
"""

from .client import AgentGuardClient
from .errors import (
    GuardAuthError,
    GuardError,
    GuardProtocolError,
    GuardUnavailable,
)
from .executor import ExecutionResult, GuardedExecutor
from .registry import Tool, ToolRegistry
from .approval import (
    ApprovalHandler,
    AutoApprove,
    AutoReject,
    CallbackApprovalHandler,
)

__all__ = [
    "AgentGuardClient",
    "GuardedExecutor",
    "ExecutionResult",
    "Tool",
    "ToolRegistry",
    "ApprovalHandler",
    "AutoApprove",
    "AutoReject",
    "CallbackApprovalHandler",
    "GuardError",
    "GuardUnavailable",
    "GuardAuthError",
    "GuardProtocolError",
]
