"""
Agent Guard MCP integration.

Exposes real, side-effecting agent tools (file read/write/delete, shell command,
external HTTP request) through the Model Context Protocol, with EVERY call routed
through the existing Agent Guard engine (via the SDK's GuardedExecutor) BEFORE
execution. No security logic is duplicated here — the backend remains the sole
authority.

Trust boundary: Agent Guard governs tool calls made THROUGH this server. It does
not, and cannot, silently intercept an IDE's own internal tools — an MCP-capable
agent must connect its tools to this server.
"""

from .provider import GuardedToolProvider, ToolResult

__all__ = ["GuardedToolProvider", "ToolResult"]
