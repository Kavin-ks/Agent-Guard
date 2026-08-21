"""SDK error hierarchy. Any of these means 'authorization undetermined' -> fail closed."""

from __future__ import annotations


class GuardError(Exception):
    """Base for all Agent Guard SDK errors."""


class GuardUnavailable(GuardError):
    """The Agent Guard API could not be reached (connection error / timeout)."""


class GuardAuthError(GuardError):
    """Authentication with the Agent Guard API failed (401/403)."""


class GuardProtocolError(GuardError):
    """The API returned an unexpected status or a malformed/undecodable response."""
