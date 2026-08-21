"""Deterministic security gates."""

from .base import Gate, GateContext
from .destructive import DestructiveGate
from .external_comm import ExternalCommGate
from .policy_scope import PolicyScopeGate
from .protected_resource import ProtectedResourceGate
from .secret_exfil import SecretExfilGate

# Execution order matters: the most authoritative / highest-severity gates run
# first so that the primary reason surfaced is the strongest one.
DEFAULT_GATES: tuple[Gate, ...] = (
    SecretExfilGate(),
    ProtectedResourceGate(),
    PolicyScopeGate(),
    DestructiveGate(),
    ExternalCommGate(),
)

__all__ = [
    "Gate",
    "GateContext",
    "DEFAULT_GATES",
    "SecretExfilGate",
    "ProtectedResourceGate",
    "PolicyScopeGate",
    "DestructiveGate",
    "ExternalCommGate",
]
