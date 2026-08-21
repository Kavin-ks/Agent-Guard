"""
Deterministic security constants for Agent Guard.

These are the built-in, non-negotiable protections. They are ALWAYS applied and
can never be weakened by a user-supplied policy (see gates.protected_resource).

Nothing in this module performs I/O or executes anything. It is pure data.
"""

from __future__ import annotations

import re

# ---------------------------------------------------------------------------
# Built-in protected resource globs.
#
# Any resource matching one of these is treated as sensitive regardless of what
# the user's policy says. Matching is case-insensitive and performed against a
# normalized (traversal-collapsed, lower-cased) path (see paths.normalize_path).
# ---------------------------------------------------------------------------
DEFAULT_PROTECTED_GLOBS: tuple[str, ...] = (
    "**/.env",
    "**/.env.*",
    "**/*.env",
    "**/.env*",
    "**/secrets",
    "**/secrets/**",
    "**/secret",
    "**/secret.*",
    "**/*secret*",
    "**/credentials",
    "**/credentials/**",
    "**/*credential*",
    "**/id_rsa",
    "**/id_dsa",
    "**/id_ecdsa",
    "**/id_ed25519",
    "**/*.pem",
    "**/*.key",
    "**/*.pfx",
    "**/*.p12",
    "**/*.keystore",
    "**/*.jks",
    "**/.aws/**",
    "**/.ssh/**",
    "**/.npmrc",
    "**/.pypirc",
    "**/.git-credentials",
    "**/service-account*.json",
    "**/*serviceaccount*.json",
)

# ---------------------------------------------------------------------------
# Destructive-action markers.
#
# When an execute/delete action's resource or payload contains one of these,
# the destructive gate escalates the action to at least ASK (human approval).
# ---------------------------------------------------------------------------
DESTRUCTIVE_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\brm\s+-[a-z]*[rf]", re.IGNORECASE),
    re.compile(r"\brmdir\b", re.IGNORECASE),
    re.compile(r"\bdrop\s+(table|database|schema)\b", re.IGNORECASE),
    re.compile(r"\btruncate\s+table\b", re.IGNORECASE),
    re.compile(r"\bdelete\s+from\b", re.IGNORECASE),
    re.compile(r"\bgit\s+push\s+.*--force", re.IGNORECASE),
    re.compile(r"\bgit\s+push\s+-f\b", re.IGNORECASE),
    re.compile(r"\bgit\s+reset\s+--hard", re.IGNORECASE),
    re.compile(r"\bgit\s+clean\s+-[a-z]*f", re.IGNORECASE),
    re.compile(r"\bmkfs\b", re.IGNORECASE),
    re.compile(r"\bformat\b\s+[a-z]:", re.IGNORECASE),
    re.compile(r":\(\)\s*\{\s*:\|:&\s*\}\s*;:", re.IGNORECASE),  # fork bomb
    re.compile(r"\bshutdown\b|\breboot\b", re.IGNORECASE),
    re.compile(r"\bdd\s+if=.*of=/dev/", re.IGNORECASE),
)

# ---------------------------------------------------------------------------
# Operation base risk. This is the floor risk for an operation before any
# gate signals are added. Tuned so that in-scope reads/writes/tests land in the
# ALLOW band (< 40) while transmit/delete start higher.
# ---------------------------------------------------------------------------
OPERATION_BASE_RISK: dict[str, int] = {
    "read": 8,
    "write": 14,
    "execute": 18,
    "network": 25,
    "delete": 30,
    "transmit": 40,
}

# Risk band thresholds (inclusive lower bounds).
DEFAULT_ASK_THRESHOLD = 40
DEFAULT_DENY_THRESHOLD = 75

MAX_RISK = 100
