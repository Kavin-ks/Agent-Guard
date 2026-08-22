"""
Text redaction for prompts / arguments shown in the dashboard.

Replaces secret-like substrings (API keys, tokens, private keys, bearer/auth
headers, ``key=value`` credentials, high-entropy tokens) with ``[REDACTED]`` so a
user prompt or argument string can be stored/displayed without leaking secrets.
Reuses the deterministic secret detector's patterns — no new secret logic.
"""

from __future__ import annotations

import re

from .detectors.secrets import (
    _ASSIGNMENT_PATTERN,
    _CANDIDATE_TOKEN,
    _NAMED_PATTERNS,
    _shannon_entropy,
)

_AUTH_HEADER = re.compile(r"(?i)\bauthorization\s*[:=]\s*\S+")
_PLACEHOLDER = "[REDACTED]"


def redact_text(text: str | None, max_len: int = 2000) -> str:
    """Return ``text`` with secret-like substrings replaced by ``[REDACTED]``."""
    if not text:
        return ""
    out = str(text)

    matches: list[str] = []
    for _, pattern in _NAMED_PATTERNS:
        matches.extend(m.group(0) for m in pattern.finditer(out))
    for m in _ASSIGNMENT_PATTERN.finditer(out):
        matches.append(m.group("value"))
    for m in _CANDIDATE_TOKEN.finditer(out):
        if _shannon_entropy(m.group(0)) >= 4.0:
            matches.append(m.group(0))

    # Longest first so nested matches redact cleanly.
    for raw in sorted(set(matches), key=len, reverse=True):
        if raw:
            out = out.replace(raw, _PLACEHOLDER)

    out = _AUTH_HEADER.sub("authorization: " + _PLACEHOLDER, out)

    if len(out) > max_len:
        out = out[:max_len] + "…"
    return out
