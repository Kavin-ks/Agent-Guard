"""
Deterministic secret detection.

Finds credential-like strings in arbitrary text (a payload the agent wants to
write or transmit). Detection is regex + Shannon-entropy based and is 100%
deterministic — it never calls an LLM.

SECURITY INVARIANT: a raw secret value is NEVER returned, logged, or stored.
Every finding carries only a *redacted fingerprint* (a few edge characters with
the middle masked) plus a type label and entropy. This is what lets the audit
log prove "a secret was seen here" without ever persisting the secret itself.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass


@dataclass(frozen=True)
class SecretFinding:
    """A detected secret, safe to log. Never contains the raw value."""

    type: str
    fingerprint: str  # e.g. "sk-…N3f9" — first/last chars, middle masked
    entropy: float


# Named, high-signal credential patterns. Order matters only for labelling.
_NAMED_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("anthropic_api_key", re.compile(r"sk-ant-[A-Za-z0-9_\-]{20,}")),
    ("openai_api_key", re.compile(r"sk-(?:proj-)?[A-Za-z0-9]{20,}")),
    ("aws_access_key_id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("google_api_key", re.compile(r"AIza[0-9A-Za-z_\-]{35}")),
    ("github_token", re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}")),
    ("slack_token", re.compile(r"xox[baprs]-[A-Za-z0-9\-]{10,}")),
    ("stripe_key", re.compile(r"(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{16,}")),
    ("google_oauth_token", re.compile(r"ya29\.[A-Za-z0-9_\-]{20,}")),
    (
        "private_key_block",
        re.compile(
            r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----",
        ),
    ),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{5,}")),
    ("bearer_token", re.compile(r"[Bb]earer\s+[A-Za-z0-9_\-\.=]{20,}")),
)

# Generic "key = value" assignments where the KEY names a secret. The value is
# what gets fingerprinted.
_ASSIGNMENT_PATTERN = re.compile(
    r"""(?ix)
    \b(?P<name>[a-z0-9_\-]*(?:password|passwd|secret|api[_\-]?key|
        access[_\-]?key|auth[_\-]?token|token|private[_\-]?key|
        client[_\-]?secret)[a-z0-9_\-]*)
    \s*[:=]\s*
    (?P<q>["']?)
    (?P<value>[^\s"']{6,})
    (?P=q)
    """
)

# Long, high-entropy tokens that don't match a named pattern.
_CANDIDATE_TOKEN = re.compile(r"[A-Za-z0-9_\-+/=]{24,}")
_ENTROPY_THRESHOLD = 4.0


def _shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts: dict[str, int] = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    length = len(text)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def _fingerprint(value: str) -> str:
    """Redact a secret to a loggable fingerprint. Never returns the raw value."""
    value = value.strip()
    if len(value) <= 8:
        return (value[:1] + "…") if value else "…"
    return f"{value[:3]}…{value[-4:]}"


def detect_secrets(text: str | None) -> list[SecretFinding]:
    """Return redacted findings for any secrets in ``text`` (deduplicated)."""
    if not text:
        return []

    findings: dict[tuple[str, str], SecretFinding] = {}

    def add(kind: str, value: str) -> None:
        fp = _fingerprint(value)
        findings.setdefault(
            (kind, fp),
            SecretFinding(type=kind, fingerprint=fp, entropy=round(_shannon_entropy(value), 2)),
        )

    for kind, pattern in _NAMED_PATTERNS:
        for match in pattern.finditer(text):
            add(kind, match.group(0))

    for match in _ASSIGNMENT_PATTERN.finditer(text):
        add(f"assigned_{match.group('name').lower()}", match.group("value"))

    # Entropy fallback for unlabelled high-entropy tokens.
    for match in _CANDIDATE_TOKEN.finditer(text):
        token = match.group(0)
        if _shannon_entropy(token) >= _ENTROPY_THRESHOLD:
            add("high_entropy_token", token)

    return list(findings.values())


def contains_secret(text: str | None) -> bool:
    return bool(detect_secrets(text))
