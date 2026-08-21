"""
Unified sensitive-data scan.

Aggregates the modular detectors (secrets, PII, financial) into one list of
redacted ``SensitiveFinding`` objects. This is the single local entry point the
engine uses; the raw text never leaves this boundary — callers receive only
categories, severities, and fingerprints.

The secrets detector is reused as-is (no duplicated regexes) and its findings are
mapped onto the SECRET / AUTHENTICATION categories.
"""

from __future__ import annotations

from .base import Category, SensitiveFinding, Severity, SEVERITY_RANK
from .financial import detect_financial
from .pii import detect_pii
from .secrets import detect_secrets

_MIN_CONFIDENCE = 0.5

# Secret subtypes that are really authentication material.
_AUTH_SUBTYPES = {"jwt", "bearer_token", "private_key_block", "google_oauth_token"}


def _map_secret(f, location: str) -> SensitiveFinding:
    category = Category.AUTHENTICATION if f.type in _AUTH_SUBTYPES else Category.SECRET
    severity = Severity.CRITICAL if f.type == "private_key_block" else Severity.HIGH
    confidence = 0.6 if (f.type == "high_entropy_token" or f.type.startswith("assigned_")) else 0.95
    return SensitiveFinding(category=category, subtype=f.type, severity=severity,
                            confidence=confidence, fingerprint=f.fingerprint,
                            location=location, entropy=f.entropy)


def scan_text(text: str | None, location: str = "payload") -> list[SensitiveFinding]:
    """Return redacted sensitive findings in ``text`` (confidence-filtered)."""
    if not text:
        return []
    findings: list[SensitiveFinding] = []
    findings.extend(_map_secret(f, location) for f in detect_secrets(text))
    findings.extend(detect_pii(text, location))
    findings.extend(detect_financial(text, location))
    return [f for f in findings if f.confidence >= _MIN_CONFIDENCE]


def categories(findings: list[SensitiveFinding]) -> list[str]:
    """Distinct category labels present, in a stable order."""
    order = [Category.SECRET, Category.AUTHENTICATION, Category.FINANCIAL,
             Category.PII, Category.SENSITIVE_FILE]
    present = {f.category for f in findings}
    return [c.value for c in order if c in present]


def max_severity(findings: list[SensitiveFinding]) -> Severity | None:
    if not findings:
        return None
    return max((f.severity for f in findings), key=lambda s: SEVERITY_RANK[s])


def has_high_or_critical(findings: list[SensitiveFinding]) -> bool:
    return any(f.severity in (Severity.HIGH, Severity.CRITICAL) for f in findings)
