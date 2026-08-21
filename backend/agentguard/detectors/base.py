"""
Shared types + helpers for the modular sensitive-data detectors.

Every detector returns ``SensitiveFinding`` objects that are safe to log/store:
they carry a category, a subtype, a severity, a confidence, a location, and a
REDACTED fingerprint — never the raw value. This is the single invariant the
whole phase depends on.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class Category(str, Enum):
    SECRET = "SECRET"
    AUTHENTICATION = "AUTHENTICATION"
    PII = "PII"
    FINANCIAL = "FINANCIAL"
    SENSITIVE_FILE = "SENSITIVE_FILE"


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


SEVERITY_RANK = {Severity.LOW: 0, Severity.MEDIUM: 1, Severity.HIGH: 2, Severity.CRITICAL: 3}


@dataclass(frozen=True)
class SensitiveFinding:
    """A safe, redacted description of one detected sensitive datum."""

    category: Category
    subtype: str            # e.g. "api_key", "email", "credit_card", "aadhaar"
    severity: Severity
    confidence: float       # 0.0 - 1.0 (heuristic)
    fingerprint: str        # redacted, e.g. "sk-…HHHH" or "••••1111"
    location: str = "payload"   # payload | resource | destination | context
    entropy: float = 0.0


def redact(value: str, keep_start: int = 3, keep_end: int = 3) -> str:
    """Redact a raw value to a loggable fingerprint. Never returns the raw value."""
    value = (value or "").strip()
    if len(value) <= keep_start + keep_end:
        return (value[:1] + "…") if value else "…"
    return f"{value[:keep_start]}…{value[-keep_end:]}"


def redact_tail(value: str, keep_end: int = 4) -> str:
    """Redact keeping only the last few chars (used for cards/IDs): ••••1111."""
    digits = "".join(ch for ch in (value or "") if ch.isalnum())
    if len(digits) <= keep_end:
        return "•" * len(digits)
    return "•" * (len(digits) - keep_end) + digits[-keep_end:]


def luhn_ok(number: str) -> bool:
    """Validate a numeric string with the Luhn checksum (used for card numbers)."""
    digits = [int(c) for c in number if c.isdigit()]
    if len(digits) < 12:
        return False
    total = 0
    parity = len(digits) % 2
    for i, d in enumerate(digits):
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0
