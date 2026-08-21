"""
Personal-information detectors (heuristic).

Covers email, phone, and India-specific government IDs (Aadhaar with Verhoeff
checksum, PAN). Government-ID detectors use checksum/format validation to keep
false positives low — a random 12-digit number is NOT flagged as Aadhaar unless
it passes the Verhoeff check.

These are heuristics, not perfect identifiers.
"""

from __future__ import annotations

import re

from .base import Category, SensitiveFinding, Severity, redact, redact_tail

_EMAIL = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")
# International (+countrycode…) or Indian mobile (10 digits starting 6-9). The
# strict shapes avoid flagging ordinary numeric strings as phone numbers.
_PHONE_INTL = re.compile(r"\+\d[\d\s\-]{7,15}\d")
_PHONE_IN = re.compile(r"(?<!\d)[6-9]\d{9}(?!\d)")
_AADHAAR = re.compile(r"(?<!\d)\d{4}\s?\d{4}\s?\d{4}(?!\d)")
_PAN = re.compile(r"\b[A-Z]{5}[0-9]{4}[A-Z]\b")

# --- Verhoeff checksum (used by Aadhaar) ---
_D = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6], [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8], [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2], [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4], [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
]
_P = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2], [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0], [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5], [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
]


def verhoeff_valid(number: str) -> bool:
    digits = [int(c) for c in number if c.isdigit()]
    if len(digits) != 12:
        return False
    c = 0
    for i, d in enumerate(reversed(digits)):
        c = _D[c][_P[i % 8][d]]
    return c == 0


def detect_pii(text: str | None, location: str = "payload") -> list[SensitiveFinding]:
    if not text:
        return []
    out: list[SensitiveFinding] = []
    seen: set[tuple] = set()

    def add(f: SensitiveFinding) -> None:
        key = (f.subtype, f.fingerprint)
        if key not in seen:
            seen.add(key)
            out.append(f)

    for m in _EMAIL.finditer(text):
        add(SensitiveFinding(Category.PII, "email", Severity.MEDIUM, 0.7,
                             redact(m.group(0)), location))
    for m in _PHONE_INTL.finditer(text):
        add(SensitiveFinding(Category.PII, "phone", Severity.MEDIUM, 0.55,
                             redact_tail(m.group(0)), location))
    for m in _PHONE_IN.finditer(text):
        add(SensitiveFinding(Category.PII, "phone", Severity.MEDIUM, 0.55,
                             redact_tail(m.group(0)), location))
    for m in _AADHAAR.finditer(text):
        if verhoeff_valid(m.group(0)):
            add(SensitiveFinding(Category.PII, "aadhaar", Severity.HIGH, 0.85,
                                 redact_tail(m.group(0)), location))
    for m in _PAN.finditer(text):
        add(SensitiveFinding(Category.PII, "pan", Severity.HIGH, 0.8,
                             redact(m.group(0)), location))
    return out
