"""
Financial-information detectors (heuristic + checksum).

Credit/debit card numbers are only flagged when they pass the Luhn checksum, so
an ordinary 16-digit numeric string is NOT treated as a card. IFSC codes (Indian
bank routing) are matched by format. Payment tokens (Stripe etc.) are already
handled by the secrets detector.
"""

from __future__ import annotations

import re

from .base import Category, SensitiveFinding, Severity, luhn_ok, redact_tail

# 13–19 digits, optionally separated by spaces/dashes.
_CARD = re.compile(r"(?<![\d])(?:\d[ -]?){12,18}\d(?![\d])")
_IFSC = re.compile(r"\b[A-Z]{4}0[A-Z0-9]{6}\b")


def detect_financial(text: str | None, location: str = "payload") -> list[SensitiveFinding]:
    if not text:
        return []
    out: list[SensitiveFinding] = []
    seen: set[tuple] = set()

    def add(f: SensitiveFinding) -> None:
        key = (f.subtype, f.fingerprint)
        if key not in seen:
            seen.add(key)
            out.append(f)

    for m in _CARD.finditer(text):
        raw = m.group(0)
        digits = re.sub(r"[ -]", "", raw)
        if 13 <= len(digits) <= 19 and luhn_ok(digits):
            add(SensitiveFinding(Category.FINANCIAL, "credit_card", Severity.HIGH, 0.9,
                                 redact_tail(digits), location))
    for m in _IFSC.finditer(text):
        add(SensitiveFinding(Category.FINANCIAL, "ifsc", Severity.MEDIUM, 0.65,
                             m.group(0)[:4] + "…", location))
    return out
