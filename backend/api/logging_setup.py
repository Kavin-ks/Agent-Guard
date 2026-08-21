"""
Logging hardening (Phase 8).

A logging filter that scrubs any secret-looking substrings from formatted log
records — defense in depth so that even an accidental ``logger.info(payload)``
cannot leak a credential. Detection reuses the deterministic secret detector; the
matched value is replaced with its redacted fingerprint.
"""

from __future__ import annotations

import logging

from agentguard.detectors.secrets import detect_secrets


class RedactionFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        try:
            msg = record.getMessage()
        except Exception:
            return True
        findings = detect_secrets(msg)
        if not findings:
            return True
        # We cannot recover the raw substrings from fingerprints, so redact by
        # re-scanning: replace the detector's raw matches with a marker.
        redacted = msg
        for raw in _raw_matches(msg):
            redacted = redacted.replace(raw, "«redacted-secret»")
        record.msg = redacted
        record.args = ()
        return True


def _raw_matches(text: str) -> list[str]:
    """Return the raw substrings the secret detector matched (local use only)."""
    from agentguard.detectors.secrets import (
        _ASSIGNMENT_PATTERN,
        _CANDIDATE_TOKEN,
        _NAMED_PATTERNS,
        _shannon_entropy,
    )

    out: list[str] = []
    for _, pat in _NAMED_PATTERNS:
        out.extend(m.group(0) for m in pat.finditer(text))
    for m in _ASSIGNMENT_PATTERN.finditer(text):
        out.append(m.group("value"))
    for m in _CANDIDATE_TOKEN.finditer(text):
        if _shannon_entropy(m.group(0)) >= 4.0:
            out.append(m.group(0))
    # Longest first so nested matches redact cleanly.
    return sorted(set(out), key=len, reverse=True)


def configure_logging(level: str = "INFO") -> None:
    root = logging.getLogger()
    if not any(isinstance(f, RedactionFilter) for f in root.filters):
        root.addFilter(RedactionFilter())
    # Also attach to existing handlers so formatted output is filtered.
    redaction = RedactionFilter()
    for handler in root.handlers:
        if not any(isinstance(f, RedactionFilter) for f in handler.filters):
            handler.addFilter(redaction)
    root.setLevel(level.upper())
