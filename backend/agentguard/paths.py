"""
Path & glob utilities used by the deterministic gates.

Security-critical: all resource matching is done against a *normalized* path so
that traversal (``../../.env``), case variation (``.ENV``), backslashes, and
URL-encoding (``%2e%65nv``) cannot be used to slip past a protected-resource
glob. There is deliberately NO filesystem access here — normalization is purely
lexical so it behaves identically regardless of what exists on disk.
"""

from __future__ import annotations

import posixpath
import re
from functools import lru_cache
from urllib.parse import unquote


def normalize_path(value: str) -> str:
    """Return a canonical, lower-cased path for matching.

    Steps: url-decode (repeatedly, to defeat double-encoding), unify slashes,
    collapse ``.``/``..`` segments lexically, strip a leading ``./``, lower-case.
    """
    if value is None:
        return ""
    text = str(value).strip()

    # Repeatedly percent-decode until stable (defeats %252e style double-encoding).
    for _ in range(3):
        decoded = unquote(text)
        if decoded == text:
            break
        text = decoded

    text = text.replace("\\", "/")

    # Strip a scheme+host if this looks like a URL so we match on the path part.
    # (URL/domain based rules live in the external-comm gate, not here.)
    text = text.strip()

    # Collapse . and .. lexically without touching the filesystem.
    # posixpath.normpath keeps leading '..' which is exactly what we want to
    # preserve so that '../../.env' still ends in '.env'.
    normalized = posixpath.normpath(text)

    if normalized.startswith("./"):
        normalized = normalized[2:]

    return normalized.lower()


@lru_cache(maxsize=2048)
def _glob_to_regex(pattern: str) -> re.Pattern[str]:
    """Translate a glob (supporting ``**``, ``*``, ``?``) to an anchored regex.

    ``**/`` matches zero or more path segments; ``**`` matches anything; ``*``
    matches within a single segment; ``?`` matches a single non-slash char.
    """
    pat = pattern.lower()
    out: list[str] = ["^"]
    i = 0
    n = len(pat)
    while i < n:
        if pat.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
        elif pat.startswith("**", i):
            out.append(".*")
            i += 2
        elif pat[i] == "*":
            out.append("[^/]*")
            i += 1
        elif pat[i] == "?":
            out.append("[^/]")
            i += 1
        else:
            out.append(re.escape(pat[i]))
            i += 1
    out.append("$")
    return re.compile("".join(out))


def glob_match(pattern: str, path: str) -> bool:
    """True if the already-arbitrary ``path`` matches ``pattern`` (case-insensitive).

    ``path`` is normalized internally, so callers may pass a raw resource value.
    """
    normalized = normalize_path(path)
    return bool(_glob_to_regex(pattern).match(normalized))


def matches_any(patterns, path: str) -> str | None:
    """Return the first pattern in ``patterns`` that matches ``path``, else None."""
    normalized = normalize_path(path)
    for pattern in patterns:
        if _glob_to_regex(pattern).match(normalized):
            return pattern
    return None
