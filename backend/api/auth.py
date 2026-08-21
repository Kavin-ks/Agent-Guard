"""
Prototype API-key authentication.

A protected route depends on ``require_api_key``. The client sends the key in the
``X-API-Key`` header. Comparison is constant-time. The key is only ever read from
configuration (env), never logged, and never echoed in a response.

Fail-closed: if no key is configured on the server, every protected request is
rejected (401) rather than served unauthenticated.
"""

from __future__ import annotations

import hmac

from fastapi import Depends, Header, HTTPException, status

from .config import Settings, get_settings

API_KEY_HEADER = "X-API-Key"


def require_api_key(
    x_api_key: str | None = Header(default=None, alias=API_KEY_HEADER),
    settings: Settings = Depends(get_settings),
) -> None:
    expected = settings.api_key
    if not expected:
        # Misconfiguration -> refuse rather than run open.
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Server auth is not configured.",
        )
    if not x_api_key or not hmac.compare_digest(x_api_key, expected):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API key.",
            headers={"WWW-Authenticate": API_KEY_HEADER},
        )
