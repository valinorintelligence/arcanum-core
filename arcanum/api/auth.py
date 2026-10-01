"""Token-based access control for the Arcanum API and WebSocket.

The API drives security tooling, so every data/action route requires a shared
secret. The token is read from (in order): the ``Authorization: Bearer`` header,
an ``X-Arcanum-Token`` header, or a ``token`` query parameter (needed for file
downloads and the WebSocket upgrade, which cannot set custom headers from the
browser). Comparison is constant-time.
"""
from __future__ import annotations

import secrets

from fastapi import HTTPException, Request, status


def extract_token(request: Request) -> str | None:
    """Pull the caller-supplied token from header or query string."""
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        return auth[len("Bearer "):].strip()
    hdr = request.headers.get("X-Arcanum-Token")
    if hdr:
        return hdr.strip()
    q = request.query_params.get("token")
    if q:
        return q.strip()
    return None


def token_valid(expected: str, provided: str | None) -> bool:
    """Constant-time token comparison. Empty expected token => auth disabled."""
    if not expected:
        return True
    if not provided:
        return False
    return secrets.compare_digest(provided, expected)


async def require_token(request: Request) -> None:
    """FastAPI dependency: 401 unless a valid token is supplied."""
    expected = getattr(request.app.state, "api_token", "") or ""
    if token_valid(expected, extract_token(request)):
        return
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Missing or invalid API token",
        headers={"WWW-Authenticate": "Bearer"},
    )
