"""Short-lived signed access tokens for the lab's internal client."""

from __future__ import annotations

import time
import uuid

import jwt

from .settings import Settings


def issue_access_token(
    settings: Settings,
    *,
    subject: str = "course-reviewer",
    scopes: tuple[str, ...] = ("mcp:access", "incidents:read", "incidents:write"),
    ttl_seconds: int = 300,
) -> str:
    """Create a short-lived, audience-bound JWT for local demonstration."""
    now = int(time.time())
    claims = {
        "iss": settings.issuer,
        "aud": settings.audience,
        "sub": subject,
        "client_id": subject,
        "iat": now,
        "exp": now + ttl_seconds,
        "jti": str(uuid.uuid4()),
        "scope": " ".join(scopes),
    }
    return jwt.encode(claims, settings.jwt_secret, algorithm="HS256")
