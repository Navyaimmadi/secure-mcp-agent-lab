"""Human-approval tokens bound to one exact sensitive action."""

from __future__ import annotations

import hashlib
import json
import time
import uuid
from collections.abc import Mapping

import jwt


class ApprovalError(ValueError):
    """Raised when an approval is absent, invalid, expired, mismatched, or reused."""


_used_nonces: set[str] = set()


def action_digest(tool_name: str, arguments: Mapping[str, object]) -> str:
    payload = {"tool": tool_name, "arguments": dict(arguments)}
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def issue_approval_token(
    secret: str,
    *,
    tool_name: str,
    arguments: Mapping[str, object],
    approved_by: str = "local-human-reviewer",
    ttl_seconds: int = 90,
) -> str:
    now = int(time.time())
    claims = {
        "iss": "secure-mcp-approval-gate",
        "aud": "secure-mcp-sensitive-tools",
        "sub": approved_by,
        "iat": now,
        "exp": now + ttl_seconds,
        "nonce": str(uuid.uuid4()),
        "tool": tool_name,
        "action_digest": action_digest(tool_name, arguments),
    }
    return jwt.encode(claims, secret, algorithm="HS256")


def verify_approval_token(
    token: str,
    secret: str,
    *,
    tool_name: str,
    arguments: Mapping[str, object],
) -> str:
    try:
        claims = jwt.decode(
            token,
            secret,
            algorithms=["HS256"],
            issuer="secure-mcp-approval-gate",
            audience="secure-mcp-sensitive-tools",
        )
    except jwt.PyJWTError as exc:
        raise ApprovalError("Approval token is invalid or expired") from exc

    expected_digest = action_digest(tool_name, arguments)
    if claims.get("tool") != tool_name or claims.get("action_digest") != expected_digest:
        raise ApprovalError("Approval token does not match this exact action")

    nonce = str(claims.get("nonce", ""))
    if not nonce or nonce in _used_nonces:
        raise ApprovalError("Approval token has already been used")
    _used_nonces.add(nonce)
    return str(claims.get("sub", "unknown-approver"))


def reset_used_approvals() -> None:
    """Test helper; a production implementation would use a durable nonce store."""
    _used_nonces.clear()

