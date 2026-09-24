from __future__ import annotations

import time

import jwt
import pytest

from secure_mcp_agent.auth import issue_access_token
from secure_mcp_agent.settings import Settings


def settings() -> Settings:
    return Settings(
        jwt_secret="jwt-test-secret-that-is-at-least-32-characters",
        approval_secret="approval-test-secret-that-is-different-12345",
        issuer="test-issuer",
        audience="test-audience",
        server_url="http://127.0.0.1:8000/mcp",
        host="127.0.0.1",
        port=8000,
        sharedllm_base_url="https://api.sharedllm.com/openai/v1",
        sharedllm_model="kimi-k2.7-code",
        sharedllm_api_key=None,
    )


def test_access_token_has_audience_expiry_and_scopes() -> None:
    cfg = settings()
    token = issue_access_token(cfg, ttl_seconds=60)
    claims = jwt.decode(
        token,
        cfg.jwt_secret,
        algorithms=["HS256"],
        audience=cfg.audience,
        issuer=cfg.issuer,
    )
    assert claims["aud"] == cfg.audience
    assert claims["exp"] > time.time()
    assert "mcp:access" in claims["scope"].split()


def test_wrong_audience_is_rejected() -> None:
    cfg = settings()
    token = issue_access_token(cfg)
    with pytest.raises(jwt.InvalidAudienceError):
        jwt.decode(
            token,
            cfg.jwt_secret,
            algorithms=["HS256"],
            audience="other-server",
            issuer=cfg.issuer,
        )
