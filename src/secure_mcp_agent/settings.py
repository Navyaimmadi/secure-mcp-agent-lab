"""Environment-backed configuration with no embedded credentials."""

from __future__ import annotations

import os
from dataclasses import dataclass

from dotenv import load_dotenv


load_dotenv()


@dataclass(frozen=True)
class Settings:
    jwt_secret: str
    approval_secret: str
    issuer: str
    audience: str
    server_url: str
    host: str
    port: int
    sharedllm_base_url: str
    sharedllm_model: str
    sharedllm_api_key: str | None

    @classmethod
    def from_env(cls) -> "Settings":
        jwt_secret = os.getenv(
            "MCP_JWT_SECRET", ""
        )
        approval_secret = os.getenv(
            "MCP_APPROVAL_SECRET", ""
        )
        if len(jwt_secret) < 32 or len(approval_secret) < 32:
            raise ValueError(
                "MCP_JWT_SECRET and MCP_APPROVAL_SECRET must each contain at least "
                "32 characters; configure them in .env"
            )
        if jwt_secret == approval_secret:
            raise ValueError("JWT and approval secrets must be different")
        return cls(
            jwt_secret=jwt_secret,
            approval_secret=approval_secret,
            issuer=os.getenv("MCP_JWT_ISSUER", "secure-mcp-lab-auth"),
            audience=os.getenv("MCP_JWT_AUDIENCE", "secure-mcp-lab-server"),
            server_url=os.getenv("MCP_SERVER_URL", "http://127.0.0.1:8000/mcp"),
            host=os.getenv("MCP_HOST", "127.0.0.1"),
            port=int(os.getenv("MCP_PORT", "8000")),
            sharedllm_base_url=os.getenv(
                "SHAREDLLM_BASE_URL", "https://api.sharedllm.com/openai/v1"
            ).rstrip("/"),
            sharedllm_model=os.getenv("SHAREDLLM_MODEL", "kimi-k2.7-code"),
            sharedllm_api_key=os.getenv("SHAREDLLM_API_KEY") or None,
        )
