"""Authenticated FastMCP server exposing synthetic incident operations."""

from __future__ import annotations

import re
from typing import Annotated, Literal

from fastmcp import FastMCP
from fastmcp.server.auth.providers.jwt import JWTVerifier
from fastmcp.server.dependencies import get_access_token
from pydantic import Field

from .approval import ApprovalError, verify_approval_token
from .data import INCIDENTS, SERVICE_STATUS
from .guardrails import sanitize_user_request
from .settings import Settings


settings = Settings.from_env()
verifier = JWTVerifier(
    public_key=settings.jwt_secret,
    issuer=settings.issuer,
    audience=settings.audience,
    algorithm="HS256",
    required_scopes=["mcp:access"],
)
mcp = FastMCP("Secure Incident Agent", auth=verifier)


def _require_scope(scope: str) -> str:
    token = get_access_token()
    if token is None or scope not in token.scopes:
        raise PermissionError(f"Missing required scope: {scope}")
    return token.subject or token.client_id


@mcp.tool
def query_incidents(
    status: Literal["open", "investigating", "resolved"] = "open",
    limit: Annotated[int, Field(ge=1, le=10)] = 5,
) -> dict[str, object]:
    """Return synthetic incidents matching one allowlisted status; this tool is read-only."""
    _require_scope("incidents:read")
    records = [dict(item) for item in INCIDENTS.values() if item["status"] == status]
    return {"status": status, "count": min(len(records), limit), "incidents": records[:limit]}


@mcp.tool
def get_service_status(
    service: Literal["billing-api", "checkout-api", "reporting-api"],
) -> dict[str, object]:
    """Call the synthetic internal service-status API using an allowlisted service name."""
    _require_scope("incidents:read")
    return {"service": service, **SERVICE_STATUS[service]}


@mcp.tool
def update_incident_status(
    incident_id: Annotated[str, Field(pattern=r"^INC-\d{4}$")],
    new_status: Literal["open", "investigating", "resolved"],
    reason: Annotated[str, Field(min_length=5, max_length=200)],
    approval_token: Annotated[str, Field(min_length=20, max_length=2000)],
) -> dict[str, object]:
    """Sensitive write: update one incident only after exact, signed human approval."""
    actor = _require_scope("incidents:write")
    normalized_reason = sanitize_user_request(reason)
    incident_id = incident_id.upper()
    if not re.fullmatch(r"INC-\d{4}", incident_id) or incident_id not in INCIDENTS:
        raise ValueError("Incident not found")
    action = {
        "incident_id": incident_id,
        "new_status": new_status,
        "reason": normalized_reason,
    }
    try:
        approved_by = verify_approval_token(
            approval_token,
            settings.approval_secret,
            tool_name="update_incident_status",
            arguments=action,
        )
    except ApprovalError as exc:
        raise PermissionError(str(exc)) from exc
    previous = str(INCIDENTS[incident_id]["status"])
    INCIDENTS[incident_id]["status"] = new_status
    return {
        "incident_id": incident_id,
        "previous_status": previous,
        "new_status": new_status,
        "reason": normalized_reason,
        "actor": actor,
        "approved_by": approved_by,
    }


def main() -> None:
    mcp.run(transport="http", host=settings.host, port=settings.port, path="/mcp")


if __name__ == "__main__":
    main()
