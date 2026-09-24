"""Deterministic routing plus an optional SharedLLM planner."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass

import httpx

from .guardrails import EXPECTED_TOOLS, GuardrailError, sanitize_user_request
from .settings import Settings


@dataclass(frozen=True)
class ToolPlan:
    tool: str
    arguments: dict[str, object]


def deterministic_plan(request: str) -> ToolPlan:
    text = sanitize_user_request(request)
    lower = text.lower()

    update = re.search(
        r"(?:resolve|update)\s+(INC-\d{4})\s+(?:to\s+)?(open|investigating|resolved)",
        text,
        re.IGNORECASE,
    )
    if update:
        return ToolPlan(
            "update_incident_status",
            {
                "incident_id": update.group(1).upper(),
                "new_status": update.group(2).lower(),
                "reason": "Requested through the secure MCP client",
            },
        )

    for service in ("billing-api", "checkout-api", "reporting-api"):
        if service in lower:
            return ToolPlan("get_service_status", {"service": service})

    status = next(
        (value for value in ("open", "investigating", "resolved") if value in lower),
        "open",
    )
    return ToolPlan("query_incidents", {"status": status, "limit": 5})


def _parse_plan(raw: str) -> ToolPlan:
    cleaned = raw.strip()
    if cleaned.startswith("```"):
        cleaned = re.sub(r"^```(?:json)?\s*|\s*```$", "", cleaned, flags=re.I)
    try:
        value = json.loads(cleaned)
    except json.JSONDecodeError as exc:
        raise GuardrailError("SharedLLM returned a non-JSON tool plan") from exc
    tool = value.get("tool") if isinstance(value, dict) else None
    arguments = value.get("arguments") if isinstance(value, dict) else None
    if tool not in EXPECTED_TOOLS or not isinstance(arguments, dict):
        raise GuardrailError("SharedLLM returned an unapproved tool plan")
    return ToolPlan(str(tool), dict(arguments))


async def sharedllm_plan(request: str, settings: Settings) -> ToolPlan:
    """Use course credits only when explicitly selected by the caller."""
    text = sanitize_user_request(request)
    if not settings.sharedllm_api_key:
        raise GuardrailError("SHAREDLLM_API_KEY is required for --sharedllm")
    system = (
        "Return only JSON with keys tool and arguments. Allowed tools: "
        "query_incidents(status, limit), get_service_status(service), "
        "update_incident_status(incident_id, new_status, reason). "
        "Never include credentials or an approval token."
    )
    payload = {
        "model": settings.sharedllm_model,
        "temperature": 0,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": text},
        ],
    }
    headers = {
        "X-SharedLLM-Key": settings.sharedllm_api_key,
        "Content-Type": "application/json",
    }
    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.post(
            f"{settings.sharedllm_base_url}/chat/completions",
            headers=headers,
            json=payload,
        )
        response.raise_for_status()
    try:
        raw = response.json()["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError) as exc:
        raise GuardrailError("SharedLLM response did not contain a tool plan") from exc
    return _parse_plan(str(raw))

