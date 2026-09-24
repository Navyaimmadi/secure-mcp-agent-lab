"""Input and tool-catalog defenses applied before any tool call."""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Iterable
from typing import Any


class GuardrailError(ValueError):
    """Safe, user-facing guardrail failure."""


MAX_REQUEST_LENGTH = 500
EXPECTED_TOOLS = {
    "query_incidents",
    "get_service_status",
    "update_incident_status",
}

_INJECTION_PATTERNS = [
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        r"ignore\s+(all\s+)?(previous|prior|system|developer)\s+instructions?",
        r"reveal\s+(the\s+)?(system|developer)\s+(prompt|message)",
        r"bypass\s+(the\s+)?(guardrail|approval|security|policy)",
        r"act\s+as\s+(an?\s+)?unrestricted",
        r"execute\s+(this\s+)?hidden\s+(tool|command)",
    )
]


def sanitize_user_request(value: str) -> str:
    """Normalize input, reject control characters, length abuse, and injection text."""
    if not isinstance(value, str):
        raise GuardrailError("Request must be text")
    normalized = unicodedata.normalize("NFKC", value).strip()
    if not normalized:
        raise GuardrailError("Request cannot be empty")
    if len(normalized) > MAX_REQUEST_LENGTH:
        raise GuardrailError(f"Request exceeds {MAX_REQUEST_LENGTH} characters")
    if any(unicodedata.category(ch) == "Cc" and ch not in "\n\t" for ch in normalized):
        raise GuardrailError("Request contains forbidden control characters")
    if any(pattern.search(normalized) for pattern in _INJECTION_PATTERNS):
        raise GuardrailError("Request was blocked as a prompt-injection attempt")
    return normalized


def validate_tool_catalog(tools: Iterable[Any]) -> None:
    """Reject unknown, missing, duplicated, or suspicious MCP tool metadata."""
    seen: set[str] = set()
    suspicious = ("ignore previous", "bypass approval", "reveal secret", "hidden command")
    for tool in tools:
        name = str(getattr(tool, "name", ""))
        description = str(getattr(tool, "description", "")).lower()
        if not name or name in seen:
            raise GuardrailError("Tool catalog contains a missing or duplicate name")
        if name not in EXPECTED_TOOLS:
            raise GuardrailError(f"Unapproved tool advertised by server: {name}")
        if any(phrase in description for phrase in suspicious):
            raise GuardrailError(f"Suspicious metadata detected for tool: {name}")
        seen.add(name)
    if seen != EXPECTED_TOOLS:
        missing = ", ".join(sorted(EXPECTED_TOOLS - seen))
        raise GuardrailError(f"Expected tool missing from server catalog: {missing}")

