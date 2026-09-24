"""Authenticated MCP client with guarded routing and human approval."""

from __future__ import annotations

import argparse
import asyncio
import json
from typing import Any
from urllib.parse import urlparse

import httpx2
from fastmcp import Client
from fastmcp.client.transports import StreamableHttpTransport

from .approval import issue_approval_token
from .auth import issue_access_token
from .guardrails import validate_tool_catalog
from .router import ToolPlan, deterministic_plan, sharedllm_plan
from .settings import Settings


def _json(value: Any) -> str:
    if hasattr(value, "model_dump"):
        value = value.model_dump(mode="json")
    return json.dumps(value, indent=2, default=str)


def _client(settings: Settings, access_token: str) -> Client:
    """Build an HTTP client; localhost must never be sent through a proxy."""
    hostname = urlparse(settings.server_url).hostname
    factory = None
    if hostname in {"127.0.0.1", "localhost", "::1"}:
        def local_http_client(**kwargs: Any) -> httpx2.AsyncClient:
            kwargs["trust_env"] = False
            return httpx2.AsyncClient(**kwargs)

        factory = local_http_client
    transport = StreamableHttpTransport(
        settings.server_url,
        auth=access_token,
        httpx_client_factory=factory,
    )
    return Client(transport, timeout=15.0)


def _approval_prompt(plan: ToolPlan, settings: Settings) -> ToolPlan:
    print("\nSENSITIVE ACTION REQUIRES HUMAN APPROVAL")
    print(_json({"tool": plan.tool, "arguments": plan.arguments}))
    answer = input("Approve this exact action? Type yes to continue: ").strip().lower()
    if answer != "yes":
        raise PermissionError("Human reviewer declined the action")
    approval_token = issue_approval_token(
        settings.approval_secret,
        tool_name=plan.tool,
        arguments=plan.arguments,
    )
    return ToolPlan(plan.tool, {**plan.arguments, "approval_token": approval_token})


async def execute_request(request: str, *, use_sharedllm: bool = False) -> object:
    settings = Settings.from_env()
    plan = (
        await sharedllm_plan(request, settings)
        if use_sharedllm
        else deterministic_plan(request)
    )
    if plan.tool == "update_incident_status":
        plan = _approval_prompt(plan, settings)

    access_token = issue_access_token(settings)
    async with _client(settings, access_token) as client:
        tools = await client.list_tools()
        validate_tool_catalog(tools)
        result = await client.call_tool(plan.tool, plan.arguments)
        return result.data


async def run_demo() -> None:
    settings = Settings.from_env()
    access_token = issue_access_token(settings)
    async with _client(settings, access_token) as client:
        tools = await client.list_tools()
        validate_tool_catalog(tools)
        print("=== AUTHENTICATED DISCOVERY ===")
        print("Tools:", [tool.name for tool in tools])

        print("\n=== DATABASE QUERY TOOL ===")
        incidents = await client.call_tool("query_incidents", {"status": "open", "limit": 5})
        print(_json(incidents.data))

        print("\n=== INTERNAL API TOOL ===")
        service = await client.call_tool("get_service_status", {"service": "checkout-api"})
        print(_json(service.data))

        print("\n=== SECURITY CONTROLS ===")
        print("JWT authentication: passed")
        print("Tool-catalog allowlist and metadata scan: passed")
        print("Sensitive writes require a separate, exact-action approval token")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("request", nargs="?", help="Natural-language request to route")
    parser.add_argument("--demo", action="store_true", help="Run non-destructive reviewer demo")
    parser.add_argument(
        "--sharedllm",
        action="store_true",
        help="Use optional SharedLLM planning instead of deterministic routing",
    )
    args = parser.parse_args()
    if args.demo:
        asyncio.run(run_demo())
        return
    if not args.request:
        parser.error("provide a request or use --demo")
    result = asyncio.run(execute_request(args.request, use_sharedllm=args.sharedllm))
    print(_json(result))


if __name__ == "__main__":
    main()
