"""Start the server, run the real authenticated demo, and stop cleanly."""

from __future__ import annotations

import asyncio
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

from fastmcp.exceptions import ToolError


ROOT = Path(__file__).resolve().parents[1]
HOST = "127.0.0.1"
PORT = 8765


def wait_for_port(timeout: float = 20.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        with socket.socket() as sock:
            sock.settimeout(0.25)
            if sock.connect_ex((HOST, PORT)) == 0:
                return
        time.sleep(0.1)
    raise RuntimeError("MCP server did not start before the timeout")


def main() -> None:
    env = os.environ.copy()
    env.update(
        {
            "MCP_HOST": HOST,
            "MCP_PORT": str(PORT),
            "MCP_SERVER_URL": f"http://{HOST}:{PORT}/mcp",
            "NO_PROXY": "127.0.0.1,localhost",
            "no_proxy": "127.0.0.1,localhost",
        }
    )
    os.environ.update(env)
    process = subprocess.Popen(
        [sys.executable, "server.py"],
        cwd=ROOT,
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        wait_for_port()
        from secure_mcp_agent.approval import issue_approval_token
        from secure_mcp_agent.auth import issue_access_token
        from secure_mcp_agent.client import _client, run_demo
        from secure_mcp_agent.settings import Settings

        async def security_evidence() -> None:
            settings = Settings.from_env()
            print("=== AUTHENTICATION FAILURE CHECK ===")
            try:
                async with _client(settings, "not-a-valid-jwt") as invalid_client:
                    await invalid_client.list_tools()
            except Exception:
                print("Invalid JWT: rejected by server")
            else:
                raise AssertionError("Invalid JWT unexpectedly succeeded")

            await run_demo()

            action = {
                "incident_id": "INC-1001",
                "new_status": "resolved",
                "reason": "Approved during the live security demonstration",
            }
            access_token = issue_access_token(settings)
            async with _client(settings, access_token) as client:
                print("\n=== SENSITIVE TOOL APPROVAL CHECK ===")
                try:
                    await client.call_tool(
                        "update_incident_status",
                        {**action, "approval_token": "invalid-approval-token-value"},
                    )
                except ToolError:
                    print("Mismatched approval: rejected by server")
                else:
                    raise AssertionError("Invalid approval unexpectedly succeeded")

                approval = issue_approval_token(
                    settings.approval_secret,
                    tool_name="update_incident_status",
                    arguments=action,
                    approved_by="live-demo-reviewer",
                )
                result = await client.call_tool(
                    "update_incident_status",
                    {**action, "approval_token": approval},
                )
                print("Exact-action approval: accepted")
                print(
                    f"Status change: {result.data['previous_status']} -> "
                    f"{result.data['new_status']}"
                )

        asyncio.run(security_evidence())
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


if __name__ == "__main__":
    main()
