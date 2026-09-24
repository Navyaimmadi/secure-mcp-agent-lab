from secure_mcp_agent.router import deterministic_plan


def test_router_selects_read_tool() -> None:
    plan = deterministic_plan("Show open incidents")
    assert plan.tool == "query_incidents"
    assert plan.arguments["status"] == "open"


def test_router_selects_sensitive_tool_without_forging_approval() -> None:
    plan = deterministic_plan("Resolve INC-1001 to resolved")
    assert plan.tool == "update_incident_status"
    assert "approval_token" not in plan.arguments

