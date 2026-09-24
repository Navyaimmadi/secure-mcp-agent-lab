from __future__ import annotations

import pytest

from secure_mcp_agent.approval import (
    ApprovalError,
    issue_approval_token,
    reset_used_approvals,
    verify_approval_token,
)


SECRET = "approval-test-secret-that-is-long-enough-123"
ACTION = {
    "incident_id": "INC-1001",
    "new_status": "resolved",
    "reason": "Approved during the security test",
}


def setup_function() -> None:
    reset_used_approvals()


def test_approval_is_bound_to_exact_arguments() -> None:
    token = issue_approval_token(
        SECRET, tool_name="update_incident_status", arguments=ACTION
    )
    changed = {**ACTION, "incident_id": "INC-1002"}
    with pytest.raises(ApprovalError, match="exact action"):
        verify_approval_token(
            token,
            SECRET,
            tool_name="update_incident_status",
            arguments=changed,
        )


def test_approval_is_single_use() -> None:
    token = issue_approval_token(
        SECRET, tool_name="update_incident_status", arguments=ACTION
    )
    verify_approval_token(
        token, SECRET, tool_name="update_incident_status", arguments=ACTION
    )
    with pytest.raises(ApprovalError, match="already been used"):
        verify_approval_token(
            token, SECRET, tool_name="update_incident_status", arguments=ACTION
        )

