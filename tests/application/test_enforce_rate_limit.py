"""Tests for EnforceRateLimitUseCase — use case tests."""

from __future__ import annotations

import pytest

from sentinel.application.intercept.enforce_rate_limit import EnforceRateLimitUseCase
from sentinel.domain.entities.tool_call import ToolCall


def _make_tool_call(agent_id: str = "agent-1") -> ToolCall:
    return ToolCall(
        id="tc-1",
        agent_id=agent_id,
        server_name="server",
        tool_name="read_file",
        arguments={},
    )


@pytest.mark.asyncio
class TestEnforceRateLimitUseCase:
    async def test_allow_within_limit(self):
        use_case = EnforceRateLimitUseCase(max_calls=100, window_seconds=60)
        result = await use_case.execute(agent_id="agent-1", tool_call=_make_tool_call())
        assert result.allowed is True

    async def test_deny_exceeds_limit(self):
        use_case = EnforceRateLimitUseCase(max_calls=2, window_seconds=60)
        await use_case.execute(agent_id="agent-1", tool_call=_make_tool_call())
        await use_case.execute(agent_id="agent-1", tool_call=_make_tool_call())
        result = await use_case.execute(agent_id="agent-1", tool_call=_make_tool_call())
        assert result.allowed is False
