"""Tests for DetectCoordinationAnomalyUseCase — use case tests with mocked ports."""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import AsyncMock

import pytest

from sentinel.application.detect.detect_coordination_anomaly import (
    DetectCoordinationAnomalyUseCase,
)
from sentinel.domain.entities.tool_call import ToolCall


def _make_tool_call(
    agent_id: str,
    tool_name: str = "some_tool",
    server_name: str = "server-1",
    response: dict | None = None,
) -> ToolCall:
    return ToolCall(
        id=f"tc-{agent_id}-{tool_name}",
        agent_id=agent_id,
        server_name=server_name,
        tool_name=tool_name,
        arguments={},
        response=response,
        latency_ms=50.0,
        timestamp=datetime(2026, 4, 1, tzinfo=UTC),
    )


@pytest.mark.asyncio
class TestDetectCoordinationAnomalyUseCase:
    async def test_no_anomaly_with_normal_calls(self) -> None:
        tool_call_repo = AsyncMock()
        threat_repo = AsyncMock()
        event_bus = AsyncMock()

        # Regular tool calls with no delegation indicators
        normal_calls = [
            _make_tool_call("agent-a", tool_name=f"tool-{i}")
            for i in range(5)
        ]
        tool_call_repo.get_by_agent_id.return_value = normal_calls
        tool_call_repo.get_recent.return_value = normal_calls

        use_case = DetectCoordinationAnomalyUseCase(
            tool_call_repository=tool_call_repo,
            threat_repository=threat_repo,
            event_bus=event_bus,
        )

        result = await use_case.execute("agent-a")

        assert result.detected is False
        assert result.score == 0.0
        threat_repo.save.assert_not_awaited()

    async def test_circular_delegation_detected(self) -> None:
        tool_call_repo = AsyncMock()
        threat_repo = AsyncMock()
        event_bus = AsyncMock()

        # Agent A calls agent B (via response metadata)
        calls_by_a = [
            _make_tool_call(
                "agent-a",
                tool_name="delegate",
                response={"agent_id": "agent-b", "result": "ok"},
            ),
        ]

        # Agent B calls agent A back (circular)
        call_by_b = _make_tool_call(
            "agent-b",
            tool_name="delegate",
            response={"agent_id": "agent-a", "result": "ok"},
        )

        tool_call_repo.get_by_agent_id.return_value = calls_by_a
        tool_call_repo.get_recent.return_value = calls_by_a + [call_by_b]

        use_case = DetectCoordinationAnomalyUseCase(
            tool_call_repository=tool_call_repo,
            threat_repository=threat_repo,
            event_bus=event_bus,
        )

        result = await use_case.execute("agent-a")

        assert result.detected is True
        assert result.score > 0.0
        assert result.category == "COORDINATION_ANOMALY"
        threat_repo.save.assert_awaited_once()
