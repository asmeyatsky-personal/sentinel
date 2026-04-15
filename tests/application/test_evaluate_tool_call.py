"""Tests for EvaluateToolCallUseCase — use case tests with mocked ports."""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import AsyncMock

import pytest

from sentinel.application.detect.evaluate_tool_call import EvaluateToolCallUseCase
from sentinel.domain.entities.agent import Agent
from sentinel.domain.entities.tool_call import ToolCall
from sentinel.domain.value_objects.detection_score import DetectionScore
from sentinel.domain.value_objects.vaid import VAID


def _make_vaid() -> VAID:
    return VAID(
        agent_id="agent-1",
        issuer="kernel",
        capabilities=("read_file", "write_file"),
        issued_at=datetime(2026, 1, 1, tzinfo=UTC),
        expires_at=datetime(2027, 1, 1, tzinfo=UTC),
        signature="sig-123",
    )


def _make_agent() -> Agent:
    return Agent(
        id="agent-1",
        name="test-agent",
        vaid=_make_vaid(),
        framework="synthera",
        model_id="claude-opus-4-6",
        registered_tools=("read_file", "write_file"),
    )


def _make_tool_call(tool_name: str = "read_file") -> ToolCall:
    return ToolCall(
        id="tc-1",
        agent_id="agent-1",
        server_name="file-server",
        tool_name=tool_name,
        arguments={"path": "/data/test.txt"},
    )


@pytest.mark.asyncio
class TestEvaluateToolCallUseCase:
    async def test_safe_tool_call_returns_low_score(self):
        agent_repo = AsyncMock()
        agent_repo.get_by_id.return_value = _make_agent()
        rule_engine = AsyncMock()
        rule_engine.evaluate.return_value = DetectionScore(value=10.0)
        threat_repo = AsyncMock()
        event_bus = AsyncMock()

        use_case = EvaluateToolCallUseCase(
            rule_engine=rule_engine,
            agent_repository=agent_repo,
            threat_repository=threat_repo,
            event_bus=event_bus,
        )

        result = await use_case.execute(_make_tool_call())
        assert result.score <= 40.0
        assert not result.detected
        threat_repo.save.assert_not_awaited()

    async def test_dangerous_tool_call_creates_threat(self):
        agent_repo = AsyncMock()
        agent_repo.get_by_id.return_value = _make_agent()
        rule_engine = AsyncMock()
        rule_engine.evaluate.return_value = DetectionScore(value=85.0)
        threat_repo = AsyncMock()
        event_bus = AsyncMock()

        use_case = EvaluateToolCallUseCase(
            rule_engine=rule_engine,
            agent_repository=agent_repo,
            threat_repository=threat_repo,
            event_bus=event_bus,
        )

        result = await use_case.execute(_make_tool_call("delete_all"))
        assert result.score >= 70.0
        assert result.detected
        threat_repo.save.assert_awaited_once()

    async def test_unknown_agent_returns_critical(self):
        agent_repo = AsyncMock()
        agent_repo.get_by_id.return_value = None
        rule_engine = AsyncMock()
        threat_repo = AsyncMock()
        event_bus = AsyncMock()

        use_case = EvaluateToolCallUseCase(
            rule_engine=rule_engine,
            agent_repository=agent_repo,
            threat_repository=threat_repo,
            event_bus=event_bus,
        )

        result = await use_case.execute(_make_tool_call())
        assert result.score >= 90.0
        assert result.detected
        assert result.threat_level == "CRITICAL"
