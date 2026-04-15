"""Tests for IsolateAgentUseCase — use case tests with mocked ports."""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import AsyncMock

import pytest

from sentinel.application.contain.isolate_agent import IsolateAgentUseCase
from sentinel.domain.entities.agent import Agent, AgentStatus
from sentinel.domain.value_objects.vaid import VAID


def _make_agent(status: AgentStatus = AgentStatus.ACTIVE) -> Agent:
    return Agent(
        id="agent-1",
        name="test-agent",
        vaid=VAID(
            agent_id="agent-1",
            issuer="kernel",
            capabilities=("read",),
            issued_at=datetime(2026, 1, 1, tzinfo=UTC),
            expires_at=datetime(2027, 1, 1, tzinfo=UTC),
            signature="sig",
        ),
        framework="synthera",
        model_id="claude-opus-4-6",
        registered_tools=("read",),
        status=status,
    )


@pytest.mark.asyncio
class TestIsolateAgentUseCase:
    async def test_isolate_active_agent(self):
        agent_repo = AsyncMock()
        agent_repo.get_by_id.return_value = _make_agent()
        event_bus = AsyncMock()

        use_case = IsolateAgentUseCase(agent_repository=agent_repo, event_bus=event_bus)
        result = await use_case.execute(agent_id="agent-1", reason="threat detected")

        assert result.status == "ISOLATED"
        agent_repo.save.assert_awaited_once()
        saved_agent = agent_repo.save.call_args[0][0]
        assert saved_agent.status is AgentStatus.ISOLATED

    async def test_isolate_nonexistent_agent_raises(self):
        agent_repo = AsyncMock()
        agent_repo.get_by_id.return_value = None
        event_bus = AsyncMock()

        use_case = IsolateAgentUseCase(agent_repository=agent_repo, event_bus=event_bus)
        with pytest.raises(ValueError, match="not found"):
            await use_case.execute(agent_id="unknown", reason="test")
        agent_repo.save.assert_not_awaited()

    async def test_isolate_already_terminated_raises(self):
        agent_repo = AsyncMock()
        agent_repo.get_by_id.return_value = _make_agent(status=AgentStatus.TERMINATED)
        event_bus = AsyncMock()

        use_case = IsolateAgentUseCase(agent_repository=agent_repo, event_bus=event_bus)
        with pytest.raises(ValueError):
            await use_case.execute(agent_id="agent-1", reason="test")
