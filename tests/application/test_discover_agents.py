"""Tests for DiscoverAgentsUseCase — use case tests with mocked ports."""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import AsyncMock

import pytest

from sentinel.application.recon.discover_agents import DiscoverAgentsUseCase
from sentinel.domain.entities.agent import Agent
from sentinel.domain.value_objects.vaid import VAID


def _make_agents(count: int = 3) -> list[Agent]:
    return [
        Agent(
            id=f"agent-{i}",
            name=f"agent-{i}",
            vaid=VAID(
                agent_id=f"agent-{i}",
                issuer="kernel",
                capabilities=(f"cap-{i}",),
                issued_at=datetime(2026, 1, 1, tzinfo=UTC),
                expires_at=datetime(2027, 1, 1, tzinfo=UTC),
                signature=f"sig-{i}",
            ),
            framework="synthera",
            model_id="claude-opus-4-6",
            registered_tools=(f"tool-{i}",),
        )
        for i in range(count)
    ]


@pytest.mark.asyncio
class TestDiscoverAgentsUseCase:
    async def test_discover_returns_all_agents(self):
        agent_repo = AsyncMock()
        agent_repo.get_all.return_value = _make_agents(3)
        event_bus = AsyncMock()

        use_case = DiscoverAgentsUseCase(agent_repository=agent_repo, event_bus=event_bus)
        result = await use_case.execute()

        assert len(result) == 3
        assert result[0].id == "agent-0"

    async def test_discover_empty_estate(self):
        agent_repo = AsyncMock()
        agent_repo.get_all.return_value = []
        event_bus = AsyncMock()

        use_case = DiscoverAgentsUseCase(agent_repository=agent_repo, event_bus=event_bus)
        result = await use_case.execute()

        assert len(result) == 0
