"""Tests for ContainBlastRadiusUseCase."""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import AsyncMock

import pytest

from sentinel.application.contain.contain_blast_radius import (
    ContainBlastRadiusUseCase,
)
from sentinel.domain.entities.agent import Agent, AgentStatus
from sentinel.domain.entities.incident import Incident, IncidentStatus
from sentinel.domain.entities.tool_call import ToolCall
from sentinel.domain.value_objects.threat_level import ThreatLevel
from sentinel.domain.value_objects.vaid import VAID


def _make_agent(agent_id: str) -> Agent:
    return Agent(
        id=agent_id,
        name=f"agent-{agent_id}",
        vaid=VAID(
            agent_id=agent_id,
            issuer="kernel",
            capabilities=("read",),
            issued_at=datetime(2026, 1, 1, tzinfo=UTC),
            expires_at=datetime(2027, 1, 1, tzinfo=UTC),
            signature="sig",
        ),
        framework="synthera",
        model_id="claude-opus-4-6",
        registered_tools=("read",),
        status=AgentStatus.ACTIVE,
    )


def _make_tool_call(agent_id: str, server_name: str) -> ToolCall:
    return ToolCall(
        id=f"tc-{agent_id}-{server_name}",
        agent_id=agent_id,
        server_name=server_name,
        tool_name="execute",
        arguments={},
    )


def _make_incident(incident_id: str) -> Incident:
    return Incident(
        id=incident_id,
        threat_ids=("threat-1",),
        affected_agent_ids=("agent-1",),
        severity=ThreatLevel.HIGH,
        status=IncidentStatus.DETECTED,
    )


@pytest.mark.asyncio
class TestContainBlastRadius:
    async def test_no_blast_radius_isolated_agent(self):
        """Agent with unique servers has empty blast radius."""
        agent_repo = AsyncMock()
        tool_call_repo = AsyncMock()
        incident_repo = AsyncMock()
        event_bus = AsyncMock()

        agent_a = _make_agent("agent-a")
        agent_b = _make_agent("agent-b")

        agent_repo.get_all.return_value = [agent_a, agent_b]

        # Agent A uses server-x, Agent B uses server-y (no overlap)
        tool_call_repo.get_by_agent_id.side_effect = lambda aid, **kw: {
            "agent-a": [_make_tool_call("agent-a", "server-x")],
            "agent-b": [_make_tool_call("agent-b", "server-y")],
        }[aid]

        incident_repo.get_by_id.return_value = _make_incident("inc-1")

        use_case = ContainBlastRadiusUseCase(
            agent_repository=agent_repo,
            tool_call_repository=tool_call_repo,
            incident_repository=incident_repo,
            event_bus=event_bus,
        )
        result = await use_case.execute(agent_id="agent-a", incident_id="inc-1")

        assert result["blast_radius_agent_ids"] == []
        assert result["shared_resources"] == []
        assert result["agents_elevated"] == 0

    async def test_blast_radius_shared_servers(self):
        """Two agents sharing a server appear in each other's blast radius."""
        agent_repo = AsyncMock()
        tool_call_repo = AsyncMock()
        incident_repo = AsyncMock()
        event_bus = AsyncMock()

        agent_a = _make_agent("agent-a")
        agent_b = _make_agent("agent-b")

        agent_repo.get_all.return_value = [agent_a, agent_b]

        # Both agents use "shared-server"
        tool_call_repo.get_by_agent_id.side_effect = lambda aid, **kw: {
            "agent-a": [_make_tool_call("agent-a", "shared-server")],
            "agent-b": [_make_tool_call("agent-b", "shared-server")],
        }[aid]

        incident = _make_incident("inc-1")
        incident_repo.get_by_id.return_value = incident

        use_case = ContainBlastRadiusUseCase(
            agent_repository=agent_repo,
            tool_call_repository=tool_call_repo,
            incident_repository=incident_repo,
            event_bus=event_bus,
        )
        result = await use_case.execute(agent_id="agent-a", incident_id="inc-1")

        assert "agent-b" in result["blast_radius_agent_ids"]
        assert "shared-server" in result["shared_resources"]
        assert result["agents_elevated"] == 1
        incident_repo.save.assert_awaited_once()

    async def test_blast_radius_excludes_compromised_agent(self):
        """The compromised agent itself should not appear in the blast radius list."""
        agent_repo = AsyncMock()
        tool_call_repo = AsyncMock()
        incident_repo = AsyncMock()
        event_bus = AsyncMock()

        agent_a = _make_agent("agent-a")

        agent_repo.get_all.return_value = [agent_a]

        tool_call_repo.get_by_agent_id.side_effect = lambda aid, **kw: {
            "agent-a": [_make_tool_call("agent-a", "server-x")],
        }[aid]

        incident_repo.get_by_id.return_value = _make_incident("inc-1")

        use_case = ContainBlastRadiusUseCase(
            agent_repository=agent_repo,
            tool_call_repository=tool_call_repo,
            incident_repository=incident_repo,
            event_bus=event_bus,
        )
        result = await use_case.execute(agent_id="agent-a", incident_id="inc-1")

        assert "agent-a" not in result["blast_radius_agent_ids"]
        assert result["agents_elevated"] == 0
