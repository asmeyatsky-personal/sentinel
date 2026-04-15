"""Tests for in-memory repositories — infrastructure integration tests."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from sentinel.domain.entities.agent import Agent, AgentStatus
from sentinel.domain.entities.threat import Threat, ThreatCategory, ThreatStatus
from sentinel.domain.value_objects.detection_score import DetectionScore
from sentinel.domain.value_objects.threat_level import ThreatLevel
from sentinel.domain.value_objects.vaid import VAID


def _make_agent(agent_id: str = "agent-1") -> Agent:
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
    )


def _make_threat(threat_id: str = "threat-1", status: ThreatStatus = ThreatStatus.OPEN) -> Threat:
    return Threat(
        id=threat_id,
        agent_id="agent-1",
        category=ThreatCategory.PROMPT_INJECTION,
        score=DetectionScore(value=75.0),
        level=ThreatLevel.HIGH,
        description="test",
        evidence={},
        status=status,
    )


@pytest.mark.asyncio
class TestInMemoryAgentRepository:
    async def test_save_and_get(self):
        from sentinel.infrastructure.repositories.in_memory_agent_repo import (
            InMemoryAgentRepository,
        )

        repo = InMemoryAgentRepository()
        agent = _make_agent()
        await repo.save(agent)
        retrieved = await repo.get_by_id("agent-1")
        assert retrieved is not None
        assert retrieved.id == "agent-1"

    async def test_get_nonexistent(self):
        from sentinel.infrastructure.repositories.in_memory_agent_repo import (
            InMemoryAgentRepository,
        )

        repo = InMemoryAgentRepository()
        assert await repo.get_by_id("nonexistent") is None

    async def test_get_all(self):
        from sentinel.infrastructure.repositories.in_memory_agent_repo import (
            InMemoryAgentRepository,
        )

        repo = InMemoryAgentRepository()
        await repo.save(_make_agent("a1"))
        await repo.save(_make_agent("a2"))
        all_agents = await repo.get_all()
        assert len(all_agents) == 2

    async def test_delete(self):
        from sentinel.infrastructure.repositories.in_memory_agent_repo import (
            InMemoryAgentRepository,
        )

        repo = InMemoryAgentRepository()
        await repo.save(_make_agent())
        await repo.delete("agent-1")
        assert await repo.get_by_id("agent-1") is None


@pytest.mark.asyncio
class TestInMemoryThreatRepository:
    async def test_save_and_get(self):
        from sentinel.infrastructure.repositories.in_memory_threat_repo import (
            InMemoryThreatRepository,
        )

        repo = InMemoryThreatRepository()
        await repo.save(_make_threat())
        assert await repo.get_by_id("threat-1") is not None

    async def test_get_open_threats(self):
        from sentinel.infrastructure.repositories.in_memory_threat_repo import (
            InMemoryThreatRepository,
        )

        repo = InMemoryThreatRepository()
        await repo.save(_make_threat("t1", ThreatStatus.OPEN))
        await repo.save(_make_threat("t2", ThreatStatus.MITIGATED))
        await repo.save(_make_threat("t3", ThreatStatus.OPEN))
        open_threats = await repo.get_open_threats()
        assert len(open_threats) == 2

    async def test_get_by_agent_id(self):
        from sentinel.infrastructure.repositories.in_memory_threat_repo import (
            InMemoryThreatRepository,
        )

        repo = InMemoryThreatRepository()
        await repo.save(_make_threat("t1"))
        await repo.save(_make_threat("t2"))
        threats = await repo.get_by_agent_id("agent-1")
        assert len(threats) == 2
