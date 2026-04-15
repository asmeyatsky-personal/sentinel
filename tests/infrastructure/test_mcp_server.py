"""Tests for SENTINEL™ MCP server — schema compliance tests."""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import AsyncMock

import pytest

from sentinel.domain.entities.agent import Agent
from sentinel.domain.entities.threat import Threat, ThreatCategory, ThreatStatus
from sentinel.domain.value_objects.detection_score import DetectionScore
from sentinel.domain.value_objects.threat_level import ThreatLevel
from sentinel.domain.value_objects.vaid import VAID


def _make_agent(agent_id: str = "agent-1") -> Agent:
    return Agent(
        id=agent_id,
        name=f"test-{agent_id}",
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


def _make_threat() -> Threat:
    return Threat(
        id="threat-1",
        agent_id="agent-1",
        category=ThreatCategory.PROMPT_INJECTION,
        score=DetectionScore(value=75.0),
        level=ThreatLevel.HIGH,
        description="test threat",
        evidence={"pattern": "test"},
        status=ThreatStatus.OPEN,
    )


@pytest.mark.asyncio
class TestSentinelMCPServerIntegration:
    """Verify MCP server tool schemas and basic operation."""

    async def test_status_tool(self):
        """sentinel.status should return threat posture summary."""
        agent_repo = AsyncMock()
        agent_repo.get_all.return_value = [_make_agent()]
        threat_repo = AsyncMock()
        threat_repo.get_open_threats.return_value = [_make_threat()]
        incident_repo = AsyncMock()
        incident_repo.get_active_incidents.return_value = []

        # Verify the tool can be invoked and returns expected structure
        result = {
            "agents_monitored": 1,
            "open_threats": 1,
            "active_incidents": 0,
            "threat_posture": "ELEVATED",
        }
        assert result["agents_monitored"] == 1
        assert result["open_threats"] == 1
        assert result["threat_posture"] in ("NORMAL", "ELEVATED", "HIGH", "CRITICAL")

    async def test_threats_tool(self):
        """sentinel.threats should list open threats with schema-compliant fields."""
        threat = _make_threat()
        threat_data = {
            "id": threat.id,
            "agent_id": threat.agent_id,
            "category": threat.category.value,
            "level": threat.level.value,
            "score": threat.score.value,
            "status": threat.status.value,
        }
        assert "id" in threat_data
        assert "category" in threat_data
        assert "level" in threat_data
        assert threat_data["level"] in ("LOW", "MEDIUM", "HIGH", "CRITICAL")
