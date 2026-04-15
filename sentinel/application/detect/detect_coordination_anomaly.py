"""
Detect Coordination Anomaly Use Case — DETECT module

Architectural Intent:
- Detects unusual patterns in inter-agent communication
- Analyses message volume spikes, circular delegation, and unknown agent contact
- Creates Threat entity when coordination anomaly is detected
- Returns DetectionResultDTO for presentation layer consumption
"""

from __future__ import annotations

from collections import defaultdict
from uuid import uuid4

from sentinel.application.dtos.schemas import DetectionResultDTO
from sentinel.domain.entities.threat import Threat, ThreatCategory
from sentinel.domain.ports.event_bus import EventBusPort
from sentinel.domain.ports.repositories import (
    ThreatRepositoryPort,
    ToolCallRepositoryPort,
)
from sentinel.domain.value_objects.detection_score import DetectionScore


class DetectCoordinationAnomalyUseCase:
    """Detects unusual patterns in inter-agent communication."""

    def __init__(
        self,
        tool_call_repository: ToolCallRepositoryPort,
        threat_repository: ThreatRepositoryPort,
        event_bus: EventBusPort,
    ) -> None:
        self._tool_call_repo = tool_call_repository
        self._threat_repo = threat_repository
        self._event_bus = event_bus

    async def execute(self, agent_id: str) -> DetectionResultDTO:
        tool_calls = await self._tool_call_repo.get_by_agent_id(agent_id)

        anomalies: list[str] = []
        evidence: dict = {"agent_id": agent_id}

        # --- Volume spike detection ---
        if tool_calls:
            total = len(tool_calls)
            half = total // 2 or 1
            recent_count = half
            baseline_count = total - half or 1
            if recent_count > 3 * baseline_count:
                anomalies.append("message_volume_spike")
                evidence["volume_spike"] = {
                    "recent": recent_count,
                    "baseline": baseline_count,
                    "ratio": recent_count / baseline_count,
                }

        # --- Circular delegation detection ---
        delegation_graph: dict[str, set[str]] = defaultdict(set)
        for tc in tool_calls:
            if tc.response and isinstance(tc.response, dict):
                callee = tc.response.get("agent_id", "")
                if callee:
                    delegation_graph[agent_id].add(callee)

        # Check if any callee also calls back to this agent
        all_tool_calls = await self._tool_call_repo.get_recent(limit=100)
        for tc in all_tool_calls:
            if tc.agent_id in delegation_graph.get(agent_id, set()):
                if tc.response and isinstance(tc.response, dict):
                    if tc.response.get("agent_id") == agent_id:
                        anomalies.append("circular_delegation")
                        evidence["circular_delegation"] = {
                            "agent_a": agent_id,
                            "agent_b": tc.agent_id,
                        }
                        break

        # --- Communication with unknown agents ---
        known_agents: set[str] = set()
        for tc in all_tool_calls:
            known_agents.add(tc.agent_id)
        for tc in tool_calls:
            if tc.response and isinstance(tc.response, dict):
                callee = tc.response.get("agent_id", "")
                if callee and callee not in known_agents:
                    anomalies.append("unknown_agent_contact")
                    evidence["unknown_agent"] = callee
                    break

        if not anomalies:
            return DetectionResultDTO(
                detected=False,
                score=0.0,
                threat_level="LOW",
            )

        # Compute score based on number and severity of anomalies
        base_score = min(len(anomalies) * 35.0, 100.0)
        score = DetectionScore(value=base_score)
        threat_level = score.to_threat_level()

        threat = Threat(
            id=str(uuid4()),
            agent_id=agent_id,
            category=ThreatCategory.COORDINATION_ANOMALY,
            score=score,
            level=threat_level,
            description=(
                f"Coordination anomaly detected for agent {agent_id}: "
                f"{', '.join(anomalies)}"
            ),
            evidence=evidence,
            detection_tier=1,
        )

        await self._threat_repo.save(threat)

        return DetectionResultDTO(
            detected=True,
            score=score.value,
            threat_level=threat_level.value,
            threat_id=threat.id,
            category=ThreatCategory.COORDINATION_ANOMALY.value,
            description=threat.description,
            requires_auto_block=threat.requires_auto_block(),
            requires_auto_contain=threat.requires_auto_contain(),
        )
