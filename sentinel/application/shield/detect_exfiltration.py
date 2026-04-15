"""
Detect Exfiltration Use Case — SHIELD module

Architectural Intent:
- Analyses patterns across multiple tool calls for data staging/exfiltration
- Identifies aggregation patterns (many reads) followed by external writes
- Uses heuristics: read-heavy bursts + large payload writes to external targets
- Creates Threat if exfiltration pattern detected

Parallelisation Notes:
- Pattern analysis sub-checks (read pattern, write pattern) run concurrently
"""

from __future__ import annotations

import asyncio
from uuid import uuid4

from sentinel.domain.entities.threat import Threat, ThreatCategory
from sentinel.domain.events.detection_events import DataLeakageDetectedEvent
from sentinel.domain.ports.event_bus import EventBusPort
from sentinel.domain.ports.repositories import ToolCallRepositoryPort, ThreatRepositoryPort
from sentinel.domain.value_objects.detection_score import DetectionScore
from sentinel.application.dtos.schemas import DetectionResultDTO


# Heuristic thresholds
_READ_TOOLS = frozenset({"read", "get", "fetch", "list", "query", "search", "select"})
_WRITE_EXTERNAL_TOOLS = frozenset({"send", "post", "upload", "write", "put", "email", "webhook"})
_READ_BURST_THRESHOLD = 5
_LARGE_PAYLOAD_BYTES = 5000


class DetectExfiltrationUseCase:
    """Analyses tool call patterns for data staging and exfiltration."""

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
        if not tool_calls:
            return DetectionResultDTO(detected=False, score=0.0)

        # Analyse read and write patterns concurrently
        read_score_coro = self._analyse_read_aggregation(tool_calls)
        write_score_coro = self._analyse_external_writes(tool_calls)
        read_score, write_score = await asyncio.gather(
            read_score_coro, write_score_coro
        )

        # Combined exfiltration signal: reads aggregating data + external writes
        combined_value = 0.0
        if read_score > 0 and write_score > 0:
            combined_value = min((read_score + write_score) / 2.0 + 20.0, 100.0)
        elif write_score > 0:
            combined_value = write_score * 0.6
        else:
            combined_value = 0.0

        final_score = DetectionScore(value=combined_value)
        threat_level = final_score.to_threat_level()

        if final_score.value < 40.0:
            return DetectionResultDTO(
                detected=False,
                score=final_score.value,
                threat_level=threat_level.value,
            )

        threat = Threat(
            id=str(uuid4()),
            agent_id=agent_id,
            category=ThreatCategory.DATA_EXFILTRATION,
            score=final_score,
            level=threat_level,
            description=(
                f"Exfiltration pattern detected for agent '{agent_id}': "
                f"read_score={read_score:.1f}, write_score={write_score:.1f}"
            ),
            evidence={
                "read_score": read_score,
                "write_score": write_score,
                "tool_call_count": len(tool_calls),
                "read_tool_calls": sum(
                    1 for tc in tool_calls if self._is_read_tool(tc.tool_name)
                ),
                "write_tool_calls": sum(
                    1 for tc in tool_calls if self._is_write_external_tool(tc.tool_name)
                ),
            },
            detection_tier=2,
        )

        await self._threat_repo.save(threat)

        await self._event_bus.publish([
            DataLeakageDetectedEvent(
                aggregate_id=agent_id,
                pii_types=(),
                destination="external",
                classification="UNKNOWN",
            ),
        ])

        return DetectionResultDTO(
            detected=True,
            score=final_score.value,
            threat_level=threat_level.value,
            threat_id=threat.id,
            category=ThreatCategory.DATA_EXFILTRATION.value,
            description=threat.description,
            requires_auto_block=threat.requires_auto_block(),
            requires_auto_contain=threat.requires_auto_contain(),
        )

    # ── Private helpers ──────────────────────────────────────────────────

    @staticmethod
    def _is_read_tool(tool_name: str) -> bool:
        name_lower = tool_name.lower()
        return any(keyword in name_lower for keyword in _READ_TOOLS)

    @staticmethod
    def _is_write_external_tool(tool_name: str) -> bool:
        name_lower = tool_name.lower()
        return any(keyword in name_lower for keyword in _WRITE_EXTERNAL_TOOLS)

    async def _analyse_read_aggregation(self, tool_calls: list) -> float:
        """Score read-heavy bursts indicative of data staging."""
        read_calls = [tc for tc in tool_calls if self._is_read_tool(tc.tool_name)]
        if len(read_calls) < _READ_BURST_THRESHOLD:
            return 0.0

        # More reads in a burst = higher suspicion
        ratio = len(read_calls) / max(len(tool_calls), 1)
        if ratio > 0.8:
            return 80.0
        if ratio > 0.6:
            return 60.0
        if ratio > 0.4:
            return 40.0
        return 20.0

    async def _analyse_external_writes(self, tool_calls: list) -> float:
        """Score external write operations, especially with large payloads."""
        write_calls = [
            tc for tc in tool_calls if self._is_write_external_tool(tc.tool_name)
        ]
        if not write_calls:
            return 0.0

        large_payload_count = sum(
            1 for tc in write_calls if tc.payload_size_bytes() > _LARGE_PAYLOAD_BYTES
        )

        if large_payload_count >= 3:
            return 90.0
        if large_payload_count >= 1:
            return 60.0
        if len(write_calls) >= 3:
            return 40.0
        return 20.0
