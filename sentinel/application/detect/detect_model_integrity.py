"""
Detect Model Integrity Use Case — DETECT module

Architectural Intent:
- Monitors for statistical indicators that the underlying model has changed
- Maintains per-agent baseline profiles (latency, response size, token patterns)
- Flags significant distribution shifts as potential model integrity threats
- Creates Threat entity when shift exceeds thresholds
"""

from __future__ import annotations

from uuid import uuid4

from sentinel.application.dtos.schemas import DetectionResultDTO
from sentinel.domain.entities.threat import Threat, ThreatCategory
from sentinel.domain.ports.event_bus import EventBusPort
from sentinel.domain.ports.repositories import (
    ThreatRepositoryPort,
    ToolCallRepositoryPort,
)
from sentinel.domain.value_objects.detection_score import DetectionScore

_MAX_PROFILES = 10_000


class DetectModelIntegrityUseCase:
    """Monitors for statistical indicators that the underlying model has changed."""

    def __init__(
        self,
        tool_call_repository: ToolCallRepositoryPort,
        threat_repository: ThreatRepositoryPort,
        event_bus: EventBusPort,
    ) -> None:
        self._tool_call_repo = tool_call_repository
        self._threat_repo = threat_repository
        self._event_bus = event_bus
        self._agent_profiles: dict[str, dict] = {}

    async def execute(self, agent_id: str) -> DetectionResultDTO:
        tool_calls = await self._tool_call_repo.get_by_agent_id(agent_id)

        if not tool_calls:
            return DetectionResultDTO(
                detected=False,
                score=0.0,
                threat_level="LOW",
            )

        # Compute current profile
        latencies = [tc.latency_ms for tc in tool_calls if tc.latency_ms > 0]
        response_sizes = [
            len(str(tc.response)) for tc in tool_calls if tc.response is not None
        ]

        current_avg_latency = sum(latencies) / len(latencies) if latencies else 0.0
        current_avg_response_size = (
            sum(response_sizes) / len(response_sizes) if response_sizes else 0.0
        )

        current_profile = {
            "avg_latency": current_avg_latency,
            "avg_response_length": current_avg_response_size,
            "sample_count": len(tool_calls),
        }

        # Compare against stored baseline
        baseline = self._agent_profiles.get(agent_id)

        if baseline is None:
            # First observation — store as baseline, no detection
            self._store_profile(agent_id, current_profile)
            return DetectionResultDTO(
                detected=False,
                score=0.0,
                threat_level="LOW",
            )

        anomalies: list[str] = []
        evidence: dict = {"agent_id": agent_id}

        # Latency distribution shift (>2x)
        baseline_latency = baseline["avg_latency"]
        if baseline_latency > 0 and current_avg_latency > 2 * baseline_latency:
            anomalies.append("latency_shift")
            evidence["latency_shift"] = {
                "baseline": baseline_latency,
                "current": current_avg_latency,
                "ratio": current_avg_latency / baseline_latency,
            }

        # Response size shift (>3x)
        baseline_response = baseline["avg_response_length"]
        if baseline_response > 0 and current_avg_response_size > 3 * baseline_response:
            anomalies.append("response_size_shift")
            evidence["response_size_shift"] = {
                "baseline": baseline_response,
                "current": current_avg_response_size,
                "ratio": current_avg_response_size / baseline_response,
            }

        # Update stored profile
        self._store_profile(agent_id, current_profile)

        if not anomalies:
            return DetectionResultDTO(
                detected=False,
                score=0.0,
                threat_level="LOW",
            )

        base_score = min(len(anomalies) * 45.0, 100.0)
        score = DetectionScore(value=base_score)
        threat_level = score.to_threat_level()

        threat = Threat(
            id=str(uuid4()),
            agent_id=agent_id,
            category=ThreatCategory.MODEL_INTEGRITY,
            score=score,
            level=threat_level,
            description=(
                f"Model integrity shift detected for agent {agent_id}: "
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
            category=ThreatCategory.MODEL_INTEGRITY.value,
            description=threat.description,
            requires_auto_block=threat.requires_auto_block(),
            requires_auto_contain=threat.requires_auto_contain(),
        )

    def _store_profile(self, agent_id: str, profile: dict) -> None:
        if len(self._agent_profiles) >= _MAX_PROFILES and agent_id not in self._agent_profiles:
            oldest_key = next(iter(self._agent_profiles))
            del self._agent_profiles[oldest_key]
        self._agent_profiles[agent_id] = profile
