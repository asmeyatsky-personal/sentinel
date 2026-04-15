"""
Analyse Trajectory Use Case — DETECT module (Tier 2)

Architectural Intent:
- Tier 2 near-real-time trajectory analysis
- Fetches recent tool calls for a given agent
- Scores them against behavioural baselines via BehaviouralAnalyserPort
- Uses AnomalyDetectionService for domain-level scoring
- Creates Threat if anomaly score exceeds threshold

Parallelisation Notes:
- Behavioural analyser scoring and anomaly detection scoring run concurrently
"""

from __future__ import annotations

import asyncio
from uuid import uuid4

from sentinel.domain.entities.threat import Threat, ThreatCategory
from sentinel.domain.events.detection_events import BehaviouralAnomalyDetectedEvent
from sentinel.domain.ports.detection import BehaviouralAnalyserPort
from sentinel.domain.ports.event_bus import EventBusPort
from sentinel.domain.ports.repositories import ToolCallRepositoryPort, ThreatRepositoryPort
from sentinel.domain.services.anomaly_detection import AnomalyDetectionService
from sentinel.domain.services.behavioural_baseline import BehaviouralBaselineService
from sentinel.domain.value_objects.detection_score import DetectionScore
from sentinel.application.dtos.schemas import DetectionResultDTO


_DEFAULT_THRESHOLD = 40.0


class AnalyseTrajectoryUseCase:
    """Tier 2 near-real-time behavioural trajectory analysis."""

    def __init__(
        self,
        tool_call_repository: ToolCallRepositoryPort,
        threat_repository: ThreatRepositoryPort,
        behavioural_analyser: BehaviouralAnalyserPort,
        anomaly_detection_service: AnomalyDetectionService,
        baseline_service: BehaviouralBaselineService,
        event_bus: EventBusPort,
        threshold: float = _DEFAULT_THRESHOLD,
    ) -> None:
        self._tool_call_repo = tool_call_repository
        self._threat_repo = threat_repository
        self._behavioural_analyser = behavioural_analyser
        self._anomaly_service = anomaly_detection_service
        self._baseline_service = baseline_service
        self._event_bus = event_bus
        self._threshold = threshold

    async def execute(self, agent_id: str) -> DetectionResultDTO:
        tool_calls = await self._tool_call_repo.get_by_agent_id(agent_id)
        if not tool_calls:
            return DetectionResultDTO(detected=False, score=0.0)

        # Build baseline from historical calls
        baseline = self._baseline_service.build_baseline(agent_id, tool_calls)

        # Run analyser and anomaly scoring concurrently
        baseline_dict = {
            "avg_tool_calls_per_task": baseline.avg_tool_calls_per_task,
            "avg_latency_ms": baseline.avg_latency_ms,
            "avg_data_sources": baseline.avg_data_sources,
            "avg_payload_size_bytes": baseline.avg_payload_size_bytes,
        }

        analyser_score_task = self._behavioural_analyser.score_trajectory(
            tool_calls, baseline_dict
        )

        # Domain-level scoring: frequency + sequence anomaly
        frequency_score = self._anomaly_service.score_tool_call_frequency(
            tool_calls, baseline
        )
        sequence_score = self._anomaly_service.score_unknown_tool_sequence(
            tool_calls, baseline
        )

        analyser_score = await analyser_score_task

        # Aggregate all scores
        final_score = self._anomaly_service.aggregate_scores(
            [analyser_score, frequency_score, sequence_score]
        )
        threat_level = final_score.to_threat_level()

        if not final_score.exceeds_threshold(self._threshold):
            return DetectionResultDTO(
                detected=False,
                score=final_score.value,
                threat_level=threat_level.value,
            )

        # Anomaly detected — create threat
        threat = Threat(
            id=str(uuid4()),
            agent_id=agent_id,
            category=ThreatCategory.TRAJECTORY_ANOMALY,
            score=final_score,
            level=threat_level,
            description=(
                f"Tier 2 trajectory anomaly for agent '{agent_id}': "
                f"score={final_score.value}"
            ),
            evidence={
                "tool_call_count": len(tool_calls),
                "analyser_score": analyser_score.value,
                "frequency_score": frequency_score.value,
                "sequence_score": sequence_score.value,
                "baseline_avg_calls": baseline.avg_tool_calls_per_task,
            },
            detection_tier=2,
        )

        await self._threat_repo.save(threat)

        await self._event_bus.publish([
            BehaviouralAnomalyDetectedEvent(
                aggregate_id=agent_id,
                metric="trajectory",
                baseline_value=baseline.avg_tool_calls_per_task,
                observed_value=float(len(tool_calls)),
                deviation_sigma=final_score.value,
            ),
        ])

        return DetectionResultDTO(
            detected=True,
            score=final_score.value,
            threat_level=threat_level.value,
            threat_id=threat.id,
            category=ThreatCategory.TRAJECTORY_ANOMALY.value,
            description=threat.description,
            requires_auto_block=threat.requires_auto_block(),
            requires_auto_contain=threat.requires_auto_contain(),
        )
