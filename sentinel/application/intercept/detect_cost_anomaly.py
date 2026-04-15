"""
Detect Cost Anomaly Use Case — INTERCEPT module

Architectural Intent:
- Tracks inference cost per agent based on tool call volume and latency
- Compares current cost against a rolling baseline
- Alerts on cost anomalies that deviate significantly from the baseline
- Creates Threat if cost ratio exceeds threshold
- Publishes CostAnomalyDetectedEvent
"""

from __future__ import annotations

from collections import defaultdict
from uuid import uuid4

from sentinel.domain.entities.threat import Threat, ThreatCategory
from sentinel.domain.events.detection_events import CostAnomalyDetectedEvent
from sentinel.domain.ports.event_bus import EventBusPort
from sentinel.domain.ports.repositories import ToolCallRepositoryPort, ThreatRepositoryPort
from sentinel.domain.value_objects.detection_score import DetectionScore
from sentinel.application.dtos.schemas import CostAnomalyDTO


# Simple cost model: cost = number_of_calls * avg_latency_ms * cost_per_ms
_COST_PER_MS = 0.0001  # USD per ms of inference time
_ANOMALY_RATIO_THRESHOLD = 3.0


class DetectCostAnomalyUseCase:
    """Tracks inference cost per agent and alerts on anomalies."""

    def __init__(
        self,
        tool_call_repository: ToolCallRepositoryPort,
        threat_repository: ThreatRepositoryPort,
        event_bus: EventBusPort,
        cost_per_ms: float = _COST_PER_MS,
        anomaly_ratio_threshold: float = _ANOMALY_RATIO_THRESHOLD,
    ) -> None:
        self._tool_call_repo = tool_call_repository
        self._threat_repo = threat_repository
        self._event_bus = event_bus
        self._cost_per_ms = cost_per_ms
        self._anomaly_ratio = anomaly_ratio_threshold
        # Rolling baseline per agent (accumulated over invocations)
        self._baselines: dict[str, list[float]] = defaultdict(list)

    async def execute(self, agent_id: str) -> CostAnomalyDTO:
        tool_calls = await self._tool_call_repo.get_by_agent_id(agent_id)
        if not tool_calls:
            return CostAnomalyDTO(agent_id=agent_id)

        # Calculate current cost
        total_latency_ms = sum(tc.latency_ms for tc in tool_calls)
        current_cost = total_latency_ms * self._cost_per_ms

        # Get or initialise baseline
        baseline_costs = self._baselines[agent_id]

        if not baseline_costs:
            # First observation — record as baseline, no anomaly
            self._baselines[agent_id].append(current_cost)
            return CostAnomalyDTO(
                agent_id=agent_id,
                expected_cost=current_cost,
                actual_cost=current_cost,
                ratio=1.0,
            )

        expected_cost = sum(baseline_costs) / len(baseline_costs)
        ratio = current_cost / expected_cost if expected_cost > 0 else 0.0

        # Update rolling baseline (keep last 20 observations)
        self._baselines[agent_id].append(current_cost)
        if len(self._baselines[agent_id]) > 20:
            self._baselines[agent_id] = self._baselines[agent_id][-20:]

        if ratio < self._anomaly_ratio:
            return CostAnomalyDTO(
                agent_id=agent_id,
                expected_cost=expected_cost,
                actual_cost=current_cost,
                ratio=ratio,
            )

        # Cost anomaly detected
        score_value = min(50.0 + (ratio - self._anomaly_ratio) * 10.0, 100.0)
        score = DetectionScore(value=score_value)

        threat = Threat(
            id=str(uuid4()),
            agent_id=agent_id,
            category=ThreatCategory.COST_ANOMALY,
            score=score,
            level=score.to_threat_level(),
            description=(
                f"Cost anomaly for agent '{agent_id}': "
                f"expected=${expected_cost:.4f}, actual=${current_cost:.4f}, "
                f"ratio={ratio:.1f}x"
            ),
            evidence={
                "expected_cost": expected_cost,
                "actual_cost": current_cost,
                "ratio": ratio,
                "tool_call_count": len(tool_calls),
                "total_latency_ms": total_latency_ms,
            },
            detection_tier=2,
        )

        await self._threat_repo.save(threat)

        await self._event_bus.publish([
            CostAnomalyDetectedEvent(
                aggregate_id=agent_id,
                expected_cost=expected_cost,
                actual_cost=current_cost,
                ratio=ratio,
            ),
        ])

        return CostAnomalyDTO(
            is_anomaly=True,
            agent_id=agent_id,
            expected_cost=expected_cost,
            actual_cost=current_cost,
            ratio=ratio,
            threat_id=threat.id,
        )
