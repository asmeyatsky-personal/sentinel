"""
Evaluate Tool Call Use Case — DETECT module (Tier 1)

Architectural Intent:
- Tier 1 real-time evaluation (<5 ms target)
- Runs a ToolCall through the RuleEnginePort for fast policy checks
- Validates capability boundaries against the agent's VAID
- Returns DetectionScore; creates and persists Threat if threshold exceeded
- Publishes domain events on detection

Parallelisation Notes:
- Rule evaluation and capability check run concurrently (independent)
"""

from __future__ import annotations

import asyncio
from uuid import uuid4

from sentinel.domain.entities.threat import Threat, ThreatCategory, ThreatStatus
from sentinel.domain.events.detection_events import CapabilityViolationDetectedEvent
from sentinel.domain.ports.detection import RuleEnginePort
from sentinel.domain.ports.event_bus import EventBusPort
from sentinel.domain.ports.repositories import (
    AgentRepositoryPort,
    ThreatRepositoryPort,
)
from sentinel.domain.entities.tool_call import ToolCall
from sentinel.domain.value_objects.detection_score import DetectionScore
from sentinel.application.dtos.schemas import DetectionResultDTO


_DEFAULT_THRESHOLD = 40.0


class EvaluateToolCallUseCase:
    """Tier 1 real-time tool call evaluation."""

    def __init__(
        self,
        rule_engine: RuleEnginePort,
        agent_repository: AgentRepositoryPort,
        threat_repository: ThreatRepositoryPort,
        event_bus: EventBusPort,
        threshold: float = _DEFAULT_THRESHOLD,
    ) -> None:
        self._rule_engine = rule_engine
        self._agent_repo = agent_repository
        self._threat_repo = threat_repository
        self._event_bus = event_bus
        self._threshold = threshold

    async def execute(self, tool_call: ToolCall) -> DetectionResultDTO:
        # Fetch agent to get VAID capabilities
        agent = await self._agent_repo.get_by_id(tool_call.agent_id)
        if agent is None:
            return DetectionResultDTO(
                detected=True,
                score=100.0,
                threat_level="CRITICAL",
                category="CAPABILITY_VIOLATION",
                description=f"Unknown agent '{tool_call.agent_id}' attempted tool call",
                requires_auto_block=True,
            )

        capabilities = agent.vaid.capabilities

        # Run rule engine evaluation and capability check concurrently
        rule_score, capability_violation = await asyncio.gather(
            self._rule_engine.evaluate(tool_call, capabilities),
            self._check_capability_boundary(tool_call, agent),
        )

        # Merge scores — take the worst
        final_score = DetectionScore(
            value=max(rule_score.value, capability_violation.value)
        )
        threat_level = final_score.to_threat_level()

        if not final_score.exceeds_threshold(self._threshold):
            return DetectionResultDTO(
                detected=False,
                score=final_score.value,
                threat_level=threat_level.value,
            )

        # Threshold exceeded — create and save threat
        category = (
            ThreatCategory.CAPABILITY_VIOLATION
            if capability_violation.value >= rule_score.value
            else ThreatCategory.BEHAVIOURAL_ANOMALY
        )

        threat = Threat(
            id=str(uuid4()),
            agent_id=tool_call.agent_id,
            category=category,
            score=final_score,
            level=threat_level,
            description=(
                f"Tier 1 detection on tool '{tool_call.full_tool_path}': "
                f"score={final_score.value}"
            ),
            evidence={
                "tool_call_id": tool_call.id,
                "tool_path": tool_call.full_tool_path,
                "rule_score": rule_score.value,
                "capability_score": capability_violation.value,
            },
            detection_tier=1,
        )

        await self._threat_repo.save(threat)

        events = list(threat.domain_events)
        if category is ThreatCategory.CAPABILITY_VIOLATION:
            events.append(
                CapabilityViolationDetectedEvent(
                    aggregate_id=agent.id,
                    tool_name=tool_call.full_tool_path,
                    required_capability=tool_call.tool_name,
                )
            )
        if events:
            await self._event_bus.publish(events)

        return DetectionResultDTO(
            detected=True,
            score=final_score.value,
            threat_level=threat_level.value,
            threat_id=threat.id,
            category=category.value,
            description=threat.description,
            requires_auto_block=threat.requires_auto_block(),
            requires_auto_contain=threat.requires_auto_contain(),
        )

    # ── Private helpers ──────────────────────────────────────────────────

    async def _check_capability_boundary(
        self, tool_call: ToolCall, agent: object
    ) -> DetectionScore:
        """Check whether the agent's VAID grants the required capability."""
        from sentinel.domain.entities.agent import Agent

        assert isinstance(agent, Agent)

        if not agent.vaid.is_valid():
            return DetectionScore(value=95.0)

        if not agent.has_tool(tool_call.tool_name):
            return DetectionScore(value=85.0)

        if not agent.vaid.has_capability(tool_call.tool_name):
            return DetectionScore(value=75.0)

        return DetectionScore(value=0.0)
