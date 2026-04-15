"""
Detect Prompt Injection Use Case — DETECT module

Architectural Intent:
- Scans content (tool call responses, external data) for prompt injection
- Delegates detection to PromptInjectionDetectorPort (infrastructure)
- Creates Threat entity if injection detected
- Publishes PromptInjectionDetectedEvent
"""

from __future__ import annotations

from uuid import uuid4

from sentinel.domain.entities.threat import Threat, ThreatCategory
from sentinel.domain.events.detection_events import PromptInjectionDetectedEvent
from sentinel.domain.ports.detection import PromptInjectionDetectorPort
from sentinel.domain.ports.event_bus import EventBusPort
from sentinel.domain.ports.repositories import ThreatRepositoryPort
from sentinel.domain.value_objects.detection_score import DetectionScore
from sentinel.application.dtos.schemas import DetectionResultDTO


class DetectPromptInjectionUseCase:
    """Scans content for prompt injection attacks."""

    def __init__(
        self,
        injection_detector: PromptInjectionDetectorPort,
        threat_repository: ThreatRepositoryPort,
        event_bus: EventBusPort,
    ) -> None:
        self._detector = injection_detector
        self._threat_repo = threat_repository
        self._event_bus = event_bus

    async def execute(
        self, content: str, agent_id: str = "", tool_call_id: str = ""
    ) -> DetectionResultDTO:
        result = await self._detector.analyse(content)

        if not result.is_injection:
            return DetectionResultDTO(
                detected=False,
                score=result.confidence * 100.0,
                threat_level="LOW",
            )

        score = DetectionScore(value=min(result.confidence * 100.0, 100.0))
        threat_level = score.to_threat_level()

        threat = Threat(
            id=str(uuid4()),
            agent_id=agent_id,
            category=ThreatCategory.PROMPT_INJECTION,
            score=score,
            level=threat_level,
            description=(
                f"Prompt injection detected (confidence={result.confidence:.2f}). "
                f"Matched patterns: {', '.join(result.matched_patterns)}"
            ),
            evidence={
                "confidence": result.confidence,
                "matched_patterns": list(result.matched_patterns),
                "tool_call_id": tool_call_id,
                "content_snippet": content[:200],
            },
            detection_tier=1,
        )

        await self._threat_repo.save(threat)

        await self._event_bus.publish([
            PromptInjectionDetectedEvent(
                aggregate_id=agent_id or threat.id,
                tool_call_id=tool_call_id,
                confidence=result.confidence,
                payload_snippet=content[:200],
            ),
        ])

        return DetectionResultDTO(
            detected=True,
            score=score.value,
            threat_level=threat_level.value,
            threat_id=threat.id,
            category=ThreatCategory.PROMPT_INJECTION.value,
            description=threat.description,
            requires_auto_block=threat.requires_auto_block(),
            requires_auto_contain=threat.requires_auto_contain(),
        )
