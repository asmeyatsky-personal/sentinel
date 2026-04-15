"""
Inspect Model API Payload Use Case — SHIELD module

Architectural Intent:
- Inspects data sent to model API endpoints (Anthropic, OpenAI, Google)
  for sensitive content before it leaves the trust boundary
- Uses PIIDetectionService (domain) for pattern matching and classification
- Returns ShieldResultDTO with matches, classification, and optional redaction
- Creates Threat with DATA_EXFILTRATION category if PII is detected
- Publishes DataLeakageDetectedEvent via event bus
"""

from __future__ import annotations

from uuid import uuid4

from sentinel.application.dtos.schemas import PIIMatchDTO, ShieldResultDTO
from sentinel.domain.entities.threat import Threat, ThreatCategory
from sentinel.domain.events.detection_events import DataLeakageDetectedEvent
from sentinel.domain.ports.event_bus import EventBusPort
from sentinel.domain.ports.repositories import ThreatRepositoryPort
from sentinel.domain.services.pii_detection import PIIDetectionService
from sentinel.domain.value_objects.detection_score import DetectionScore


MODEL_API_DOMAINS: frozenset[str] = frozenset({
    "api.anthropic.com",
    "api.openai.com",
    "generativelanguage.googleapis.com",
})


class InspectModelAPIPayloadUseCase:
    """Scans outbound payloads destined for model APIs for PII leakage."""

    def __init__(
        self,
        pii_detection_service: PIIDetectionService,
        threat_repository: ThreatRepositoryPort,
        event_bus: EventBusPort,
    ) -> None:
        self._pii_service = pii_detection_service
        self._threat_repo = threat_repository
        self._event_bus = event_bus

    async def execute(
        self,
        payload: str,
        destination: str,
        agent_id: str = "",
    ) -> ShieldResultDTO:
        # Only deep-scan payloads headed to known model API domains
        if destination not in MODEL_API_DOMAINS:
            return ShieldResultDTO()

        # Domain service handles PII detection and classification
        matches = self._pii_service.detect(payload)
        classification = self._pii_service.classify_content(payload)

        match_dtos = [
            PIIMatchDTO(pii_type=pattern.name, value=matched_value)
            for pattern, matched_value in matches
        ]

        has_pii = len(matches) > 0

        result = ShieldResultDTO(
            has_pii=has_pii,
            classification=classification.value,
            matches=match_dtos,
        )

        if not has_pii:
            return result

        # Redact if classification warrants it
        if classification.requires_redaction():
            result = result.model_copy(
                update={"redacted_content": self._pii_service.redact(payload)}
            )

        # Score based on classification severity
        pii_types = tuple(m.pii_type for m in match_dtos)
        score_value = 90.0 if classification.value == "RESTRICTED" else 70.0
        score = DetectionScore(value=score_value)

        threat = Threat(
            id=str(uuid4()),
            agent_id=agent_id,
            category=ThreatCategory.DATA_EXFILTRATION,
            score=score,
            level=score.to_threat_level(),
            description=(
                f"PII detected in model API payload to {destination}: "
                f"{', '.join(pii_types)}. "
                f"Classification: {classification.value}"
            ),
            evidence={
                "pii_types": list(pii_types),
                "classification": classification.value,
                "match_count": len(matches),
                "destination": destination,
            },
            detection_tier=1,
        )

        await self._threat_repo.save(threat)

        await self._event_bus.publish([
            DataLeakageDetectedEvent(
                aggregate_id=agent_id or threat.id,
                pii_types=pii_types,
                destination=destination,
                classification=classification.value,
            ),
        ])

        result = result.model_copy(update={"threat_id": threat.id})

        return result
