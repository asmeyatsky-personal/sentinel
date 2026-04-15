"""
Inspect Payload Use Case — SHIELD module

Architectural Intent:
- Scans outbound tool call payloads for PII / sensitive data
- Uses PIIDetectionService (domain) for pattern matching and classification
- Returns ShieldResultDTO with matches, classification, and optional redaction
- Creates Threat if data leakage detected (CONFIDENTIAL or RESTRICTED data)
- Publishes DataLeakageDetectedEvent
"""

from __future__ import annotations

import json
from uuid import uuid4

from sentinel.domain.entities.threat import Threat, ThreatCategory
from sentinel.domain.events.detection_events import DataLeakageDetectedEvent
from sentinel.domain.ports.event_bus import EventBusPort
from sentinel.domain.ports.repositories import ThreatRepositoryPort
from sentinel.domain.services.pii_detection import PIIDetectionService
from sentinel.domain.value_objects.detection_score import DetectionScore
from sentinel.application.dtos.schemas import PIIMatchDTO, ShieldResultDTO


class InspectPayloadUseCase:
    """Scans outbound payloads for PII and classifies data sensitivity."""

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
        payload: dict | str,
        agent_id: str = "",
        tool_call_id: str = "",
        destination: str = "",
    ) -> ShieldResultDTO:
        # Normalise payload to string for scanning
        content = payload if isinstance(payload, str) else json.dumps(payload, default=str)

        # Domain service handles PII detection and classification
        matches = self._pii_service.detect(content)
        classification = self._pii_service.classify_content(content)

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

        # Redact if sensitive
        if classification.requires_redaction():
            result = result.model_copy(
                update={"redacted_content": self._pii_service.redact(content)}
            )

        # Create threat if data leakage risk
        if has_pii and classification.requires_redaction():
            pii_types = tuple(m.pii_type for m in match_dtos)
            score_value = 70.0 if classification.value == "CONFIDENTIAL" else 90.0
            score = DetectionScore(value=score_value)

            threat = Threat(
                id=str(uuid4()),
                agent_id=agent_id,
                category=ThreatCategory.DATA_EXFILTRATION,
                score=score,
                level=score.to_threat_level(),
                description=(
                    f"PII detected in outbound payload: "
                    f"{', '.join(pii_types)}. "
                    f"Classification: {classification.value}"
                ),
                evidence={
                    "pii_types": list(pii_types),
                    "classification": classification.value,
                    "match_count": len(matches),
                    "tool_call_id": tool_call_id,
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
