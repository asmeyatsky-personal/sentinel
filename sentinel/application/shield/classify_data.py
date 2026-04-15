"""
Classify Data Use Case — SHIELD module

Architectural Intent:
- Classifies arbitrary data content into sensitivity tiers
- Delegates to PIIDetectionService for domain-level classification
- Returns the classification level: PUBLIC / INTERNAL / CONFIDENTIAL / RESTRICTED
"""

from __future__ import annotations

from sentinel.domain.services.pii_detection import PIIDetectionService
from sentinel.application.dtos.schemas import ShieldResultDTO, PIIMatchDTO


class ClassifyDataUseCase:
    """Classifies data content into PUBLIC/INTERNAL/CONFIDENTIAL/RESTRICTED."""

    def __init__(self, pii_detection_service: PIIDetectionService) -> None:
        self._pii_service = pii_detection_service

    async def execute(self, content: str) -> ShieldResultDTO:
        matches = self._pii_service.detect(content)
        classification = self._pii_service.classify_content(content)

        match_dtos = [
            PIIMatchDTO(pii_type=pattern.name, value=matched_value)
            for pattern, matched_value in matches
        ]

        result = ShieldResultDTO(
            has_pii=len(matches) > 0,
            classification=classification.value,
            matches=match_dtos,
        )

        if classification.requires_redaction():
            result = result.model_copy(
                update={"redacted_content": self._pii_service.redact(content)}
            )

        return result
