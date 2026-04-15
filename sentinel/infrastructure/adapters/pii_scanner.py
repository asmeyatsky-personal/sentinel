"""Infrastructure adapter implementing PIIDetectorPort using the domain PIIDetectionService."""

from __future__ import annotations

import re

from sentinel.domain.ports.detection import PIIMatch
from sentinel.domain.services.pii_detection import PIIDetectionService


class PIIScanner:
    """Wraps the domain PIIDetectionService to satisfy the PIIDetectorPort interface."""

    def __init__(self, pii_service: PIIDetectionService | None = None) -> None:
        self._service = pii_service or PIIDetectionService()

    async def scan(self, content: str) -> list[PIIMatch]:
        matches: list[PIIMatch] = []
        for pattern, compiled in self._service._compiled:
            for m in compiled.finditer(content):
                matches.append(
                    PIIMatch(
                        pii_type=pattern.name,
                        value=m.group(),
                        start=m.start(),
                        end=m.end(),
                    )
                )
        return matches

    async def redact(self, content: str) -> str:
        return self._service.redact(content)
