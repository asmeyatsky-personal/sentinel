"""Tests for InspectPayloadUseCase — use case tests with mocked ports."""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from sentinel.application.shield.inspect_payload import InspectPayloadUseCase
from sentinel.domain.services.pii_detection import PIIDetectionService


@pytest.mark.asyncio
class TestInspectPayloadUseCase:
    async def test_clean_payload_passes(self):
        pii_service = PIIDetectionService()
        threat_repo = AsyncMock()
        event_bus = AsyncMock()

        use_case = InspectPayloadUseCase(
            pii_detection_service=pii_service,
            threat_repository=threat_repo,
            event_bus=event_bus,
        )

        result = await use_case.execute(
            payload="Hello world, this is clean data",
            agent_id="agent-1",
            destination="internal-api",
        )
        assert result.has_pii is False
        assert result.classification == "PUBLIC"
        threat_repo.save.assert_not_awaited()

    async def test_payload_with_email_detects_pii(self):
        pii_service = PIIDetectionService()
        threat_repo = AsyncMock()
        event_bus = AsyncMock()

        use_case = InspectPayloadUseCase(
            pii_detection_service=pii_service,
            threat_repository=threat_repo,
            event_bus=event_bus,
        )

        result = await use_case.execute(
            payload="User email: john@example.com",
            agent_id="agent-1",
            destination="external-api",
        )
        assert result.has_pii is True
        assert result.classification in ("CONFIDENTIAL", "RESTRICTED")

    async def test_restricted_data_creates_threat(self):
        pii_service = PIIDetectionService()
        threat_repo = AsyncMock()
        event_bus = AsyncMock()

        use_case = InspectPayloadUseCase(
            pii_detection_service=pii_service,
            threat_repository=threat_repo,
            event_bus=event_bus,
        )

        result = await use_case.execute(
            payload="Card: 4111-1111-1111-1111 SSN: 123-45-6789",
            agent_id="agent-1",
            destination="external-api",
        )
        assert result.has_pii is True
        threat_repo.save.assert_awaited_once()
