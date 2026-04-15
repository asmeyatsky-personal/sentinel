"""Tests for InspectModelAPIPayloadUseCase — use case tests with mocked ports."""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from sentinel.application.shield.inspect_model_api import InspectModelAPIPayloadUseCase
from sentinel.domain.services.pii_detection import PIIDetectionService


@pytest.mark.asyncio
class TestInspectModelAPIPayloadUseCase:
    async def test_clean_payload_to_model_api(self):
        """No PII in payload to Anthropic API — no threat created."""
        pii_service = PIIDetectionService()
        threat_repo = AsyncMock()
        event_bus = AsyncMock()

        use_case = InspectModelAPIPayloadUseCase(
            pii_detection_service=pii_service,
            threat_repository=threat_repo,
            event_bus=event_bus,
        )

        result = await use_case.execute(
            payload="Summarise the quarterly earnings report",
            destination="api.anthropic.com",
            agent_id="agent-1",
        )

        assert result.has_pii is False
        assert result.classification == "PUBLIC"
        assert result.threat_id is None
        threat_repo.save.assert_not_awaited()
        event_bus.publish.assert_not_awaited()

    async def test_pii_detected_in_model_api_payload(self):
        """Email in payload to api.anthropic.com triggers PII detection and threat."""
        pii_service = PIIDetectionService()
        threat_repo = AsyncMock()
        event_bus = AsyncMock()

        use_case = InspectModelAPIPayloadUseCase(
            pii_detection_service=pii_service,
            threat_repository=threat_repo,
            event_bus=event_bus,
        )

        result = await use_case.execute(
            payload="Forward this to john.doe@example.com please",
            destination="api.anthropic.com",
            agent_id="agent-2",
        )

        assert result.has_pii is True
        assert result.classification in ("CONFIDENTIAL", "RESTRICTED")
        assert len(result.matches) >= 1
        assert any(m.pii_type == "email_address" for m in result.matches)
        assert result.threat_id is not None
        threat_repo.save.assert_awaited_once()
        event_bus.publish.assert_awaited_once()

    async def test_non_model_api_skips_deep_scan(self):
        """Payload to an internal API returns no detection — scan is skipped."""
        pii_service = PIIDetectionService()
        threat_repo = AsyncMock()
        event_bus = AsyncMock()

        use_case = InspectModelAPIPayloadUseCase(
            pii_detection_service=pii_service,
            threat_repository=threat_repo,
            event_bus=event_bus,
        )

        result = await use_case.execute(
            payload="User email: secret@corp.internal with SSN 123-45-6789",
            destination="internal.mycompany.com",
            agent_id="agent-3",
        )

        assert result.has_pii is False
        assert result.classification == "PUBLIC"
        assert result.threat_id is None
        threat_repo.save.assert_not_awaited()
        event_bus.publish.assert_not_awaited()
