"""Tests for DetectReplayAttackUseCase — use case tests with mocked ports."""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from sentinel.application.intercept.detect_replay_attack import (
    DetectReplayAttackUseCase,
)


@pytest.mark.asyncio
class TestDetectReplayAttackUseCase:
    async def test_first_message_allowed(self):
        """First nonce seen is not a replay — message is allowed."""
        threat_repo = AsyncMock()
        event_bus = AsyncMock()

        use_case = DetectReplayAttackUseCase(
            threat_repository=threat_repo,
            event_bus=event_bus,
        )

        result = await use_case.execute(
            message_id="msg-001",
            nonce="nonce-aaa",
            agent_id="agent-1",
        )

        assert result["is_replay"] is False
        assert result["blocked"] is False
        threat_repo.save.assert_not_awaited()

    async def test_duplicate_nonce_blocked(self):
        """Same nonce submitted twice within window is blocked as replay."""
        threat_repo = AsyncMock()
        event_bus = AsyncMock()

        use_case = DetectReplayAttackUseCase(
            threat_repository=threat_repo,
            event_bus=event_bus,
        )

        # First attempt — should pass
        first_result = await use_case.execute(
            message_id="msg-001",
            nonce="nonce-bbb",
            agent_id="agent-1",
        )
        assert first_result["is_replay"] is False

        # Second attempt with same nonce — should be blocked
        second_result = await use_case.execute(
            message_id="msg-002",
            nonce="nonce-bbb",
            agent_id="agent-1",
        )

        assert second_result["is_replay"] is True
        assert second_result["blocked"] is True
        threat_repo.save.assert_awaited_once()

    async def test_expired_nonce_allowed(self):
        """Nonce reuse after the replay window expires is allowed."""
        threat_repo = AsyncMock()
        event_bus = AsyncMock()

        # Use a very short window so nonce expires immediately
        use_case = DetectReplayAttackUseCase(
            threat_repository=threat_repo,
            event_bus=event_bus,
            window_seconds=0.0,
        )

        # First attempt
        first_result = await use_case.execute(
            message_id="msg-001",
            nonce="nonce-ccc",
            agent_id="agent-1",
        )
        assert first_result["is_replay"] is False

        # Second attempt — nonce should have expired (window_seconds=0.0)
        second_result = await use_case.execute(
            message_id="msg-003",
            nonce="nonce-ccc",
            agent_id="agent-1",
        )

        assert second_result["is_replay"] is False
        assert second_result["blocked"] is False
        threat_repo.save.assert_not_awaited()
