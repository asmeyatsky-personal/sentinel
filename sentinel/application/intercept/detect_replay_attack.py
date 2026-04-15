"""
Detect Replay Attack Use Case — INTERCEPT module

Architectural Intent:
- Detects and blocks replay of captured MCP messages
- Maintains an in-memory nonce cache mapping nonce -> monotonic timestamp
- Bounded to 100k entries to prevent unbounded memory growth
- Prunes expired nonces on each call
- Creates Threat with API_ABUSE category when replay detected
"""

from __future__ import annotations

import time
from uuid import uuid4

from sentinel.domain.entities.threat import Threat, ThreatCategory
from sentinel.domain.ports.event_bus import EventBusPort
from sentinel.domain.ports.repositories import ThreatRepositoryPort
from sentinel.domain.value_objects.detection_score import DetectionScore


_MAX_NONCES = 100_000
_DEFAULT_WINDOW_SECONDS = 300.0


class DetectReplayAttackUseCase:
    """Detects replay of captured MCP messages using nonce tracking."""

    def __init__(
        self,
        threat_repository: ThreatRepositoryPort,
        event_bus: EventBusPort,
        window_seconds: float = _DEFAULT_WINDOW_SECONDS,
    ) -> None:
        self._threat_repo = threat_repository
        self._event_bus = event_bus
        self._window_seconds = window_seconds
        self._seen_nonces: dict[str, float] = {}

    def _prune_expired(self, now: float) -> None:
        """Remove nonces older than the replay window."""
        cutoff = now - self._window_seconds
        expired = [n for n, ts in self._seen_nonces.items() if ts < cutoff]
        for n in expired:
            del self._seen_nonces[n]

    async def execute(
        self,
        message_id: str,
        nonce: str,
        agent_id: str = "",
    ) -> dict:
        now = time.monotonic()

        # Prune expired nonces first
        self._prune_expired(now)

        # Check for replay
        if nonce in self._seen_nonces:
            # Replay detected — create threat
            score = DetectionScore(value=85.0)

            threat = Threat(
                id=str(uuid4()),
                agent_id=agent_id,
                category=ThreatCategory.API_ABUSE,
                score=score,
                level=score.to_threat_level(),
                description=(
                    f"Replay attack detected: duplicate nonce '{nonce}' "
                    f"for message '{message_id}'"
                ),
                evidence={
                    "message_id": message_id,
                    "nonce": nonce,
                    "agent_id": agent_id,
                },
                detection_tier=1,
            )

            await self._threat_repo.save(threat)

            return {"is_replay": True, "blocked": True}

        # Record nonce
        self._seen_nonces[nonce] = now

        # Evict oldest entries if cache exceeds max size
        if len(self._seen_nonces) > _MAX_NONCES:
            # Sort by timestamp and keep only the newest entries
            sorted_nonces = sorted(
                self._seen_nonces.items(), key=lambda item: item[1]
            )
            to_remove = len(self._seen_nonces) - _MAX_NONCES
            for key, _ in sorted_nonces[:to_remove]:
                del self._seen_nonces[key]

        return {"is_replay": False, "blocked": False}
