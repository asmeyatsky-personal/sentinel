"""
Stream Multi-SIEM Use Case — SIGNAL module

Architectural Intent:
- Streams events to multiple SIEM targets simultaneously
- Uses asyncio.gather for concurrent delivery to all adapters
- Tracks successes and failures per adapter
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime

from sentinel.domain.ports.repositories import ThreatRepositoryPort
from sentinel.domain.ports.siem import SIEMEvent, SIEMIntegrationPort


class StreamMultiSIEMUseCase:
    """Streams threat events to multiple SIEM targets concurrently."""

    def __init__(
        self,
        siem_adapters: dict[str, SIEMIntegrationPort],
        threat_repository: ThreatRepositoryPort,
    ) -> None:
        self._siem_adapters = siem_adapters
        self._threat_repo = threat_repository

    async def execute(self, threat_id: str) -> dict:
        threat = await self._threat_repo.get_by_id(threat_id)
        if threat is None:
            raise ValueError(f"Threat '{threat_id}' not found")

        # Transform threat to SIEMEvent
        siem_event = SIEMEvent(
            event_type=threat.category.value,
            severity=threat.level.value,
            source="SENTINEL",
            agent_id=threat.agent_id,
            description=threat.description,
            evidence=threat.evidence,
            timestamp=datetime.now(UTC).isoformat(),
        )

        # Send to ALL adapters concurrently
        sent_to: list[str] = []
        failures: list[str] = []

        async def _send(name: str, adapter: SIEMIntegrationPort) -> None:
            try:
                await adapter.send_event(siem_event)
                sent_to.append(name)
            except Exception:  # noqa: BLE001
                failures.append(name)

        await asyncio.gather(
            *[
                _send(name, adapter)
                for name, adapter in self._siem_adapters.items()
            ]
        )

        return {
            "sent_to": sent_to,
            "failures": failures,
        }
