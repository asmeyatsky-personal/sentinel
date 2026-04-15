"""Logging-based SIEM adapter implementing SIEMIntegrationPort."""

from __future__ import annotations

import structlog

from sentinel.domain.ports.siem import SIEMEvent

logger = structlog.get_logger(__name__)


class LoggingSIEMAdapter:
    """Logs SIEM events via structlog. Production would forward to Chronicle / Splunk."""

    async def send_event(self, event: SIEMEvent) -> None:
        logger.info(
            "siem_event",
            event_type=event.event_type,
            severity=event.severity,
            source=event.source,
            agent_id=event.agent_id,
            description=event.description,
            evidence=event.evidence,
            timestamp=event.timestamp,
        )

    async def send_batch(self, events: list[SIEMEvent]) -> None:
        for event in events:
            await self.send_event(event)
