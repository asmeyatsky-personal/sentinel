"""
Stream to SIEM Use Case — SIGNAL module

Architectural Intent:
- Transforms SENTINEL events into SIEM-compatible SIEMEvent format
- Sends to SIEMIntegrationPort for forwarding to Chronicle, Splunk, Datadog, etc.
- Supports both single event and batch streaming
"""

from __future__ import annotations

from datetime import UTC, datetime

from sentinel.domain.events.base import DomainEvent
from sentinel.domain.ports.siem import SIEMEvent, SIEMIntegrationPort
from sentinel.application.dtos.schemas import GovernanceEventDTO


class StreamToSIEMUseCase:
    """Transforms SENTINEL events into SIEM-compatible format and sends them."""

    def __init__(self, siem_integration: SIEMIntegrationPort) -> None:
        self._siem = siem_integration

    async def execute(
        self,
        event_type: str,
        severity: str,
        agent_id: str,
        description: str,
        evidence: dict | None = None,
    ) -> None:
        siem_event = SIEMEvent(
            event_type=event_type,
            severity=severity,
            source="SENTINEL",
            agent_id=agent_id,
            description=description,
            evidence=evidence or {},
            timestamp=datetime.now(UTC).isoformat(),
        )
        await self._siem.send_event(siem_event)

    async def execute_from_domain_event(self, domain_event: DomainEvent) -> None:
        """Transform a domain event into a SIEM event and send it."""
        event_type_name = type(domain_event).__name__

        severity = self._infer_severity(event_type_name)

        siem_event = SIEMEvent(
            event_type=event_type_name,
            severity=severity,
            source="SENTINEL",
            agent_id=domain_event.aggregate_id,
            description=f"SENTINEL event: {event_type_name}",
            evidence={"event_id": domain_event.event_id},
            timestamp=domain_event.occurred_at.isoformat(),
        )
        await self._siem.send_event(siem_event)

    async def execute_from_governance_event(
        self, governance_event: GovernanceEventDTO
    ) -> None:
        """Transform a governance DTO into a SIEM event and send it."""
        timestamp = (
            governance_event.timestamp.isoformat()
            if governance_event.timestamp
            else datetime.now(UTC).isoformat()
        )
        siem_event = SIEMEvent(
            event_type=governance_event.event_type,
            severity=governance_event.severity,
            source=governance_event.source,
            agent_id=governance_event.agent_id,
            description=governance_event.description,
            evidence=governance_event.evidence,
            timestamp=timestamp,
        )
        await self._siem.send_event(siem_event)

    async def execute_batch(
        self, domain_events: list[DomainEvent]
    ) -> None:
        """Transform and send a batch of domain events to SIEM."""
        siem_events = [
            SIEMEvent(
                event_type=type(evt).__name__,
                severity=self._infer_severity(type(evt).__name__),
                source="SENTINEL",
                agent_id=evt.aggregate_id,
                description=f"SENTINEL event: {type(evt).__name__}",
                evidence={"event_id": evt.event_id},
                timestamp=evt.occurred_at.isoformat(),
            )
            for evt in domain_events
        ]
        await self._siem.send_batch(siem_events)

    # ── Private helpers ──────────────────────────────────────────────────

    @staticmethod
    def _infer_severity(event_type_name: str) -> str:
        name_lower = event_type_name.lower()
        if any(kw in name_lower for kw in ("critical", "escalat", "kill", "terminat")):
            return "CRITICAL"
        if any(kw in name_lower for kw in ("isolat", "block", "exfiltrat", "quarantin")):
            return "HIGH"
        if any(kw in name_lower for kw in ("anomaly", "injection", "violation", "drift")):
            return "MEDIUM"
        return "LOW"
