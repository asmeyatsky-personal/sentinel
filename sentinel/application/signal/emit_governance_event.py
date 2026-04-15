"""
Emit Governance Event Use Case — SIGNAL module

Architectural Intent:
- Transforms SENTINEL domain events into CODEX governance events
- Provides a unified event format for external governance consumers
- Publishes transformed events to the event bus
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

from sentinel.domain.events.base import DomainEvent
from sentinel.domain.events.base import DomainEvent as _BaseDomainEvent
from sentinel.domain.ports.event_bus import EventBusPort
from sentinel.application.dtos.schemas import GovernanceEventDTO


@dataclass(frozen=True)
class _GovernanceEmittedEvent(_BaseDomainEvent):
    event_type: str = ""
    severity: str = ""


class EmitGovernanceEventUseCase:
    """Transforms SENTINEL events into CODEX governance events."""

    def __init__(self, event_bus: EventBusPort) -> None:
        self._event_bus = event_bus

    async def execute(
        self,
        event_type: str,
        agent_id: str = "",
        severity: str = "LOW",
        description: str = "",
        evidence: dict | None = None,
    ) -> GovernanceEventDTO:
        governance_event = GovernanceEventDTO(
            event_type=event_type,
            source="SENTINEL",
            agent_id=agent_id,
            severity=severity,
            description=description,
            evidence=evidence or {},
            timestamp=datetime.now(UTC),
        )

        # Wrap as a domain event for bus publication
        domain_event = _GovernanceEmittedEvent(
            aggregate_id=agent_id or "SENTINEL",
            event_type=event_type,
            severity=severity,
        )

        await self._event_bus.publish([domain_event])

        return governance_event

    async def execute_from_domain_event(
        self, domain_event: DomainEvent
    ) -> GovernanceEventDTO:
        """Convenience method to transform and emit from an existing domain event."""
        event_type_name = type(domain_event).__name__

        # Determine severity from event type heuristics
        severity = "LOW"
        name_lower = event_type_name.lower()
        if any(kw in name_lower for kw in ("critical", "escalat", "kill")):
            severity = "CRITICAL"
        elif any(kw in name_lower for kw in ("isolat", "block", "exfiltrat")):
            severity = "HIGH"
        elif any(kw in name_lower for kw in ("anomaly", "injection", "violation")):
            severity = "MEDIUM"

        return await self.execute(
            event_type=event_type_name,
            agent_id=domain_event.aggregate_id,
            severity=severity,
            description=f"Governance event from {event_type_name}",
            evidence={"event_id": domain_event.event_id},
        )
