"""
Block Tool Call Use Case — CONTAIN module

Architectural Intent:
- Selectively blocks specific tool calls as containment response
- Creates an Incident record linking to the blocked call
- Publishes ToolCallBlockedEvent for audit trail
"""

from __future__ import annotations

from uuid import uuid4

from sentinel.domain.entities.incident import Incident, IncidentStatus, ResponseAction
from sentinel.domain.events.incident_events import ToolCallBlockedEvent
from sentinel.domain.ports.event_bus import EventBusPort
from sentinel.domain.ports.repositories import IncidentRepositoryPort
from sentinel.domain.value_objects.threat_level import ThreatLevel
from sentinel.domain.entities.tool_call import ToolCall
from sentinel.application.dtos.schemas import IncidentResponseDTO


class BlockToolCallUseCase:
    """Selectively blocks a tool call and creates an incident record."""

    def __init__(
        self,
        incident_repository: IncidentRepositoryPort,
        event_bus: EventBusPort,
    ) -> None:
        self._incident_repo = incident_repository
        self._event_bus = event_bus

    async def execute(
        self,
        tool_call: ToolCall,
        reason: str,
        threat_id: str = "",
        severity: ThreatLevel = ThreatLevel.HIGH,
    ) -> IncidentResponseDTO:
        # Create incident for the blocked call
        incident = Incident(
            id=str(uuid4()),
            threat_ids=(threat_id,) if threat_id else (),
            affected_agent_ids=(tool_call.agent_id,),
            severity=severity,
            status=IncidentStatus.CONTAINING,
            actions_taken=(ResponseAction.TOOL_BLOCKED,),
        )

        await self._incident_repo.save(incident)

        await self._event_bus.publish([
            ToolCallBlockedEvent(
                aggregate_id=incident.id,
                tool_call_id=tool_call.id,
                tool_name=tool_call.full_tool_path,
                reason=reason,
            ),
        ])

        return IncidentResponseDTO(
            incident_id=incident.id,
            status=incident.status.value,
            actions_taken=[a.value for a in incident.actions_taken],
            threat_level=severity.value,
            justification=(
                f"Blocked tool call '{tool_call.full_tool_path}' "
                f"for agent '{tool_call.agent_id}': {reason}"
            ),
        )
