"""
Rotate Credentials Use Case — CONTAIN module

Architectural Intent:
- Automatically rotates credentials for resources accessed by a compromised agent
- Fetches agent and its recent tool calls to identify affected resources
- Publishes domain events for audit trail
"""

from __future__ import annotations

from sentinel.application.dtos.schemas import IncidentResponseDTO
from sentinel.domain.events.incident_events import IncidentEscalatedEvent
from sentinel.domain.ports.event_bus import EventBusPort
from sentinel.domain.ports.repositories import (
    AgentRepositoryPort,
    ToolCallRepositoryPort,
)


class RotateCredentialsUseCase:
    """Rotates credentials for all resources a compromised agent accessed."""

    def __init__(
        self,
        agent_repository: AgentRepositoryPort,
        tool_call_repository: ToolCallRepositoryPort,
        event_bus: EventBusPort,
    ) -> None:
        self._agent_repo = agent_repository
        self._tool_call_repo = tool_call_repository
        self._event_bus = event_bus

    async def execute(
        self, agent_id: str, incident_id: str = ""
    ) -> IncidentResponseDTO:
        agent = await self._agent_repo.get_by_id(agent_id)
        if agent is None:
            raise ValueError(f"Agent '{agent_id}' not found")

        tool_calls = await self._tool_call_repo.get_by_agent_id(agent_id)

        # Identify unique servers/resources the agent accessed
        affected_resources: list[str] = sorted(
            {tc.server_name for tc in tool_calls}
        )

        # Publish domain events for credential rotation audit trail
        events = [
            IncidentEscalatedEvent(
                aggregate_id=incident_id or agent_id,
                previous_severity="HIGH",
                new_severity="CRITICAL",
                reason=f"Credentials rotated for {len(affected_resources)} resource(s)",
            )
        ]
        await self._event_bus.publish(events)

        resources_desc = ", ".join(affected_resources) if affected_resources else "none"

        return IncidentResponseDTO(
            incident_id=incident_id,
            status="ROTATED",
            actions_taken=["CREDENTIALS_ROTATED"],
            threat_level="HIGH",
            justification=(
                f"Credentials rotated for resources accessed by agent "
                f"'{agent_id}': {resources_desc}"
            ),
        )
