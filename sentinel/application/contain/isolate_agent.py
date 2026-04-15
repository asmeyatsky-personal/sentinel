"""
Isolate Agent Use Case — CONTAIN module

Architectural Intent:
- Executes agent isolation as a containment response
- Fetches agent, calls agent.isolate() (domain method)
- Persists the isolated agent state
- Publishes domain events from the agent aggregate
- Publishes AgentIsolationExecutedEvent for audit trail
"""

from __future__ import annotations

from sentinel.domain.events.incident_events import AgentIsolationExecutedEvent
from sentinel.domain.ports.event_bus import EventBusPort
from sentinel.domain.ports.repositories import AgentRepositoryPort
from sentinel.application.dtos.schemas import IncidentResponseDTO


class IsolateAgentUseCase:
    """Isolates an agent as a containment response."""

    def __init__(
        self,
        agent_repository: AgentRepositoryPort,
        event_bus: EventBusPort,
    ) -> None:
        self._agent_repo = agent_repository
        self._event_bus = event_bus

    async def execute(
        self, agent_id: str, reason: str, incident_id: str = ""
    ) -> IncidentResponseDTO:
        agent = await self._agent_repo.get_by_id(agent_id)
        if agent is None:
            raise ValueError(f"Agent '{agent_id}' not found")

        # Domain method enforces state machine rules
        isolated_agent = agent.isolate(reason)

        await self._agent_repo.save(isolated_agent)

        # Publish domain events from the aggregate + containment event
        events = list(isolated_agent.domain_events)
        events.append(
            AgentIsolationExecutedEvent(
                aggregate_id=agent_id,
                target_agent_id=agent_id,
                incident_id=incident_id,
            )
        )
        await self._event_bus.publish(events)

        return IncidentResponseDTO(
            incident_id=incident_id,
            status="ISOLATED",
            actions_taken=["AGENT_ISOLATED"],
            threat_level="HIGH",
            justification=f"Agent '{agent_id}' isolated: {reason}",
        )
