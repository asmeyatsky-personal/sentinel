"""
Discover Agents Use Case — RECON module

Architectural Intent:
- Fetches all agents from the repository
- Analyses privilege levels and VAID validity
- Publishes discovery events for new/changed agents
- Returns DTOs for presentation layer consumption
"""

from __future__ import annotations

from sentinel.domain.events.recon_events import (
    AgentDiscoveredEvent,
    OverPrivilegedAgentDetectedEvent,
)
from sentinel.domain.ports.event_bus import EventBusPort
from sentinel.domain.ports.repositories import AgentRepositoryPort
from sentinel.application.dtos.schemas import AgentDTO


class DiscoverAgentsUseCase:
    """Discovers and catalogues all monitored agents with privilege analysis."""

    def __init__(
        self,
        agent_repository: AgentRepositoryPort,
        event_bus: EventBusPort,
    ) -> None:
        self._agent_repo = agent_repository
        self._event_bus = event_bus

    async def execute(self) -> list[AgentDTO]:
        agents = await self._agent_repo.get_all()

        events = []
        results: list[AgentDTO] = []

        for agent in agents:
            events.append(
                AgentDiscoveredEvent(
                    aggregate_id=agent.id,
                    agent_name=agent.name,
                    framework=agent.framework,
                    tool_count=len(agent.registered_tools),
                )
            )

            if agent.is_over_privileged():
                events.append(
                    OverPrivilegedAgentDetectedEvent(
                        aggregate_id=agent.id,
                        tool_count=len(agent.registered_tools),
                        excess_tools=agent.registered_tools[10:],
                    )
                )

            results.append(
                AgentDTO(
                    id=agent.id,
                    name=agent.name,
                    framework=agent.framework,
                    model_id=agent.model_id,
                    status=agent.status.value,
                    registered_tools=list(agent.registered_tools),
                    vaid_agent_id=agent.vaid.agent_id,
                    vaid_capabilities=list(agent.vaid.capabilities),
                    vaid_expired=agent.vaid.is_expired(),
                    is_over_privileged=agent.is_over_privileged(),
                    last_seen_at=agent.last_seen_at,
                )
            )

        if events:
            await self._event_bus.publish(events)

        return results
