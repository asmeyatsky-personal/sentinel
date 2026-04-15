"""
Contain Blast Radius Use Case — CONTAIN module

Architectural Intent:
- Identifies all agents in the blast radius of a compromised agent
- Finds shared servers/resources and expands the incident blast radius
- Monitors co-located agents for potential lateral movement
"""

from __future__ import annotations

from sentinel.domain.ports.repositories import (
    AgentRepositoryPort,
    IncidentRepositoryPort,
    ToolCallRepositoryPort,
)
from sentinel.domain.ports.event_bus import EventBusPort


class ContainBlastRadiusUseCase:
    """Identifies and monitors all agents in the blast radius of a compromised agent."""

    def __init__(
        self,
        agent_repository: AgentRepositoryPort,
        tool_call_repository: ToolCallRepositoryPort,
        incident_repository: IncidentRepositoryPort,
        event_bus: EventBusPort,
    ) -> None:
        self._agent_repo = agent_repository
        self._tool_call_repo = tool_call_repository
        self._incident_repo = incident_repository
        self._event_bus = event_bus

    async def execute(
        self, agent_id: str, incident_id: str
    ) -> dict:
        # Fetch the compromised agent's tool call history to find shared servers
        compromised_tool_calls = await self._tool_call_repo.get_by_agent_id(agent_id)
        compromised_servers: set[str] = {
            tc.server_name for tc in compromised_tool_calls
        }

        # Find all other agents that use the same servers (blast radius)
        all_agents = await self._agent_repo.get_all()
        blast_radius_agent_ids: list[str] = []
        shared_resources: set[str] = set()

        for agent in all_agents:
            if agent.id == agent_id:
                continue

            agent_tool_calls = await self._tool_call_repo.get_by_agent_id(agent.id)
            agent_servers = {tc.server_name for tc in agent_tool_calls}

            overlap = compromised_servers & agent_servers
            if overlap:
                blast_radius_agent_ids.append(agent.id)
                shared_resources.update(overlap)

        # Update the incident with expanded blast radius
        incident = await self._incident_repo.get_by_id(incident_id)
        if incident is not None:
            updated_incident = incident.expand_blast_radius(
                tuple(blast_radius_agent_ids)
            )
            await self._incident_repo.save(updated_incident)

        return {
            "blast_radius_agent_ids": blast_radius_agent_ids,
            "shared_resources": sorted(shared_resources),
            "agents_elevated": len(blast_radius_agent_ids),
        }
