"""
Map Dependencies Use Case — RECON module

Architectural Intent:
- Maps agent dependencies showing blast radius for any compromise
- Builds adjacency graph: agent -> set of servers it uses
- Calculates blast radius: agents sharing the same servers
- Identifies single points of failure (servers used by >3 agents)
"""

from __future__ import annotations

from collections import defaultdict

from sentinel.domain.ports.repositories import (
    AgentRepositoryPort,
    ToolCallRepositoryPort,
)


class MapDependenciesUseCase:
    """Maps agent dependencies showing blast radius for any compromise."""

    def __init__(
        self,
        agent_repository: AgentRepositoryPort,
        tool_call_repository: ToolCallRepositoryPort,
    ) -> None:
        self._agent_repo = agent_repository
        self._tool_call_repo = tool_call_repository

    async def execute(self) -> dict:
        all_agents = await self._agent_repo.get_all()
        tool_calls = await self._tool_call_repo.get_recent(limit=100)

        # Build adjacency graph: agent_id -> set of server names
        # Seed with all registered agents so they appear even without tool calls
        agent_to_servers: dict[str, set[str]] = defaultdict(set)
        for agent_id in (a.id for a in all_agents):
            agent_to_servers.setdefault(agent_id, set())
        for tc in tool_calls:
            agent_to_servers[tc.agent_id].add(tc.server_name)

        # Build reverse map: server_name -> set of agent_ids
        server_to_agents: dict[str, set[str]] = defaultdict(set)
        for agent_id, servers in agent_to_servers.items():
            for server in servers:
                server_to_agents[server].add(agent_id)

        # Dependency graph: agent_id -> list of server names
        dependency_graph: dict[str, list[str]] = {
            agent_id: sorted(servers)
            for agent_id, servers in agent_to_servers.items()
        }

        # Blast radius: for each agent, find other agents sharing the same servers
        blast_radius: dict[str, list[str]] = {}
        for agent_id, servers in agent_to_servers.items():
            affected: set[str] = set()
            for server in servers:
                affected.update(server_to_agents[server])
            affected.discard(agent_id)
            blast_radius[agent_id] = sorted(affected)

        # Single points of failure: servers used by >3 agents
        single_points_of_failure: list[str] = sorted(
            server
            for server, agent_ids in server_to_agents.items()
            if len(agent_ids) > 3
        )

        return {
            "dependency_graph": dependency_graph,
            "blast_radius": blast_radius,
            "single_points_of_failure": single_points_of_failure,
        }
