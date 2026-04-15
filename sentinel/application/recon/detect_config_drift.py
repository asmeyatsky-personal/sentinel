"""
Detect Configuration Drift Use Case — RECON module

Architectural Intent:
- Detects changes to agent configurations and MCP server definitions between scans
- Maintains snapshots of previous scans for comparison
- Publishes ConfigurationDriftDetectedEvent when drift is detected
- Returns structured drift report for presentation layer consumption
"""

from __future__ import annotations

from sentinel.domain.events.recon_events import ConfigurationDriftDetectedEvent
from sentinel.domain.ports.event_bus import EventBusPort
from sentinel.domain.ports.repositories import (
    AgentRepositoryPort,
    MCPServerRepositoryPort,
)

_MAX_SNAPSHOT_ENTRIES = 10_000


class DetectConfigDriftUseCase:
    """Detects changes to agent configurations and MCP server definitions between scans."""

    def __init__(
        self,
        agent_repository: AgentRepositoryPort,
        mcp_server_repository: MCPServerRepositoryPort,
        event_bus: EventBusPort,
    ) -> None:
        self._agent_repo = agent_repository
        self._mcp_server_repo = mcp_server_repository
        self._event_bus = event_bus
        self._previous_agents: dict[str, tuple] = {}
        self._previous_servers: dict[str, tuple] = {}

    async def execute(self) -> dict:
        agents = await self._agent_repo.get_all()
        servers = await self._mcp_server_repo.get_all()

        current_agents: dict[str, tuple] = {
            agent.id: agent.registered_tools for agent in agents
        }
        current_servers: dict[str, tuple] = {
            server.id: server.tool_names() for server in servers
        }

        changes: list[dict] = []
        events: list[ConfigurationDriftDetectedEvent] = []

        # --- agent drift ---
        if self._previous_agents:
            previous_ids = set(self._previous_agents)
            current_ids = set(current_agents)

            for agent_id in current_ids - previous_ids:
                change = {
                    "type": "new_agent",
                    "resource_type": "agent",
                    "resource_id": agent_id,
                }
                changes.append(change)
                events.append(
                    ConfigurationDriftDetectedEvent(
                        aggregate_id=agent_id,
                        resource_type="agent",
                        resource_id=agent_id,
                        changes=("new_agent",),
                    )
                )

            for agent_id in previous_ids - current_ids:
                change = {
                    "type": "removed_agent",
                    "resource_type": "agent",
                    "resource_id": agent_id,
                }
                changes.append(change)
                events.append(
                    ConfigurationDriftDetectedEvent(
                        aggregate_id=agent_id,
                        resource_type="agent",
                        resource_id=agent_id,
                        changes=("removed_agent",),
                    )
                )

            for agent_id in current_ids & previous_ids:
                if current_agents[agent_id] != self._previous_agents[agent_id]:
                    change = {
                        "type": "tool_change",
                        "resource_type": "agent",
                        "resource_id": agent_id,
                        "previous_tools": list(self._previous_agents[agent_id]),
                        "current_tools": list(current_agents[agent_id]),
                    }
                    changes.append(change)
                    events.append(
                        ConfigurationDriftDetectedEvent(
                            aggregate_id=agent_id,
                            resource_type="agent",
                            resource_id=agent_id,
                            changes=("tool_change",),
                        )
                    )

        # --- MCP server drift ---
        if self._previous_servers:
            previous_ids = set(self._previous_servers)
            current_ids = set(current_servers)

            for server_id in current_ids - previous_ids:
                change = {
                    "type": "new_server",
                    "resource_type": "mcp_server",
                    "resource_id": server_id,
                }
                changes.append(change)
                events.append(
                    ConfigurationDriftDetectedEvent(
                        aggregate_id=server_id,
                        resource_type="mcp_server",
                        resource_id=server_id,
                        changes=("new_server",),
                    )
                )

            for server_id in previous_ids - current_ids:
                change = {
                    "type": "removed_server",
                    "resource_type": "mcp_server",
                    "resource_id": server_id,
                }
                changes.append(change)
                events.append(
                    ConfigurationDriftDetectedEvent(
                        aggregate_id=server_id,
                        resource_type="mcp_server",
                        resource_id=server_id,
                        changes=("removed_server",),
                    )
                )

            for server_id in current_ids & previous_ids:
                if current_servers[server_id] != self._previous_servers[server_id]:
                    change = {
                        "type": "server_tool_change",
                        "resource_type": "mcp_server",
                        "resource_id": server_id,
                        "previous_tools": list(self._previous_servers[server_id]),
                        "current_tools": list(current_servers[server_id]),
                    }
                    changes.append(change)
                    events.append(
                        ConfigurationDriftDetectedEvent(
                            aggregate_id=server_id,
                            resource_type="mcp_server",
                            resource_id=server_id,
                            changes=("server_tool_change",),
                        )
                    )

        # Publish drift events
        if events:
            await self._event_bus.publish(events)

        # Update snapshots, bounded to max entries
        self._previous_agents = dict(list(current_agents.items())[:_MAX_SNAPSHOT_ENTRIES])
        self._previous_servers = dict(list(current_servers.items())[:_MAX_SNAPSHOT_ENTRIES])

        return {
            "changes": changes,
            "drift_detected": len(changes) > 0,
        }
