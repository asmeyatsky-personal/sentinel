"""
Enumerate MCP Servers Use Case — RECON module

Architectural Intent:
- Inventories all known MCP servers in the estate
- Analyses exposure (unauthenticated, shadow servers)
- Publishes discovery events for each server
- Returns DTOs with exposure analysis
"""

from __future__ import annotations

from sentinel.domain.events.recon_events import MCPServerDiscoveredEvent
from sentinel.domain.ports.event_bus import EventBusPort
from sentinel.domain.ports.repositories import MCPServerRepositoryPort
from sentinel.application.dtos.schemas import MCPServerDTO, MCPServerToolDTO


class EnumerateMCPServersUseCase:
    """Returns inventory of MCP servers with exposure analysis."""

    def __init__(
        self,
        mcp_server_repository: MCPServerRepositoryPort,
        event_bus: EventBusPort,
    ) -> None:
        self._mcp_repo = mcp_server_repository
        self._event_bus = event_bus

    async def execute(self) -> list[MCPServerDTO]:
        servers = await self._mcp_repo.get_all()

        events = []
        results: list[MCPServerDTO] = []

        for server in servers:
            events.append(
                MCPServerDiscoveredEvent(
                    aggregate_id=server.id,
                    server_name=server.name,
                    tool_count=server.tool_count,
                    is_exposed=server.is_exposed(),
                )
            )

            results.append(
                MCPServerDTO(
                    id=server.id,
                    name=server.name,
                    transport=server.transport,
                    endpoint=server.endpoint,
                    status=server.status.value,
                    auth_required=server.auth_required,
                    tools=[
                        MCPServerToolDTO(
                            name=t.name,
                            description=t.description,
                            input_schema=t.input_schema,
                        )
                        for t in server.tools
                    ],
                    tool_count=server.tool_count,
                    is_exposed=server.is_exposed(),
                    is_shadow=server.is_shadow(),
                    discovered_at=server.discovered_at,
                    last_scanned_at=server.last_scanned_at,
                )
            )

        if events:
            await self._event_bus.publish(events)

        return results
