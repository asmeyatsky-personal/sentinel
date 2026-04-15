"""In-memory implementation of MCPServerRepositoryPort."""

from __future__ import annotations

from sentinel.domain.entities.mcp_server import MCPServer


class InMemoryMCPServerRepository:
    """In-memory MCP server store keyed by server ID."""

    def __init__(self) -> None:
        self._store: dict[str, MCPServer] = {}

    async def save(self, server: MCPServer) -> None:
        self._store[server.id] = server

    async def get_by_id(self, server_id: str) -> MCPServer | None:
        return self._store.get(server_id)

    async def get_all(self) -> list[MCPServer]:
        return list(self._store.values())
