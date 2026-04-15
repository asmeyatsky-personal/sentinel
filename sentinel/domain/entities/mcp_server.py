"""
MCPServer Entity

Represents a discovered MCP server in the agent estate. Tracked by RECON module.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum


class MCPServerStatus(Enum):
    ACTIVE = "ACTIVE"
    DEGRADED = "DEGRADED"
    UNREACHABLE = "UNREACHABLE"
    SHADOW = "SHADOW"


@dataclass(frozen=True)
class MCPServerTool:
    name: str
    description: str
    input_schema: dict


@dataclass(frozen=True)
class MCPServer:
    id: str
    name: str
    transport: str
    endpoint: str
    tools: tuple[MCPServerTool, ...]
    status: MCPServerStatus = MCPServerStatus.ACTIVE
    auth_required: bool = False
    discovered_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    last_scanned_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    @property
    def tool_count(self) -> int:
        return len(self.tools)

    def tool_names(self) -> tuple[str, ...]:
        return tuple(t.name for t in self.tools)

    def is_shadow(self) -> bool:
        return self.status is MCPServerStatus.SHADOW

    def is_exposed(self) -> bool:
        return not self.auth_required
