"""MCP observer port — SENTINEL™ registers as MCP observer on the Bus."""

from __future__ import annotations

from typing import Callable, Protocol

from sentinel.domain.entities.tool_call import ToolCall


class MCPObserverPort(Protocol):
    async def start_observing(self) -> None: ...
    async def stop_observing(self) -> None: ...
    async def on_tool_call(self, handler: Callable[[ToolCall], None]) -> None: ...
