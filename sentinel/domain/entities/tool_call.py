"""
ToolCall Entity

Represents a captured tool call made by an agent. Core unit of observation
for DETECT, SHIELD, and INTERCEPT modules.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime


@dataclass(frozen=True)
class ToolCall:
    id: str
    agent_id: str
    server_name: str
    tool_name: str
    arguments: dict
    response: dict | None = None
    latency_ms: float = 0.0
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))

    @property
    def full_tool_path(self) -> str:
        return f"{self.server_name}.{self.tool_name}"

    def payload_size_bytes(self) -> int:
        import json
        return len(json.dumps(self.arguments, default=str).encode())

    def has_response(self) -> bool:
        return self.response is not None
