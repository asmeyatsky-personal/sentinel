"""In-memory implementation of ToolCallRepositoryPort."""

from __future__ import annotations

from sentinel.domain.entities.tool_call import ToolCall


class InMemoryToolCallRepository:
    """In-memory tool-call store with ordered insertion tracking."""

    def __init__(self) -> None:
        self._store: dict[str, ToolCall] = {}
        self._insertion_order: list[str] = []

    async def save(self, tool_call: ToolCall) -> None:
        if tool_call.id not in self._store:
            self._insertion_order.append(tool_call.id)
        self._store[tool_call.id] = tool_call

    async def get_by_agent_id(self, agent_id: str, limit: int = 100) -> list[ToolCall]:
        matching = [
            self._store[tc_id]
            for tc_id in reversed(self._insertion_order)
            if self._store[tc_id].agent_id == agent_id
        ]
        return matching[:limit]

    async def get_recent(self, limit: int = 100) -> list[ToolCall]:
        recent_ids = self._insertion_order[-limit:] if limit else self._insertion_order
        return [self._store[tc_id] for tc_id in reversed(recent_ids)]
