"""In-memory implementation of AgentRepositoryPort."""

from __future__ import annotations

from sentinel.domain.entities.agent import Agent


class InMemoryAgentRepository:
    """Thread-safe in-memory agent store keyed by agent ID."""

    def __init__(self) -> None:
        self._store: dict[str, Agent] = {}

    async def save(self, agent: Agent) -> None:
        self._store[agent.id] = agent

    async def get_by_id(self, agent_id: str) -> Agent | None:
        return self._store.get(agent_id)

    async def get_all(self) -> list[Agent]:
        return list(self._store.values())

    async def delete(self, agent_id: str) -> None:
        self._store.pop(agent_id, None)
