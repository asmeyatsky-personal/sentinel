"""In-memory implementation of ThreatRepositoryPort."""

from __future__ import annotations

from sentinel.domain.entities.threat import Threat, ThreatStatus


class InMemoryThreatRepository:
    """In-memory threat store keyed by threat ID."""

    def __init__(self) -> None:
        self._store: dict[str, Threat] = {}

    async def save(self, threat: Threat) -> None:
        self._store[threat.id] = threat

    async def get_by_id(self, threat_id: str) -> Threat | None:
        return self._store.get(threat_id)

    async def get_by_agent_id(self, agent_id: str) -> list[Threat]:
        return [t for t in self._store.values() if t.agent_id == agent_id]

    async def get_open_threats(self) -> list[Threat]:
        return [
            t for t in self._store.values()
            if t.status in (ThreatStatus.OPEN, ThreatStatus.INVESTIGATING)
        ]
