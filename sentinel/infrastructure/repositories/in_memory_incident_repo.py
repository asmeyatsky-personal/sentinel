"""In-memory implementation of IncidentRepositoryPort."""

from __future__ import annotations

from sentinel.domain.entities.incident import Incident, IncidentStatus


class InMemoryIncidentRepository:
    """In-memory incident store keyed by incident ID."""

    def __init__(self) -> None:
        self._store: dict[str, Incident] = {}

    async def save(self, incident: Incident) -> None:
        self._store[incident.id] = incident

    async def get_by_id(self, incident_id: str) -> Incident | None:
        return self._store.get(incident_id)

    async def get_active_incidents(self) -> list[Incident]:
        terminal = {IncidentStatus.RESOLVED}
        return [
            i for i in self._store.values()
            if i.status not in terminal
        ]
