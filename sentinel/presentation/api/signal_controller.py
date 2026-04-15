"""SIGNAL module API — Governance Event Feed."""

from __future__ import annotations

from typing import Callable

from fastapi import APIRouter
from pydantic import BaseModel

from sentinel.infrastructure.config.dependency_injection import Container


class GovernanceEventRequest(BaseModel):
    threat_id: str


class SIEMStreamRequest(BaseModel):
    threat_id: str


def create_signal_router(get_container: Callable[[], Container]) -> APIRouter:
    router = APIRouter()

    @router.post("/governance")
    async def emit_governance_event(request: GovernanceEventRequest):
        container = get_container()
        result = await container.emit_governance_event.execute(request.threat_id)
        return result

    @router.post("/siem")
    async def stream_to_siem(request: SIEMStreamRequest):
        container = get_container()
        result = await container.stream_to_siem.execute(request.threat_id)
        return result

    @router.get("/threats")
    async def list_threats():
        container = get_container()
        threats = await container.threat_repo.get_open_threats()
        return [
            {
                "id": t.id,
                "agent_id": t.agent_id,
                "category": t.category.value,
                "level": t.level.value,
                "score": t.score.value,
                "status": t.status.value,
            }
            for t in threats
        ]

    @router.get("/incidents")
    async def list_incidents():
        container = get_container()
        incidents = await container.incident_repo.get_active_incidents()
        return [
            {
                "id": i.id,
                "severity": i.severity.value,
                "status": i.status.value,
                "affected_agents": i.affected_agent_ids,
                "actions_taken": [a.value for a in i.actions_taken],
            }
            for i in incidents
        ]

    return router
