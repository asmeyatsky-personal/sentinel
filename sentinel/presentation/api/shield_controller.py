"""SHIELD module API — Data Leakage Prevention."""

from __future__ import annotations

from typing import Callable

from fastapi import APIRouter
from pydantic import BaseModel

from sentinel.infrastructure.config.dependency_injection import Container


class InspectPayloadRequest(BaseModel):
    agent_id: str
    content: str
    destination: str = ""


class ClassifyDataRequest(BaseModel):
    content: str


class DetectExfiltrationRequest(BaseModel):
    agent_id: str


def create_shield_router(get_container: Callable[[], Container]) -> APIRouter:
    router = APIRouter()

    @router.post("/inspect")
    async def inspect_payload(request: InspectPayloadRequest):
        container = get_container()
        result = await container.inspect_payload.execute(
            agent_id=request.agent_id,
            content=request.content,
            destination=request.destination,
        )
        return result

    @router.post("/classify")
    async def classify_data(request: ClassifyDataRequest):
        container = get_container()
        result = await container.classify_data.execute(request.content)
        return result

    @router.post("/exfiltration")
    async def detect_exfiltration(request: DetectExfiltrationRequest):
        container = get_container()
        result = await container.detect_exfiltration.execute(request.agent_id)
        return result

    return router
