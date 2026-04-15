"""CONTAIN module API — Automated Incident Response."""

from __future__ import annotations

from typing import Callable

from fastapi import APIRouter
from pydantic import BaseModel

from sentinel.infrastructure.config.dependency_injection import Container


class IsolateAgentRequest(BaseModel):
    agent_id: str
    reason: str


class BlockToolCallRequest(BaseModel):
    agent_id: str
    tool_name: str
    reason: str


class ForensicBundleRequest(BaseModel):
    incident_id: str


def create_contain_router(get_container: Callable[[], Container]) -> APIRouter:
    router = APIRouter()

    @router.post("/isolate")
    async def isolate_agent(request: IsolateAgentRequest):
        container = get_container()
        result = await container.isolate_agent.execute(
            agent_id=request.agent_id,
            reason=request.reason,
        )
        return result

    @router.post("/block-tool")
    async def block_tool_call(request: BlockToolCallRequest):
        container = get_container()
        result = await container.block_tool_call.execute(
            agent_id=request.agent_id,
            tool_name=request.tool_name,
            reason=request.reason,
        )
        return result

    @router.post("/forensic-bundle")
    async def generate_forensic_bundle(request: ForensicBundleRequest):
        container = get_container()
        result = await container.generate_forensic_bundle.execute(request.incident_id)
        return result

    return router
