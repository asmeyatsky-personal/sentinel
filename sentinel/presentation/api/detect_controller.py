"""DETECT module API — Anomaly Detection Engine."""

from __future__ import annotations

from typing import Callable

from fastapi import APIRouter
from pydantic import BaseModel

from sentinel.infrastructure.config.dependency_injection import Container


class EvaluateToolCallRequest(BaseModel):
    tool_call_id: str
    agent_id: str
    server_name: str
    tool_name: str
    arguments: dict


class AnalyseTrajectoryRequest(BaseModel):
    agent_id: str


class DetectInjectionRequest(BaseModel):
    content: str
    tool_call_id: str = ""


def create_detect_router(get_container: Callable[[], Container]) -> APIRouter:
    router = APIRouter()

    @router.post("/evaluate")
    async def evaluate_tool_call(request: EvaluateToolCallRequest):
        container = get_container()
        from sentinel.domain.entities.tool_call import ToolCall

        tool_call = ToolCall(
            id=request.tool_call_id,
            agent_id=request.agent_id,
            server_name=request.server_name,
            tool_name=request.tool_name,
            arguments=request.arguments,
        )
        result = await container.evaluate_tool_call.execute(tool_call)
        return result

    @router.post("/trajectory")
    async def analyse_trajectory(request: AnalyseTrajectoryRequest):
        container = get_container()
        result = await container.analyse_trajectory.execute(request.agent_id)
        return result

    @router.post("/injection")
    async def detect_injection(request: DetectInjectionRequest):
        container = get_container()
        result = await container.detect_prompt_injection.execute(
            content=request.content,
            tool_call_id=request.tool_call_id,
        )
        return result

    return router
