"""INTERCEPT module API — API Abuse Detection & Rate Defence."""

from __future__ import annotations

from typing import Callable

from fastapi import APIRouter
from pydantic import BaseModel

from sentinel.infrastructure.config.dependency_injection import Container


class RateLimitCheckRequest(BaseModel):
    agent_id: str
    tool_name: str


class ValidateMCPRequest(BaseModel):
    message: dict


class CostAnomalyRequest(BaseModel):
    agent_id: str
    current_cost: float


def create_intercept_router(get_container: Callable[[], Container]) -> APIRouter:
    router = APIRouter()

    @router.post("/rate-limit")
    async def check_rate_limit(request: RateLimitCheckRequest):
        container = get_container()
        result = await container.enforce_rate_limit.execute(
            agent_id=request.agent_id,
            tool_name=request.tool_name,
        )
        return result

    @router.post("/validate-mcp")
    async def validate_mcp(request: ValidateMCPRequest):
        container = get_container()
        result = await container.validate_mcp_protocol.execute(request.message)
        return result

    @router.post("/cost-anomaly")
    async def detect_cost_anomaly(request: CostAnomalyRequest):
        container = get_container()
        result = await container.detect_cost_anomaly.execute(
            agent_id=request.agent_id,
            current_cost=request.current_cost,
        )
        return result

    return router
