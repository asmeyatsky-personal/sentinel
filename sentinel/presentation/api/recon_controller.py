"""RECON module API — Attack Surface Discovery."""

from __future__ import annotations

from typing import Callable

from fastapi import APIRouter

from sentinel.infrastructure.config.dependency_injection import Container


def create_recon_router(get_container: Callable[[], Container]) -> APIRouter:
    router = APIRouter()

    @router.get("/agents")
    async def discover_agents():
        container = get_container()
        result = await container.discover_agents.execute()
        return result

    @router.get("/mcp-servers")
    async def enumerate_mcp_servers():
        container = get_container()
        result = await container.enumerate_mcp_servers.execute()
        return result

    @router.get("/permissions")
    async def audit_permissions():
        container = get_container()
        result = await container.audit_permissions.execute()
        return result

    return router
