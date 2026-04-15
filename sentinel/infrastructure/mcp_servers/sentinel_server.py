"""SENTINEL MCP Server — exposes SENTINEL capabilities over the MCP protocol.

Uses the ``mcp`` Python SDK (FastMCP) to register tools and resources that
allow external agents and operators to query threat posture, investigate
agents, and trigger containment actions.

Usage::

    container = create_container()
    server = create_sentinel_mcp_server(container)
    server.run()  # stdio transport by default
"""

from __future__ import annotations

import json
from typing import Any

from mcp.server.fastmcp import FastMCP


def create_sentinel_mcp_server(container: Any) -> FastMCP:
    """Build and return a configured SENTINEL MCP server.

    Parameters
    ----------
    container:
        Dependency-injection container exposing repository and adapter
        instances (see ``sentinel.infrastructure.config.dependency_injection``).
    """

    server = FastMCP(
        "SENTINEL",
        instructions=(
            "SENTINEL is an agentic security platform. "
            "Use these tools to monitor agent behaviour, investigate threats, "
            "and trigger containment actions."
        ),
    )

    # ------------------------------------------------------------------
    # Tools
    # ------------------------------------------------------------------

    @server.tool(name="sentinel.status", description="Return current threat posture summary.")
    async def status() -> str:
        agents = await container.agent_repository.get_all()
        threats = await container.threat_repository.get_open_threats()
        incidents = await container.incident_repository.get_active_incidents()

        active_agents = [a for a in agents if a.status.value == "ACTIVE"]
        isolated_agents = [a for a in agents if a.status.value == "ISOLATED"]

        posture = {
            "total_agents": len(agents),
            "active_agents": len(active_agents),
            "isolated_agents": len(isolated_agents),
            "open_threats": len(threats),
            "active_incidents": len(incidents),
            "threat_breakdown": _threat_breakdown(threats),
        }
        return json.dumps(posture, indent=2, default=str)

    @server.tool(
        name="sentinel.investigate",
        description="Investigate a specific agent by ID. Returns agent details, recent threats, and tool call history.",
    )
    async def investigate(agent_id: str) -> str:
        agent = await container.agent_repository.get_by_id(agent_id)
        if agent is None:
            return json.dumps({"error": f"Agent {agent_id} not found"})

        threats = await container.threat_repository.get_by_agent_id(agent_id)
        tool_calls = await container.tool_call_repository.get_by_agent_id(agent_id, limit=20)

        result = {
            "agent": {
                "id": agent.id,
                "name": agent.name,
                "framework": agent.framework,
                "model_id": agent.model_id,
                "status": agent.status.value,
                "registered_tools": list(agent.registered_tools),
                "last_seen_at": str(agent.last_seen_at),
            },
            "threats": [
                {
                    "id": t.id,
                    "category": t.category.value,
                    "level": t.level.value,
                    "status": t.status.value,
                    "score": t.score.value,
                    "description": t.description,
                }
                for t in threats
            ],
            "recent_tool_calls": [
                {
                    "id": tc.id,
                    "tool": tc.full_tool_path,
                    "timestamp": str(tc.timestamp),
                }
                for tc in tool_calls
            ],
        }
        return json.dumps(result, indent=2, default=str)

    @server.tool(
        name="sentinel.isolate",
        description="Isolate an agent by ID, preventing further tool calls.",
    )
    async def isolate(agent_id: str, reason: str = "Manual isolation via MCP") -> str:
        agent = await container.agent_repository.get_by_id(agent_id)
        if agent is None:
            return json.dumps({"error": f"Agent {agent_id} not found"})

        try:
            isolated_agent = agent.isolate(reason)
        except ValueError as exc:
            return json.dumps({"error": str(exc)})

        await container.agent_repository.save(isolated_agent)

        # Publish domain events if event bus is available
        if isolated_agent.domain_events:
            await container.event_bus.publish(list(isolated_agent.domain_events))

        return json.dumps({
            "status": "isolated",
            "agent_id": agent_id,
            "reason": reason,
        })

    @server.tool(
        name="sentinel.threats",
        description="List all open (unresolved) threats.",
    )
    async def threats() -> str:
        open_threats = await container.threat_repository.get_open_threats()
        result = [
            {
                "id": t.id,
                "agent_id": t.agent_id,
                "category": t.category.value,
                "level": t.level.value,
                "status": t.status.value,
                "score": t.score.value,
                "description": t.description,
                "detected_at": str(t.detected_at),
            }
            for t in open_threats
        ]
        return json.dumps(result, indent=2, default=str)

    # ------------------------------------------------------------------
    # Resources
    # ------------------------------------------------------------------

    @server.resource(
        uri="sentinel://agents",
        name="Monitored Agents",
        description="List of all agents currently monitored by SENTINEL.",
    )
    async def agents_resource() -> str:
        agents = await container.agent_repository.get_all()
        data = [
            {
                "id": a.id,
                "name": a.name,
                "status": a.status.value,
                "framework": a.framework,
                "tool_count": len(a.registered_tools),
                "last_seen_at": str(a.last_seen_at),
            }
            for a in agents
        ]
        return json.dumps(data, indent=2, default=str)

    @server.resource(
        uri="sentinel://threats",
        name="Open Threats",
        description="List of all currently open threats.",
    )
    async def threats_resource() -> str:
        open_threats = await container.threat_repository.get_open_threats()
        data = [
            {
                "id": t.id,
                "agent_id": t.agent_id,
                "category": t.category.value,
                "level": t.level.value,
                "score": t.score.value,
                "detected_at": str(t.detected_at),
            }
            for t in open_threats
        ]
        return json.dumps(data, indent=2, default=str)

    return server


def _threat_breakdown(threats: list) -> dict[str, int]:
    """Count threats grouped by level."""
    breakdown: dict[str, int] = {}
    for t in threats:
        level = t.level.value
        breakdown[level] = breakdown.get(level, 0) + 1
    return breakdown
