"""Tests for DetectConfigDriftUseCase — use case tests with mocked ports."""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import AsyncMock

import pytest

from sentinel.application.recon.detect_config_drift import DetectConfigDriftUseCase
from sentinel.domain.entities.agent import Agent
from sentinel.domain.entities.mcp_server import MCPServer, MCPServerTool
from sentinel.domain.value_objects.vaid import VAID


def _make_vaid(agent_id: str) -> VAID:
    return VAID(
        agent_id=agent_id,
        issuer="kernel",
        capabilities=("cap-1",),
        issued_at=datetime(2026, 1, 1, tzinfo=UTC),
        expires_at=datetime(2027, 1, 1, tzinfo=UTC),
        signature="sig",
    )


def _make_agent(agent_id: str, tools: tuple[str, ...] = ("tool-a",)) -> Agent:
    return Agent(
        id=agent_id,
        name=agent_id,
        vaid=_make_vaid(agent_id),
        framework="synthera",
        model_id="claude-opus-4-6",
        registered_tools=tools,
    )


def _make_server(server_id: str, tool_names: tuple[str, ...] = ("read",)) -> MCPServer:
    tools = tuple(
        MCPServerTool(name=n, description=f"{n} tool", input_schema={})
        for n in tool_names
    )
    return MCPServer(
        id=server_id,
        name=server_id,
        transport="stdio",
        endpoint="localhost",
        tools=tools,
    )


@pytest.mark.asyncio
class TestDetectConfigDriftUseCase:
    async def test_no_drift_on_first_scan(self) -> None:
        agent_repo = AsyncMock()
        agent_repo.get_all.return_value = [_make_agent("a-1")]
        mcp_repo = AsyncMock()
        mcp_repo.get_all.return_value = [_make_server("s-1")]
        event_bus = AsyncMock()

        use_case = DetectConfigDriftUseCase(
            agent_repository=agent_repo,
            mcp_server_repository=mcp_repo,
            event_bus=event_bus,
        )

        result = await use_case.execute()

        assert result["drift_detected"] is False
        assert result["changes"] == []
        event_bus.publish.assert_not_awaited()

    async def test_detects_new_agent(self) -> None:
        agent_repo = AsyncMock()
        mcp_repo = AsyncMock()
        mcp_repo.get_all.return_value = []
        event_bus = AsyncMock()

        use_case = DetectConfigDriftUseCase(
            agent_repository=agent_repo,
            mcp_server_repository=mcp_repo,
            event_bus=event_bus,
        )

        # First scan — baseline
        agent_repo.get_all.return_value = [_make_agent("a-1")]
        await use_case.execute()

        # Second scan — new agent appears
        agent_repo.get_all.return_value = [_make_agent("a-1"), _make_agent("a-2")]
        result = await use_case.execute()

        assert result["drift_detected"] is True
        change_types = [c["type"] for c in result["changes"]]
        assert "new_agent" in change_types
        event_bus.publish.assert_awaited()

    async def test_detects_tool_change(self) -> None:
        agent_repo = AsyncMock()
        mcp_repo = AsyncMock()
        mcp_repo.get_all.return_value = []
        event_bus = AsyncMock()

        use_case = DetectConfigDriftUseCase(
            agent_repository=agent_repo,
            mcp_server_repository=mcp_repo,
            event_bus=event_bus,
        )

        # First scan — baseline
        agent_repo.get_all.return_value = [_make_agent("a-1", tools=("tool-a",))]
        await use_case.execute()

        # Second scan — agent changed its tools
        agent_repo.get_all.return_value = [
            _make_agent("a-1", tools=("tool-a", "tool-b"))
        ]
        result = await use_case.execute()

        assert result["drift_detected"] is True
        change_types = [c["type"] for c in result["changes"]]
        assert "tool_change" in change_types
        event_bus.publish.assert_awaited()
