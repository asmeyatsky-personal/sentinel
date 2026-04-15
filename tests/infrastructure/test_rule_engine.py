"""Tests for RuleBasedDetectionEngine — infrastructure adapter tests."""

from __future__ import annotations

import pytest

from sentinel.domain.entities.tool_call import ToolCall


def _make_tool_call(tool_name: str = "read_file") -> ToolCall:
    return ToolCall(
        id="tc-1",
        agent_id="agent-1",
        server_name="file-server",
        tool_name=tool_name,
        arguments={"path": "/data/test.txt"},
    )


@pytest.mark.asyncio
class TestRuleBasedDetectionEngine:
    async def test_allowed_tool_scores_low(self):
        from sentinel.infrastructure.detection.rule_engine import RuleBasedDetectionEngine

        engine = RuleBasedDetectionEngine()
        score = await engine.evaluate(
            _make_tool_call("read_file"),
            agent_capabilities=("read_file", "write_file"),
        )
        assert score.value < 40.0

    async def test_disallowed_tool_scores_high(self):
        from sentinel.infrastructure.detection.rule_engine import RuleBasedDetectionEngine

        engine = RuleBasedDetectionEngine()
        score = await engine.evaluate(
            _make_tool_call("delete_all"),
            agent_capabilities=("read_file",),
        )
        assert score.value >= 80.0
