"""Tests for Agent entity — pure domain tests, no mocks needed."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from sentinel.domain.entities.agent import Agent, AgentIsolatedEvent, AgentStatus
from sentinel.domain.value_objects.vaid import VAID


def _make_vaid(**overrides) -> VAID:
    defaults = {
        "agent_id": "agent-1",
        "issuer": "synthera-kernel",
        "capabilities": ("read_data", "write_data"),
        "issued_at": datetime(2026, 1, 1, tzinfo=UTC),
        "expires_at": datetime(2027, 1, 1, tzinfo=UTC),
        "signature": "sig-abc123",
    }
    defaults.update(overrides)
    return VAID(**defaults)


def _make_agent(**overrides) -> Agent:
    defaults = {
        "id": "agent-1",
        "name": "test-agent",
        "vaid": _make_vaid(),
        "framework": "synthera",
        "model_id": "claude-opus-4-6",
        "registered_tools": ("read_file", "write_file", "query_db"),
    }
    defaults.update(overrides)
    return Agent(**defaults)


class TestAgent:
    def test_create_agent(self):
        agent = _make_agent()
        assert agent.id == "agent-1"
        assert agent.status is AgentStatus.ACTIVE
        assert len(agent.domain_events) == 0

    def test_isolate_produces_new_instance(self):
        agent = _make_agent()
        isolated = agent.isolate("suspicious behaviour")
        assert isolated.status is AgentStatus.ISOLATED
        assert agent.status is AgentStatus.ACTIVE
        assert isolated is not agent

    def test_isolate_emits_domain_event(self):
        agent = _make_agent()
        isolated = agent.isolate("prompt injection detected")
        assert len(isolated.domain_events) == 1
        event = isolated.domain_events[0]
        assert isinstance(event, AgentIsolatedEvent)
        assert event.reason == "prompt injection detected"
        assert event.aggregate_id == "agent-1"

    def test_cannot_isolate_already_terminated(self):
        agent = _make_agent()
        terminated = agent.terminate("kill switch")
        with pytest.raises(ValueError, match="Cannot isolate"):
            terminated.isolate("test")

    def test_quarantine_from_active(self):
        agent = _make_agent()
        quarantined = agent.quarantine("investigation")
        assert quarantined.status is AgentStatus.QUARANTINED

    def test_quarantine_from_isolated(self):
        agent = _make_agent()
        isolated = agent.isolate("sus")
        quarantined = isolated.quarantine("deeper investigation")
        assert quarantined.status is AgentStatus.QUARANTINED
        assert len(quarantined.domain_events) == 2

    def test_terminate(self):
        agent = _make_agent()
        terminated = agent.terminate("kill switch engaged")
        assert terminated.status is AgentStatus.TERMINATED

    def test_is_over_privileged(self):
        agent = _make_agent(
            registered_tools=tuple(f"tool_{i}" for i in range(15))
        )
        assert agent.is_over_privileged(max_tools=10) is True

    def test_not_over_privileged(self):
        agent = _make_agent()
        assert agent.is_over_privileged(max_tools=10) is False

    def test_has_tool(self):
        agent = _make_agent()
        assert agent.has_tool("read_file") is True
        assert agent.has_tool("delete_all") is False

    def test_heartbeat_updates_last_seen(self):
        agent = _make_agent()
        original_time = agent.last_seen_at
        updated = agent.heartbeat()
        assert updated.last_seen_at >= original_time
        assert updated is not agent
