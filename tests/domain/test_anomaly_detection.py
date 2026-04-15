"""Tests for AnomalyDetectionService — pure domain service tests."""

from __future__ import annotations

from sentinel.domain.entities.tool_call import ToolCall
from sentinel.domain.services.anomaly_detection import (
    AnomalyDetectionService,
    BehaviouralBaseline,
)


def _make_baseline(**overrides) -> BehaviouralBaseline:
    defaults = {
        "agent_id": "agent-1",
        "avg_tool_calls_per_task": 5.0,
        "avg_latency_ms": 100.0,
        "avg_data_sources": 2.0,
        "avg_payload_size_bytes": 500.0,
        "known_tool_sequences": (
            ("server-a.read", "server-a.write"),
            ("server-b.query",),
        ),
    }
    defaults.update(overrides)
    return BehaviouralBaseline(**defaults)


def _make_tool_call(**overrides) -> ToolCall:
    defaults = {
        "id": "tc-1",
        "agent_id": "agent-1",
        "server_name": "server-a",
        "tool_name": "read",
        "arguments": {"key": "value"},
        "latency_ms": 100.0,
    }
    defaults.update(overrides)
    return ToolCall(**defaults)


class TestAnomalyDetectionService:
    def setup_method(self):
        self.service = AnomalyDetectionService()
        self.baseline = _make_baseline()

    def test_normal_frequency_scores_zero(self):
        calls = [_make_tool_call(id=f"tc-{i}") for i in range(5)]
        score = self.service.score_tool_call_frequency(calls, self.baseline)
        assert score.value == 0.0

    def test_high_frequency_scores_high(self):
        calls = [_make_tool_call(id=f"tc-{i}") for i in range(30)]
        score = self.service.score_tool_call_frequency(calls, self.baseline)
        assert score.value >= 80.0

    def test_normal_latency_scores_zero(self):
        tc = _make_tool_call(latency_ms=100.0)
        score = self.service.score_latency_anomaly(tc, self.baseline)
        assert score.value == 0.0

    def test_extreme_latency_scores_high(self):
        tc = _make_tool_call(latency_ms=5000.0)
        score = self.service.score_latency_anomaly(tc, self.baseline)
        assert score.value >= 70.0

    def test_known_sequence_scores_zero(self):
        calls = [
            _make_tool_call(id="tc-1", server_name="server-a", tool_name="read"),
            _make_tool_call(id="tc-2", server_name="server-a", tool_name="write"),
        ]
        score = self.service.score_unknown_tool_sequence(calls, self.baseline)
        assert score.value == 0.0

    def test_unknown_sequence_scores_medium(self):
        calls = [
            _make_tool_call(id="tc-1", server_name="server-x", tool_name="delete"),
            _make_tool_call(id="tc-2", server_name="server-y", tool_name="exfil"),
        ]
        score = self.service.score_unknown_tool_sequence(calls, self.baseline)
        assert score.value >= 60.0

    def test_aggregate_returns_max(self):
        from sentinel.domain.value_objects.detection_score import DetectionScore

        scores = [
            DetectionScore(value=10.0),
            DetectionScore(value=75.0),
            DetectionScore(value=30.0),
        ]
        agg = self.service.aggregate_scores(scores)
        assert agg.value == 75.0

    def test_aggregate_empty_returns_zero(self):
        agg = self.service.aggregate_scores([])
        assert agg.value == 0.0
