"""
Anomaly Detection Domain Service

Pure domain logic for scoring behavioural anomalies.
No infrastructure dependencies — operates on domain objects only.
"""

from __future__ import annotations

from dataclasses import dataclass

from sentinel.domain.entities.tool_call import ToolCall
from sentinel.domain.value_objects.detection_score import DetectionScore


@dataclass(frozen=True)
class BehaviouralBaseline:
    agent_id: str
    avg_tool_calls_per_task: float
    avg_latency_ms: float
    avg_data_sources: float
    avg_payload_size_bytes: float
    known_tool_sequences: tuple[tuple[str, ...], ...]


class AnomalyDetectionService:
    """Scores tool calls and trajectories against behavioural baselines."""

    def score_tool_call_frequency(
        self, tool_calls: list[ToolCall], baseline: BehaviouralBaseline
    ) -> DetectionScore:
        if baseline.avg_tool_calls_per_task == 0:
            return DetectionScore(value=0.0)
        ratio = len(tool_calls) / baseline.avg_tool_calls_per_task
        if ratio <= 1.5:
            return DetectionScore(value=0.0)
        if ratio <= 2.0:
            return DetectionScore(value=30.0)
        if ratio <= 3.0:
            return DetectionScore(value=60.0)
        if ratio <= 5.0:
            return DetectionScore(value=80.0)
        return DetectionScore(value=95.0)

    def score_latency_anomaly(
        self, tool_call: ToolCall, baseline: BehaviouralBaseline
    ) -> DetectionScore:
        if baseline.avg_latency_ms == 0:
            return DetectionScore(value=0.0)
        ratio = tool_call.latency_ms / baseline.avg_latency_ms
        if ratio <= 3.0:
            return DetectionScore(value=0.0)
        if ratio <= 5.0:
            return DetectionScore(value=40.0)
        if ratio <= 10.0:
            return DetectionScore(value=70.0)
        return DetectionScore(value=90.0)

    def score_payload_size_anomaly(
        self, tool_call: ToolCall, baseline: BehaviouralBaseline
    ) -> DetectionScore:
        if baseline.avg_payload_size_bytes == 0:
            return DetectionScore(value=0.0)
        size = tool_call.payload_size_bytes()
        ratio = size / baseline.avg_payload_size_bytes
        if ratio <= 2.0:
            return DetectionScore(value=0.0)
        if ratio <= 5.0:
            return DetectionScore(value=50.0)
        if ratio <= 10.0:
            return DetectionScore(value=75.0)
        return DetectionScore(value=92.0)

    def score_unknown_tool_sequence(
        self, tool_calls: list[ToolCall], baseline: BehaviouralBaseline
    ) -> DetectionScore:
        if not tool_calls:
            return DetectionScore(value=0.0)
        sequence = tuple(tc.full_tool_path for tc in tool_calls)
        if sequence in baseline.known_tool_sequences:
            return DetectionScore(value=0.0)
        for known in baseline.known_tool_sequences:
            if self._is_subsequence(sequence, known):
                return DetectionScore(value=20.0)
        return DetectionScore(value=65.0)

    def aggregate_scores(self, scores: list[DetectionScore]) -> DetectionScore:
        if not scores:
            return DetectionScore(value=0.0)
        max_score = max(s.value for s in scores)
        return DetectionScore(value=min(max_score, 100.0))

    @staticmethod
    def _is_subsequence(needle: tuple[str, ...], haystack: tuple[str, ...]) -> bool:
        it = iter(haystack)
        return all(item in it for item in needle)
