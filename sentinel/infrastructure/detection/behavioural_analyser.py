"""Statistical behavioural analyser implementing BehaviouralAnalyserPort."""

from __future__ import annotations

from sentinel.domain.entities.tool_call import ToolCall
from sentinel.domain.value_objects.detection_score import DetectionScore


class StatisticalBehaviouralAnalyser:
    """Compares tool call metrics against baseline statistics.

    Uses simple ratio-based deviation scoring: the further a metric deviates
    from its baseline average, the higher the anomaly score.
    """

    async def score_tool_call(
        self, tool_call: ToolCall, baseline: dict
    ) -> DetectionScore:
        scores: list[float] = []

        # Latency deviation
        avg_latency = baseline.get("avg_latency_ms", 0.0)
        if avg_latency > 0:
            latency_ratio = tool_call.latency_ms / avg_latency
            scores.append(self._ratio_to_score(latency_ratio))

        # Payload size deviation
        avg_payload = baseline.get("avg_payload_size_bytes", 0.0)
        if avg_payload > 0:
            payload_size = tool_call.payload_size_bytes()
            payload_ratio = payload_size / avg_payload
            scores.append(self._ratio_to_score(payload_ratio))

        # Unknown tool penalty
        known_tools: list[str] = baseline.get("known_tools", [])
        if known_tools and tool_call.tool_name not in known_tools:
            scores.append(60.0)

        if not scores:
            return DetectionScore(value=0.0)

        return DetectionScore(value=min(max(scores), 100.0))

    async def score_trajectory(
        self, tool_calls: list[ToolCall], baseline: dict
    ) -> DetectionScore:
        if not tool_calls:
            return DetectionScore(value=0.0)

        scores: list[float] = []

        # Trajectory length deviation
        avg_calls = baseline.get("avg_tool_calls_per_task", 0.0)
        if avg_calls > 0:
            call_ratio = len(tool_calls) / avg_calls
            scores.append(self._ratio_to_score(call_ratio))

        # Unique server count deviation
        avg_sources = baseline.get("avg_data_sources", 0.0)
        if avg_sources > 0:
            unique_servers = len({tc.server_name for tc in tool_calls})
            source_ratio = unique_servers / avg_sources
            scores.append(self._ratio_to_score(source_ratio))

        # Score individual calls and take the worst
        individual_scores: list[float] = []
        for tc in tool_calls:
            single = await self.score_tool_call(tc, baseline)
            individual_scores.append(single.value)
        if individual_scores:
            scores.append(max(individual_scores))

        if not scores:
            return DetectionScore(value=0.0)

        return DetectionScore(value=min(max(scores), 100.0))

    @staticmethod
    def _ratio_to_score(ratio: float) -> float:
        """Map a deviation ratio to an anomaly score (0-100)."""
        if ratio <= 1.5:
            return 0.0
        if ratio <= 2.0:
            return 30.0
        if ratio <= 3.0:
            return 55.0
        if ratio <= 5.0:
            return 75.0
        if ratio <= 10.0:
            return 90.0
        return 95.0
