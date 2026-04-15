"""
Behavioural Baseline Domain Service

Manages and updates per-agent behavioural baselines.
Pure domain logic — storage delegated to infrastructure via ports.
"""

from __future__ import annotations

import statistics

from sentinel.domain.entities.tool_call import ToolCall
from sentinel.domain.services.anomaly_detection import BehaviouralBaseline


class BehaviouralBaselineService:
    """Builds and updates behavioural baselines from historical tool calls."""

    def build_baseline(
        self, agent_id: str, historical_tool_calls: list[ToolCall]
    ) -> BehaviouralBaseline:
        if not historical_tool_calls:
            return BehaviouralBaseline(
                agent_id=agent_id,
                avg_tool_calls_per_task=0.0,
                avg_latency_ms=0.0,
                avg_data_sources=0.0,
                avg_payload_size_bytes=0.0,
                known_tool_sequences=(),
            )

        latencies = [tc.latency_ms for tc in historical_tool_calls]
        sizes = [tc.payload_size_bytes() for tc in historical_tool_calls]
        data_sources = len({tc.server_name for tc in historical_tool_calls})
        sequence = tuple(tc.full_tool_path for tc in historical_tool_calls)

        return BehaviouralBaseline(
            agent_id=agent_id,
            avg_tool_calls_per_task=float(len(historical_tool_calls)),
            avg_latency_ms=statistics.mean(latencies) if latencies else 0.0,
            avg_data_sources=float(data_sources),
            avg_payload_size_bytes=statistics.mean(sizes) if sizes else 0.0,
            known_tool_sequences=(sequence,) if sequence else (),
        )

    def update_baseline(
        self,
        existing: BehaviouralBaseline,
        new_tool_calls: list[ToolCall],
        alpha: float = 0.1,
    ) -> BehaviouralBaseline:
        """Exponential moving average update of the baseline."""
        if not new_tool_calls:
            return existing

        new_latency = statistics.mean([tc.latency_ms for tc in new_tool_calls])
        new_size = statistics.mean([tc.payload_size_bytes() for tc in new_tool_calls])
        new_sequence = tuple(tc.full_tool_path for tc in new_tool_calls)

        updated_sequences = existing.known_tool_sequences
        if new_sequence not in updated_sequences:
            updated_sequences = updated_sequences + (new_sequence,)
            # Keep only last 50 known sequences
            if len(updated_sequences) > 50:
                updated_sequences = updated_sequences[-50:]

        return BehaviouralBaseline(
            agent_id=existing.agent_id,
            avg_tool_calls_per_task=(
                (1 - alpha) * existing.avg_tool_calls_per_task
                + alpha * len(new_tool_calls)
            ),
            avg_latency_ms=(
                (1 - alpha) * existing.avg_latency_ms + alpha * new_latency
            ),
            avg_data_sources=existing.avg_data_sources,
            avg_payload_size_bytes=(
                (1 - alpha) * existing.avg_payload_size_bytes + alpha * new_size
            ),
            known_tool_sequences=updated_sequences,
        )
