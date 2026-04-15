"""
Enforce Rate Limit Use Case — INTERCEPT module

Architectural Intent:
- Per-VAID rate limiting for tool call throughput
- Maintains an in-memory sliding window counter per agent
- Returns allow/deny decision with remaining quota information
- Stateless across restarts (ephemeral rate limit state)
"""

from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import dataclass, field

from sentinel.domain.entities.tool_call import ToolCall
from sentinel.application.dtos.schemas import RateLimitDecisionDTO


@dataclass
class _RateWindow:
    """Sliding window tracking timestamps of recent calls."""
    timestamps: list[float] = field(default_factory=list)


class EnforceRateLimitUseCase:
    """Per-VAID rate limiting for tool call throughput."""

    def __init__(
        self,
        max_calls: int = 100,
        window_seconds: int = 60,
    ) -> None:
        self._max_calls = max_calls
        self._window_seconds = window_seconds
        self._windows: dict[str, _RateWindow] = defaultdict(_RateWindow)

    async def execute(
        self, agent_id: str, tool_call: ToolCall
    ) -> RateLimitDecisionDTO:
        now = time.monotonic()
        window = self._windows[agent_id]

        # Prune expired entries
        cutoff = now - self._window_seconds
        window.timestamps = [ts for ts in window.timestamps if ts > cutoff]

        current_count = len(window.timestamps)

        if current_count >= self._max_calls:
            return RateLimitDecisionDTO(
                allowed=False,
                reason=(
                    f"Rate limit exceeded for agent '{agent_id}': "
                    f"{current_count}/{self._max_calls} calls in "
                    f"{self._window_seconds}s window"
                ),
                current_count=current_count,
                limit=self._max_calls,
                window_seconds=self._window_seconds,
            )

        # Allow and record
        window.timestamps.append(now)

        return RateLimitDecisionDTO(
            allowed=True,
            reason="",
            current_count=current_count + 1,
            limit=self._max_calls,
            window_seconds=self._window_seconds,
        )
