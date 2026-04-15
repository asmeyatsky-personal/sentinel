"""In-memory sliding-window rate limiter for agent tool calls."""

from __future__ import annotations

import time
from collections import defaultdict


class InMemoryRateLimiter:
    """Tracks per-agent call counts within a sliding time window.

    Parameters
    ----------
    window_seconds:
        Duration of the sliding window in seconds.
    max_calls:
        Maximum allowed calls per agent within the window.
    """

    def __init__(self, window_seconds: float = 60.0, max_calls: int = 100) -> None:
        self._window = window_seconds
        self._max_calls = max_calls
        self._calls: dict[str, list[float]] = defaultdict(list)

    def _prune(self, agent_id: str) -> None:
        """Remove timestamps older than the sliding window."""
        cutoff = time.monotonic() - self._window
        self._calls[agent_id] = [
            ts for ts in self._calls[agent_id] if ts > cutoff
        ]

    def check_rate_limit(self, agent_id: str) -> bool:
        """Return True if the agent is within the rate limit (call is allowed)."""
        self._prune(agent_id)
        return len(self._calls[agent_id]) < self._max_calls

    def record_call(self, agent_id: str) -> None:
        """Record a new call timestamp for the agent."""
        self._calls[agent_id].append(time.monotonic())
