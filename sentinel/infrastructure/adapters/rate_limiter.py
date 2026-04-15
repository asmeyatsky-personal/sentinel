"""Thread-safe in-memory sliding-window rate limiter for agent tool calls."""

from __future__ import annotations

import asyncio
import time
from collections import defaultdict


class InMemoryRateLimiter:
    """Tracks per-agent call counts within a sliding time window.

    Thread-safe via asyncio.Lock. Memory-bounded by pruning expired entries
    and evicting inactive agents.

    Parameters
    ----------
    window_seconds:
        Duration of the sliding window in seconds.
    max_calls:
        Maximum allowed calls per agent within the window.
    max_tracked_agents:
        Maximum number of agents tracked simultaneously. Oldest pruned on overflow.
    """

    def __init__(
        self,
        window_seconds: float = 60.0,
        max_calls: int = 100,
        max_tracked_agents: int = 10_000,
    ) -> None:
        self._window = window_seconds
        self._max_calls = max_calls
        self._max_tracked = max_tracked_agents
        self._calls: dict[str, list[float]] = defaultdict(list)
        self._lock = asyncio.Lock()

    def _prune(self, agent_id: str) -> None:
        """Remove timestamps older than the sliding window."""
        cutoff = time.monotonic() - self._window
        self._calls[agent_id] = [
            ts for ts in self._calls[agent_id] if ts > cutoff
        ]

    def _evict_if_needed(self) -> None:
        """Evict oldest agents if tracking too many."""
        if len(self._calls) <= self._max_tracked:
            return
        # Find agents with no recent activity and remove them
        now = time.monotonic()
        cutoff = now - self._window
        to_remove = [
            aid for aid, timestamps in self._calls.items()
            if not timestamps or timestamps[-1] < cutoff
        ]
        for aid in to_remove:
            del self._calls[aid]
            if len(self._calls) <= self._max_tracked:
                return

    def check_rate_limit(self, agent_id: str) -> bool:
        """Return True if the agent is within the rate limit (call is allowed)."""
        self._prune(agent_id)
        return len(self._calls[agent_id]) < self._max_calls

    def record_call(self, agent_id: str) -> None:
        """Record a new call timestamp for the agent."""
        self._evict_if_needed()
        self._calls[agent_id].append(time.monotonic())

    async def check_rate_limit_async(self, agent_id: str) -> bool:
        """Thread-safe async version of check_rate_limit."""
        async with self._lock:
            return self.check_rate_limit(agent_id)

    async def record_call_async(self, agent_id: str) -> None:
        """Thread-safe async version of record_call."""
        async with self._lock:
            self.record_call(agent_id)
