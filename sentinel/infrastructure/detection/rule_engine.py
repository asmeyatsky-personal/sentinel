"""Rule-based detection engine implementing RuleEnginePort."""

from __future__ import annotations

from sentinel.domain.entities.tool_call import ToolCall
from sentinel.domain.value_objects.detection_score import DetectionScore
from sentinel.infrastructure.adapters.rate_limiter import InMemoryRateLimiter

# Tool sequences that are known indicators of compromise.
KNOWN_BAD_SEQUENCES: tuple[tuple[str, ...], ...] = (
    ("file.read", "http.post"),          # read-then-exfiltrate
    ("secrets.get", "http.post"),         # credential theft
    ("db.query", "file.write", "http.post"),  # data staging + exfil
    ("shell.exec", "file.write"),         # remote code execution
    ("config.update", "shell.exec"),      # config tampering + execution
)


class RuleBasedDetectionEngine:
    """Evaluates tool calls against static security rules.

    Rules
    -----
    1. Capability boundary check — tool must be in the agent's registered capabilities.
    2. Known-bad tool sequence detection — trailing pair matches flagged patterns.
    3. Rate-based anomaly — exceeded call rate within the sliding window.
    """

    def __init__(self, rate_limiter: InMemoryRateLimiter | None = None) -> None:
        self._rate_limiter = rate_limiter or InMemoryRateLimiter()
        self._recent_tools: dict[str, list[str]] = {}

    async def evaluate(
        self, tool_call: ToolCall, agent_capabilities: tuple[str, ...]
    ) -> DetectionScore:
        scores: list[float] = []

        # Rule 1: capability boundary
        if tool_call.tool_name not in agent_capabilities:
            scores.append(85.0)

        # Rule 2: known-bad tool sequence (check last 2-3 tool names per agent)
        history = self._recent_tools.setdefault(tool_call.agent_id, [])
        history.append(tool_call.tool_name)
        # Keep a bounded window of recent tool names
        if len(history) > 20:
            self._recent_tools[tool_call.agent_id] = history[-20:]
            history = self._recent_tools[tool_call.agent_id]

        for bad_seq in KNOWN_BAD_SEQUENCES:
            seq_len = len(bad_seq)
            if len(history) >= seq_len and tuple(history[-seq_len:]) == bad_seq:
                scores.append(90.0)
                break

        # Rule 3: rate-based anomaly
        if not self._rate_limiter.check_rate_limit(tool_call.agent_id):
            scores.append(70.0)
        self._rate_limiter.record_call(tool_call.agent_id)

        if not scores:
            return DetectionScore(value=0.0)

        return DetectionScore(value=min(max(scores), 100.0))
