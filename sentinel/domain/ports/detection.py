"""Detection engine ports — abstraction over detection implementations."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from sentinel.domain.entities.tool_call import ToolCall
from sentinel.domain.value_objects.detection_score import DetectionScore


@dataclass(frozen=True)
class PIIMatch:
    pii_type: str
    value: str
    start: int
    end: int


@dataclass(frozen=True)
class PromptInjectionResult:
    is_injection: bool
    confidence: float
    matched_patterns: tuple[str, ...]


class PromptInjectionDetectorPort(Protocol):
    async def analyse(self, content: str) -> PromptInjectionResult: ...


class PIIDetectorPort(Protocol):
    async def scan(self, content: str) -> list[PIIMatch]: ...
    async def redact(self, content: str) -> str: ...


class BehaviouralAnalyserPort(Protocol):
    async def score_tool_call(
        self, tool_call: ToolCall, baseline: dict
    ) -> DetectionScore: ...

    async def score_trajectory(
        self, tool_calls: list[ToolCall], baseline: dict
    ) -> DetectionScore: ...


class RuleEnginePort(Protocol):
    async def evaluate(self, tool_call: ToolCall, agent_capabilities: tuple[str, ...]) -> DetectionScore: ...
