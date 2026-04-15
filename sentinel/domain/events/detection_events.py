"""Domain events emitted by DETECT and SHIELD modules."""

from __future__ import annotations

from dataclasses import dataclass

from sentinel.domain.events.base import DomainEvent


@dataclass(frozen=True)
class PromptInjectionDetectedEvent(DomainEvent):
    tool_call_id: str = ""
    confidence: float = 0.0
    payload_snippet: str = ""


@dataclass(frozen=True)
class CapabilityViolationDetectedEvent(DomainEvent):
    tool_name: str = ""
    required_capability: str = ""


@dataclass(frozen=True)
class BehaviouralAnomalyDetectedEvent(DomainEvent):
    metric: str = ""
    baseline_value: float = 0.0
    observed_value: float = 0.0
    deviation_sigma: float = 0.0


@dataclass(frozen=True)
class DataLeakageDetectedEvent(DomainEvent):
    pii_types: tuple[str, ...] = ()
    destination: str = ""
    classification: str = ""


@dataclass(frozen=True)
class CostAnomalyDetectedEvent(DomainEvent):
    expected_cost: float = 0.0
    actual_cost: float = 0.0
    ratio: float = 0.0
