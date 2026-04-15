"""
Threat Entity

Represents a detected security threat. Produced by DETECT module.
Immutable — severity escalation produces new instances.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from enum import Enum

from sentinel.domain.events.base import DomainEvent
from sentinel.domain.value_objects.detection_score import DetectionScore
from sentinel.domain.value_objects.threat_level import ThreatLevel


class ThreatCategory(Enum):
    BEHAVIOURAL_ANOMALY = "BEHAVIOURAL_ANOMALY"
    TRAJECTORY_ANOMALY = "TRAJECTORY_ANOMALY"
    PROMPT_INJECTION = "PROMPT_INJECTION"
    CAPABILITY_VIOLATION = "CAPABILITY_VIOLATION"
    COORDINATION_ANOMALY = "COORDINATION_ANOMALY"
    MODEL_INTEGRITY = "MODEL_INTEGRITY"
    DATA_EXFILTRATION = "DATA_EXFILTRATION"
    API_ABUSE = "API_ABUSE"
    COST_ANOMALY = "COST_ANOMALY"


class ThreatStatus(Enum):
    OPEN = "OPEN"
    INVESTIGATING = "INVESTIGATING"
    MITIGATED = "MITIGATED"
    FALSE_POSITIVE = "FALSE_POSITIVE"


@dataclass(frozen=True)
class ThreatDetectedEvent(DomainEvent):
    category: str = ""
    threat_level: str = ""


@dataclass(frozen=True)
class ThreatEscalatedEvent(DomainEvent):
    previous_level: str = ""
    new_level: str = ""


@dataclass(frozen=True)
class Threat:
    id: str
    agent_id: str
    category: ThreatCategory
    score: DetectionScore
    level: ThreatLevel
    description: str
    evidence: dict
    status: ThreatStatus = ThreatStatus.OPEN
    detected_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    detection_tier: int = 1
    domain_events: tuple[DomainEvent, ...] = field(default=())

    _SEVERITY_ORDER = {
        ThreatLevel.LOW: 0,
        ThreatLevel.MEDIUM: 1,
        ThreatLevel.HIGH: 2,
        ThreatLevel.CRITICAL: 3,
    }

    def escalate(self, new_score: DetectionScore) -> Threat:
        new_level = new_score.to_threat_level()
        if self._SEVERITY_ORDER[new_level] <= self._SEVERITY_ORDER[self.level]:
            return self
        return replace(
            self,
            score=new_score,
            level=new_level,
            domain_events=self.domain_events + (
                ThreatEscalatedEvent(
                    aggregate_id=self.id,
                    previous_level=self.level.value,
                    new_level=new_level.value,
                ),
            ),
        )

    def mitigate(self) -> Threat:
        return replace(self, status=ThreatStatus.MITIGATED)

    def mark_false_positive(self) -> Threat:
        return replace(self, status=ThreatStatus.FALSE_POSITIVE)

    def requires_auto_block(self) -> bool:
        return self.level.should_auto_block() and self.detection_tier == 1

    def requires_auto_contain(self) -> bool:
        return self.level.should_auto_contain()
