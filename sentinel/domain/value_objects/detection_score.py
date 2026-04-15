"""Detection confidence score (0–100)."""

from __future__ import annotations

from dataclasses import dataclass

from sentinel.domain.value_objects.threat_level import ThreatLevel


@dataclass(frozen=True)
class DetectionScore:
    value: float

    def __post_init__(self) -> None:
        if not 0.0 <= self.value <= 100.0:
            raise ValueError(f"DetectionScore must be 0–100, got {self.value}")

    def to_threat_level(self) -> ThreatLevel:
        if self.value >= 90.0:
            return ThreatLevel.CRITICAL
        if self.value >= 70.0:
            return ThreatLevel.HIGH
        if self.value >= 40.0:
            return ThreatLevel.MEDIUM
        return ThreatLevel.LOW

    def exceeds_threshold(self, threshold: float) -> bool:
        return self.value >= threshold
