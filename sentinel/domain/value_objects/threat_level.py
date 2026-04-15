"""Threat level classification for SENTINEL™ detections."""

from __future__ import annotations

from enum import Enum


class ThreatLevel(Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    def should_auto_block(self) -> bool:
        return self in (ThreatLevel.HIGH, ThreatLevel.CRITICAL)

    def should_auto_contain(self) -> bool:
        return self is ThreatLevel.CRITICAL
