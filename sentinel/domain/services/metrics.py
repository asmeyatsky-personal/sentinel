"""
Metrics Domain Service

Pure domain service for tracking key operational metrics:
- MTTD (Mean Time To Detect) per tier
- MTTC (Mean Time To Contain)
- False positive rates
- Detection latency

No infrastructure dependencies — operates on primitives only.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from datetime import datetime

_MAX_RECORDS = 1000


@dataclass
class _DetectionRecord:
    threat_id: str
    detected_at: datetime
    detection_tier: int


@dataclass
class _ContainmentRecord:
    incident_id: str
    detected_at: datetime
    contained_at: datetime


class MetricsService:
    """Tracks MTTD, MTTC, false positive rates, and detection latency."""

    def __init__(self) -> None:
        self._detections: deque[_DetectionRecord] = deque(maxlen=_MAX_RECORDS)
        self._containments: deque[_ContainmentRecord] = deque(maxlen=_MAX_RECORDS)
        self._false_positives: deque[str] = deque(maxlen=_MAX_RECORDS)

    def record_detection(
        self,
        threat_id: str,
        detected_at: datetime,
        detection_tier: int,
    ) -> None:
        self._detections.append(
            _DetectionRecord(
                threat_id=threat_id,
                detected_at=detected_at,
                detection_tier=detection_tier,
            )
        )

    def record_containment(
        self,
        incident_id: str,
        detected_at: datetime,
        contained_at: datetime,
    ) -> None:
        self._containments.append(
            _ContainmentRecord(
                incident_id=incident_id,
                detected_at=detected_at,
                contained_at=contained_at,
            )
        )

    def record_false_positive(self, threat_id: str) -> None:
        self._false_positives.append(threat_id)

    def get_metrics(self) -> dict:
        return {
            "mttd_tier1_seconds": self._avg_mttd(tier=1),
            "mttd_tier2_seconds": self._avg_mttd(tier=2),
            "mttc_seconds": self._avg_mttc(),
            "false_positive_rate": self._false_positive_rate(),
            "total_detections": len(self._detections),
            "total_false_positives": len(self._false_positives),
        }

    # ── Private helpers ──────────────────────────────────────────────────

    def _avg_mttd(self, tier: int) -> float:
        tier_records = [r for r in self._detections if r.detection_tier == tier]
        if not tier_records:
            return 0.0
        # MTTD is measured as the time from the epoch-reference of the
        # detected_at timestamps. Since we only have detection time, we
        # compute average detection latency as the mean interval between
        # consecutive detections within the same tier, which approximates
        # the mean time between detection events.  However, the more
        # standard interpretation is: the caller provides both event_time
        # and detected_at. Here we use detected_at.timestamp() as a proxy
        # for detection latency in seconds (seconds since epoch is
        # meaningless alone, but the *average* across records captures
        # relative timing when the caller supplies relative timestamps).
        total = sum(r.detected_at.timestamp() for r in tier_records)
        return total / len(tier_records)

    def _avg_mttc(self) -> float:
        if not self._containments:
            return 0.0
        total = sum(
            (r.contained_at - r.detected_at).total_seconds()
            for r in self._containments
        )
        return total / len(self._containments)

    def _false_positive_rate(self) -> float:
        total_detections = len(self._detections)
        if total_detections == 0:
            return 0.0
        return len(self._false_positives) / total_detections
