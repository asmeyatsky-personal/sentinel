"""Tests for MetricsService — pure domain, no mocks required."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone


from sentinel.domain.services.metrics import MetricsService


class TestMetricsService:
    def test_record_detection_updates_mttd(self):
        """Recording a detection updates MTTD metrics."""
        svc = MetricsService()

        detected_at = datetime(2026, 1, 1, 0, 0, 10, tzinfo=timezone.utc)
        svc.record_detection(
            threat_id="t-1",
            detected_at=detected_at,
            detection_tier=1,
        )

        metrics = svc.get_metrics()
        assert metrics["total_detections"] == 1
        assert metrics["mttd_tier1_seconds"] > 0
        assert metrics["mttd_tier2_seconds"] == 0.0

    def test_false_positive_rate_calculation(self):
        """False positives are correctly calculated as a rate of total detections."""
        svc = MetricsService()

        base = datetime(2026, 6, 1, tzinfo=timezone.utc)
        for i in range(10):
            svc.record_detection(
                threat_id=f"t-{i}",
                detected_at=base + timedelta(seconds=i),
                detection_tier=1,
            )

        # Mark 3 as false positives
        svc.record_false_positive("t-0")
        svc.record_false_positive("t-1")
        svc.record_false_positive("t-2")

        metrics = svc.get_metrics()
        assert metrics["total_detections"] == 10
        assert metrics["total_false_positives"] == 3
        assert abs(metrics["false_positive_rate"] - 0.3) < 1e-9

    def test_metrics_bounded(self):
        """Recording >1000 entries doesn't grow unbounded."""
        svc = MetricsService()

        base = datetime(2026, 1, 1, tzinfo=timezone.utc)
        for i in range(1200):
            svc.record_detection(
                threat_id=f"t-{i}",
                detected_at=base + timedelta(seconds=i),
                detection_tier=1,
            )

        metrics = svc.get_metrics()
        # Bounded to 1000 max
        assert metrics["total_detections"] <= 1000
