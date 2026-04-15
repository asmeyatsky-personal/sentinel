"""Tests for value objects — pure domain tests."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from sentinel.domain.value_objects.attack_surface_score import AttackSurfaceScore
from sentinel.domain.value_objects.data_classification import DataClassification
from sentinel.domain.value_objects.detection_score import DetectionScore
from sentinel.domain.value_objects.threat_level import ThreatLevel
from sentinel.domain.value_objects.vaid import VAID


class TestDetectionScore:
    def test_valid_score(self):
        score = DetectionScore(value=75.0)
        assert score.value == 75.0

    def test_invalid_negative(self):
        with pytest.raises(ValueError):
            DetectionScore(value=-1.0)

    def test_invalid_over_100(self):
        with pytest.raises(ValueError):
            DetectionScore(value=101.0)

    def test_to_threat_level_critical(self):
        assert DetectionScore(value=95.0).to_threat_level() is ThreatLevel.CRITICAL

    def test_to_threat_level_high(self):
        assert DetectionScore(value=75.0).to_threat_level() is ThreatLevel.HIGH

    def test_to_threat_level_medium(self):
        assert DetectionScore(value=50.0).to_threat_level() is ThreatLevel.MEDIUM

    def test_to_threat_level_low(self):
        assert DetectionScore(value=20.0).to_threat_level() is ThreatLevel.LOW

    def test_exceeds_threshold(self):
        score = DetectionScore(value=80.0)
        assert score.exceeds_threshold(70.0) is True
        assert score.exceeds_threshold(90.0) is False


class TestThreatLevel:
    def test_auto_block(self):
        assert ThreatLevel.CRITICAL.should_auto_block() is True
        assert ThreatLevel.HIGH.should_auto_block() is True
        assert ThreatLevel.MEDIUM.should_auto_block() is False
        assert ThreatLevel.LOW.should_auto_block() is False

    def test_auto_contain(self):
        assert ThreatLevel.CRITICAL.should_auto_contain() is True
        assert ThreatLevel.HIGH.should_auto_contain() is False


class TestDataClassification:
    def test_requires_redaction(self):
        assert DataClassification.RESTRICTED.requires_redaction() is True
        assert DataClassification.CONFIDENTIAL.requires_redaction() is True
        assert DataClassification.INTERNAL.requires_redaction() is False
        assert DataClassification.PUBLIC.requires_redaction() is False

    def test_allows_external_transmission(self):
        assert DataClassification.PUBLIC.allows_external_transmission() is True
        assert DataClassification.CONFIDENTIAL.allows_external_transmission() is False


class TestVAID:
    def test_valid_vaid(self):
        vaid = VAID(
            agent_id="agent-1",
            issuer="kernel",
            capabilities=("read", "write"),
            issued_at=datetime(2026, 1, 1, tzinfo=UTC),
            expires_at=datetime(2027, 1, 1, tzinfo=UTC),
            signature="sig-123",
        )
        assert vaid.is_valid() is True
        assert vaid.has_capability("read") is True
        assert vaid.has_capability("delete") is False

    def test_expired_vaid(self):
        vaid = VAID(
            agent_id="agent-1",
            issuer="kernel",
            capabilities=("read",),
            issued_at=datetime(2024, 1, 1, tzinfo=UTC),
            expires_at=datetime(2025, 1, 1, tzinfo=UTC),
            signature="sig-123",
        )
        assert vaid.is_expired() is True
        assert vaid.is_valid() is False


class TestAttackSurfaceScore:
    def test_valid_score(self):
        score = AttackSurfaceScore(value=65.0)
        assert score.risk_category == "HIGH"

    def test_critical(self):
        assert AttackSurfaceScore(value=85.0).risk_category == "CRITICAL"

    def test_low(self):
        assert AttackSurfaceScore(value=20.0).risk_category == "LOW"

    def test_invalid(self):
        with pytest.raises(ValueError):
            AttackSurfaceScore(value=150.0)
