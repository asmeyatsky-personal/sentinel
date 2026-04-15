"""Tests for Threat entity — pure domain tests, no mocks."""

from __future__ import annotations


from sentinel.domain.entities.threat import (
    Threat,
    ThreatCategory,
    ThreatEscalatedEvent,
    ThreatStatus,
)
from sentinel.domain.value_objects.detection_score import DetectionScore
from sentinel.domain.value_objects.threat_level import ThreatLevel


def _make_threat(**overrides) -> Threat:
    defaults = {
        "id": "threat-1",
        "agent_id": "agent-1",
        "category": ThreatCategory.PROMPT_INJECTION,
        "score": DetectionScore(value=75.0),
        "level": ThreatLevel.HIGH,
        "description": "Prompt injection detected in tool response",
        "evidence": {"pattern": "ignore previous instructions"},
        "detection_tier": 1,
    }
    defaults.update(overrides)
    return Threat(**defaults)


class TestThreat:
    def test_create_threat(self):
        threat = _make_threat()
        assert threat.status is ThreatStatus.OPEN
        assert threat.level is ThreatLevel.HIGH

    def test_escalate_increases_level(self):
        threat = _make_threat(
            score=DetectionScore(value=50.0),
            level=ThreatLevel.MEDIUM,
        )
        escalated = threat.escalate(DetectionScore(value=92.0))
        assert escalated.level is ThreatLevel.CRITICAL
        assert escalated.score.value == 92.0
        assert threat.level is ThreatLevel.MEDIUM

    def test_escalate_emits_event(self):
        threat = _make_threat(
            score=DetectionScore(value=50.0),
            level=ThreatLevel.MEDIUM,
        )
        escalated = threat.escalate(DetectionScore(value=92.0))
        assert len(escalated.domain_events) == 1
        event = escalated.domain_events[0]
        assert isinstance(event, ThreatEscalatedEvent)
        assert event.previous_level == "MEDIUM"
        assert event.new_level == "CRITICAL"

    def test_escalate_no_change_if_same_or_lower(self):
        threat = _make_threat()
        same = threat.escalate(DetectionScore(value=50.0))
        assert same is threat

    def test_mitigate(self):
        threat = _make_threat()
        mitigated = threat.mitigate()
        assert mitigated.status is ThreatStatus.MITIGATED
        assert threat.status is ThreatStatus.OPEN

    def test_mark_false_positive(self):
        threat = _make_threat()
        fp = threat.mark_false_positive()
        assert fp.status is ThreatStatus.FALSE_POSITIVE

    def test_requires_auto_block(self):
        high_t1 = _make_threat(level=ThreatLevel.HIGH, detection_tier=1)
        assert high_t1.requires_auto_block() is True

        high_t2 = _make_threat(level=ThreatLevel.HIGH, detection_tier=2)
        assert high_t2.requires_auto_block() is False

        low_t1 = _make_threat(level=ThreatLevel.LOW, detection_tier=1)
        assert low_t1.requires_auto_block() is False

    def test_requires_auto_contain(self):
        critical = _make_threat(level=ThreatLevel.CRITICAL)
        assert critical.requires_auto_contain() is True

        high = _make_threat(level=ThreatLevel.HIGH)
        assert high.requires_auto_contain() is False
