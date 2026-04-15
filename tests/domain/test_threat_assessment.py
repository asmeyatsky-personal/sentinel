"""Tests for ThreatAssessmentService — pure domain service tests."""

from __future__ import annotations

from sentinel.domain.entities.incident import ResponseAction
from sentinel.domain.entities.threat import Threat, ThreatCategory
from sentinel.domain.services.threat_assessment import ThreatAssessmentService
from sentinel.domain.value_objects.detection_score import DetectionScore
from sentinel.domain.value_objects.threat_level import ThreatLevel


def _make_threat(
    level: ThreatLevel = ThreatLevel.HIGH,
    category: ThreatCategory = ThreatCategory.PROMPT_INJECTION,
    score: float = 75.0,
    tier: int = 1,
) -> Threat:
    return Threat(
        id="threat-1",
        agent_id="agent-1",
        category=category,
        score=DetectionScore(value=score),
        level=level,
        description="test",
        evidence={},
        detection_tier=tier,
    )


class TestThreatAssessmentService:
    def setup_method(self):
        self.service = ThreatAssessmentService()

    def test_critical_threat_recommends_isolation(self):
        threat = _make_threat(level=ThreatLevel.CRITICAL, score=95.0)
        assessment = self.service.assess(threat)
        assert ResponseAction.AGENT_ISOLATED in assessment.recommended_actions
        assert ResponseAction.CREDENTIALS_ROTATED in assessment.recommended_actions
        assert assessment.requires_human_escalation is True

    def test_high_threat_recommends_blocking(self):
        threat = _make_threat(level=ThreatLevel.HIGH)
        assessment = self.service.assess(threat)
        assert ResponseAction.TOOL_BLOCKED in assessment.recommended_actions
        assert ResponseAction.TICKET_CREATED in assessment.recommended_actions

    def test_medium_threat_creates_ticket_only(self):
        threat = _make_threat(level=ThreatLevel.MEDIUM, score=50.0)
        assessment = self.service.assess(threat)
        assert ResponseAction.TICKET_CREATED in assessment.recommended_actions
        assert ResponseAction.AGENT_ISOLATED not in assessment.recommended_actions

    def test_low_threat_no_actions(self):
        threat = _make_threat(level=ThreatLevel.LOW, score=20.0)
        assessment = self.service.assess(threat)
        assert len(assessment.recommended_actions) == 0

    def test_data_exfiltration_always_isolates(self):
        threat = _make_threat(
            level=ThreatLevel.MEDIUM,
            category=ThreatCategory.DATA_EXFILTRATION,
            score=50.0,
        )
        assessment = self.service.assess(threat)
        assert ResponseAction.AGENT_ISOLATED in assessment.recommended_actions

    def test_model_integrity_requires_human(self):
        threat = _make_threat(
            level=ThreatLevel.LOW,
            category=ThreatCategory.MODEL_INTEGRITY,
            score=30.0,
        )
        assessment = self.service.assess(threat)
        assert assessment.requires_human_escalation is True

    def test_assess_multiple_takes_worst(self):
        threats = [
            _make_threat(level=ThreatLevel.LOW, score=20.0),
            _make_threat(level=ThreatLevel.CRITICAL, score=95.0),
        ]
        assessment = self.service.assess_multiple(threats)
        assert assessment.threat_level is ThreatLevel.CRITICAL

    def test_assess_empty_returns_low(self):
        assessment = self.service.assess_multiple([])
        assert assessment.threat_level is ThreatLevel.LOW
        assert len(assessment.recommended_actions) == 0
