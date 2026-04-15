"""
Threat Assessment Domain Service

Evaluates threat signals and determines response actions.
Pure domain logic — no infrastructure dependencies.
"""

from __future__ import annotations

from dataclasses import dataclass

from sentinel.domain.entities.incident import ResponseAction
from sentinel.domain.entities.threat import Threat, ThreatCategory
from sentinel.domain.value_objects.threat_level import ThreatLevel


@dataclass(frozen=True)
class ThreatAssessment:
    threat_level: ThreatLevel
    recommended_actions: tuple[ResponseAction, ...]
    requires_human_escalation: bool
    justification: str


class ThreatAssessmentService:
    """Determines appropriate response for detected threats."""

    def assess(self, threat: Threat) -> ThreatAssessment:
        actions = self._determine_actions(threat)
        requires_human = self._requires_human_escalation(threat)
        justification = self._build_justification(threat)

        return ThreatAssessment(
            threat_level=threat.level,
            recommended_actions=tuple(actions),
            requires_human_escalation=requires_human,
            justification=justification,
        )

    def assess_multiple(self, threats: list[Threat]) -> ThreatAssessment:
        if not threats:
            return ThreatAssessment(
                threat_level=ThreatLevel.LOW,
                recommended_actions=(),
                requires_human_escalation=False,
                justification="No threats detected",
            )
        worst = max(threats, key=lambda t: t.score.value)
        all_actions: list[ResponseAction] = []
        for threat in threats:
            all_actions.extend(self._determine_actions(threat))
        unique_actions = tuple(dict.fromkeys(all_actions))
        any_human = any(self._requires_human_escalation(t) for t in threats)

        return ThreatAssessment(
            threat_level=worst.level,
            recommended_actions=unique_actions,
            requires_human_escalation=any_human,
            justification=f"Assessed {len(threats)} threats; worst={worst.category.value}",
        )

    def _determine_actions(self, threat: Threat) -> list[ResponseAction]:
        actions: list[ResponseAction] = []

        if threat.level is ThreatLevel.CRITICAL:
            actions.append(ResponseAction.AGENT_ISOLATED)
            actions.append(ResponseAction.CREDENTIALS_ROTATED)
            actions.append(ResponseAction.TICKET_CREATED)
        elif threat.level is ThreatLevel.HIGH:
            actions.append(ResponseAction.TOOL_BLOCKED)
            actions.append(ResponseAction.TICKET_CREATED)
        elif threat.level is ThreatLevel.MEDIUM:
            actions.append(ResponseAction.TICKET_CREATED)

        if threat.category is ThreatCategory.PROMPT_INJECTION:
            if threat.level in (ThreatLevel.MEDIUM, ThreatLevel.HIGH, ThreatLevel.CRITICAL):
                if ResponseAction.TOOL_BLOCKED not in actions:
                    actions.append(ResponseAction.TOOL_BLOCKED)

        if threat.category is ThreatCategory.DATA_EXFILTRATION:
            if ResponseAction.AGENT_ISOLATED not in actions:
                actions.append(ResponseAction.AGENT_ISOLATED)

        return actions

    def _requires_human_escalation(self, threat: Threat) -> bool:
        if threat.level in (ThreatLevel.HIGH, ThreatLevel.CRITICAL):
            return True
        if threat.category in (
            ThreatCategory.MODEL_INTEGRITY,
            ThreatCategory.COORDINATION_ANOMALY,
        ):
            return True
        return threat.detection_tier == 2

    def _build_justification(self, threat: Threat) -> str:
        return (
            f"Threat {threat.id}: category={threat.category.value}, "
            f"score={threat.score.value}, tier={threat.detection_tier}"
        )
