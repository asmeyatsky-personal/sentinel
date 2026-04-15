"""
Detect Credential Abuse Use Case — INTERCEPT module

Architectural Intent:
- Monitors for agents using credentials outside their granted scope
- Fetches the agent and its recent tool calls from repositories
- Checks whether any tool calls access servers outside the credential scope
- Checks whether the agent's VAID is expired
- Creates a Threat with API_ABUSE category if violations found
- Returns DetectionResultDTO
"""

from __future__ import annotations

from uuid import uuid4

from sentinel.application.dtos.schemas import DetectionResultDTO
from sentinel.domain.entities.threat import Threat, ThreatCategory
from sentinel.domain.ports.event_bus import EventBusPort
from sentinel.domain.ports.repositories import (
    AgentRepositoryPort,
    ToolCallRepositoryPort,
    ThreatRepositoryPort,
)
from sentinel.domain.value_objects.detection_score import DetectionScore


class DetectCredentialAbuseUseCase:
    """Detects agents using credentials outside their granted scope."""

    def __init__(
        self,
        agent_repository: AgentRepositoryPort,
        tool_call_repository: ToolCallRepositoryPort,
        threat_repository: ThreatRepositoryPort,
        event_bus: EventBusPort,
    ) -> None:
        self._agent_repo = agent_repository
        self._tool_call_repo = tool_call_repository
        self._threat_repo = threat_repository
        self._event_bus = event_bus

    async def execute(
        self,
        agent_id: str,
        credential_scope: tuple[str, ...] = (),
    ) -> DetectionResultDTO:
        agent = await self._agent_repo.get_by_id(agent_id)
        if agent is None:
            return DetectionResultDTO(
                description=f"Agent '{agent_id}' not found",
            )

        tool_calls = await self._tool_call_repo.get_by_agent_id(agent_id)

        violations: list[str] = []

        # Check for tool calls accessing servers outside credential scope
        if credential_scope:
            for tc in tool_calls:
                if tc.server_name not in credential_scope:
                    violations.append(
                        f"Tool call to '{tc.server_name}' is outside "
                        f"credential scope {credential_scope}"
                    )

        # Check if agent VAID is expired
        vaid_expired = agent.vaid.is_expired()
        if vaid_expired:
            violations.append(
                f"Agent VAID expired at {agent.vaid.expires_at.isoformat()}"
            )

        if not violations:
            return DetectionResultDTO(
                description="No credential abuse detected",
            )

        # Credential abuse detected — create threat
        score_value = min(60.0 + len(violations) * 10.0, 100.0)
        score = DetectionScore(value=score_value)

        threat = Threat(
            id=str(uuid4()),
            agent_id=agent_id,
            category=ThreatCategory.API_ABUSE,
            score=score,
            level=score.to_threat_level(),
            description=(
                f"Credential abuse detected for agent '{agent_id}': "
                f"{'; '.join(violations)}"
            ),
            evidence={
                "violations": violations,
                "vaid_expired": vaid_expired,
                "tool_call_count": len(tool_calls),
                "credential_scope": list(credential_scope),
            },
            detection_tier=1,
        )

        await self._threat_repo.save(threat)

        return DetectionResultDTO(
            detected=True,
            score=score.value,
            threat_level=score.to_threat_level().value,
            threat_id=threat.id,
            category=ThreatCategory.API_ABUSE.value,
            description=threat.description,
            requires_auto_block=threat.requires_auto_block(),
            requires_auto_contain=threat.requires_auto_contain(),
        )
