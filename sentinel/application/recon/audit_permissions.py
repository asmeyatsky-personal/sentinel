"""
Audit Permissions Use Case — RECON module

Architectural Intent:
- Analyses aggregate tool permissions across all agents
- Flags over-privileged agents exceeding tool thresholds
- Computes an AttackSurfaceScore reflecting overall exposure
- Publishes events for over-privileged agents
"""

from __future__ import annotations

from sentinel.domain.events.recon_events import OverPrivilegedAgentDetectedEvent
from sentinel.domain.ports.event_bus import EventBusPort
from sentinel.domain.ports.repositories import AgentRepositoryPort
from sentinel.domain.value_objects.attack_surface_score import AttackSurfaceScore
from sentinel.application.dtos.schemas import (
    AgentPrivilegeSummaryDTO,
    AttackSurfaceReportDTO,
)


class AuditPermissionsUseCase:
    """Analyses aggregate tool permissions, flags over-privileged agents."""

    def __init__(
        self,
        agent_repository: AgentRepositoryPort,
        event_bus: EventBusPort,
    ) -> None:
        self._agent_repo = agent_repository
        self._event_bus = event_bus

    async def execute(self, max_tools_threshold: int = 10) -> AttackSurfaceReportDTO:
        agents = await self._agent_repo.get_all()

        events = []
        summaries: list[AgentPrivilegeSummaryDTO] = []
        total_tools = 0
        over_privileged_count = 0

        for agent in agents:
            tool_count = len(agent.registered_tools)
            total_tools += tool_count
            is_over = agent.is_over_privileged(max_tools_threshold)

            if is_over:
                over_privileged_count += 1
                events.append(
                    OverPrivilegedAgentDetectedEvent(
                        aggregate_id=agent.id,
                        tool_count=tool_count,
                        excess_tools=agent.registered_tools[max_tools_threshold:],
                    )
                )

            summaries.append(
                AgentPrivilegeSummaryDTO(
                    agent_id=agent.id,
                    agent_name=agent.name,
                    tool_count=tool_count,
                    is_over_privileged=is_over,
                    capabilities=list(agent.vaid.capabilities),
                )
            )

        # Compute attack surface score: weighted by over-privileged ratio and tool density
        total_agents = len(agents) if agents else 1
        over_priv_ratio = over_privileged_count / total_agents
        avg_tools = total_tools / total_agents if agents else 0
        tool_density_factor = min(avg_tools / 20.0, 1.0)  # normalise to 0-1

        raw_score = (over_priv_ratio * 60.0) + (tool_density_factor * 40.0)
        score = AttackSurfaceScore(value=min(raw_score, 100.0))

        if events:
            await self._event_bus.publish(events)

        return AttackSurfaceReportDTO(
            score=score.value,
            risk_category=score.risk_category,
            total_agents=len(agents),
            over_privileged_count=over_privileged_count,
            total_tools=total_tools,
            agents=summaries,
        )
