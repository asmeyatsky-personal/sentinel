"""
Generate Forensic Bundle Use Case — CONTAIN module

Architectural Intent:
- Collects all evidence related to an incident
- Gathers threats, tool calls, and agent data referenced by the incident
- Produces a structured forensic evidence package (ForensicBundleDTO)
- Publishes ForensicBundleGeneratedEvent for audit trail

Parallelisation Notes:
- Threat, tool call, and agent fetches run concurrently (independent data)
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime

from sentinel.domain.events.incident_events import ForensicBundleGeneratedEvent
from sentinel.domain.ports.event_bus import EventBusPort
from sentinel.domain.ports.repositories import (
    AgentRepositoryPort,
    IncidentRepositoryPort,
    ThreatRepositoryPort,
    ToolCallRepositoryPort,
)
from sentinel.application.dtos.schemas import (
    AgentDTO,
    ForensicBundleDTO,
    IncidentDTO,
    ThreatDTO,
    ToolCallDTO,
)


class GenerateForensicBundleUseCase:
    """Produces a structured forensic evidence package for an incident."""

    def __init__(
        self,
        incident_repository: IncidentRepositoryPort,
        threat_repository: ThreatRepositoryPort,
        tool_call_repository: ToolCallRepositoryPort,
        agent_repository: AgentRepositoryPort,
        event_bus: EventBusPort,
    ) -> None:
        self._incident_repo = incident_repository
        self._threat_repo = threat_repository
        self._tool_call_repo = tool_call_repository
        self._agent_repo = agent_repository
        self._event_bus = event_bus

    async def execute(self, incident_id: str) -> ForensicBundleDTO:
        incident = await self._incident_repo.get_by_id(incident_id)
        if incident is None:
            raise ValueError(f"Incident '{incident_id}' not found")

        # Fetch threats, tool calls per agent, and agent details concurrently
        threat_tasks = [
            self._threat_repo.get_by_id(tid) for tid in incident.threat_ids
        ]
        tool_call_tasks = [
            self._tool_call_repo.get_by_agent_id(aid)
            for aid in incident.affected_agent_ids
        ]
        agent_tasks = [
            self._agent_repo.get_by_id(aid)
            for aid in incident.affected_agent_ids
        ]

        all_results = await asyncio.gather(
            *threat_tasks, *tool_call_tasks, *agent_tasks,
            return_exceptions=True,
        )

        # Partition results
        num_threats = len(incident.threat_ids)
        num_agents = len(incident.affected_agent_ids)

        raw_threats = all_results[:num_threats]
        raw_tool_calls = all_results[num_threats : num_threats + num_agents]
        raw_agents = all_results[num_threats + num_agents :]

        # Build DTOs — skip errors and None values
        threat_dtos = [
            ThreatDTO(
                id=t.id,
                agent_id=t.agent_id,
                category=t.category.value,
                score=t.score.value,
                level=t.level.value,
                description=t.description,
                evidence=t.evidence,
                status=t.status.value,
                detected_at=t.detected_at,
                detection_tier=t.detection_tier,
            )
            for t in raw_threats
            if t is not None and not isinstance(t, BaseException)
        ]

        tool_call_dtos: list[ToolCallDTO] = []
        for tc_list in raw_tool_calls:
            if isinstance(tc_list, BaseException) or tc_list is None:
                continue
            for tc in tc_list:
                tool_call_dtos.append(
                    ToolCallDTO(
                        id=tc.id,
                        agent_id=tc.agent_id,
                        server_name=tc.server_name,
                        tool_name=tc.tool_name,
                        arguments=tc.arguments,
                        response=tc.response,
                        latency_ms=tc.latency_ms,
                        timestamp=tc.timestamp,
                    )
                )

        agent_dtos = [
            AgentDTO(
                id=a.id,
                name=a.name,
                framework=a.framework,
                model_id=a.model_id,
                status=a.status.value,
                registered_tools=list(a.registered_tools),
                vaid_agent_id=a.vaid.agent_id,
                vaid_capabilities=list(a.vaid.capabilities),
                vaid_expired=a.vaid.is_expired(),
                is_over_privileged=a.is_over_privileged(),
                last_seen_at=a.last_seen_at,
            )
            for a in raw_agents
            if a is not None and not isinstance(a, BaseException)
        ]

        incident_dto = IncidentDTO(
            id=incident.id,
            threat_ids=list(incident.threat_ids),
            affected_agent_ids=list(incident.affected_agent_ids),
            severity=incident.severity.value,
            status=incident.status.value,
            actions_taken=[a.value for a in incident.actions_taken],
            blast_radius_agent_ids=list(incident.blast_radius_agent_ids),
            created_at=incident.created_at,
            contained_at=incident.contained_at,
            resolved_at=incident.resolved_at,
            mean_time_to_contain_seconds=incident.mean_time_to_contain_seconds,
        )

        bundle = ForensicBundleDTO(
            incident_id=incident_id,
            incident=incident_dto,
            threats=threat_dtos,
            tool_calls=tool_call_dtos,
            agents=agent_dtos,
            generated_at=datetime.now(UTC),
        )

        await self._event_bus.publish([
            ForensicBundleGeneratedEvent(
                aggregate_id=incident_id,
                incident_id=incident_id,
                bundle_path=f"forensic/{incident_id}",
            ),
        ])

        return bundle
