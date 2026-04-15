"""
Incident Entity

Represents a security incident managed by the CONTAIN module.
Aggregates one or more threats and tracks response actions.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from enum import Enum

from sentinel.domain.events.base import DomainEvent
from sentinel.domain.value_objects.threat_level import ThreatLevel


class IncidentStatus(Enum):
    DETECTED = "DETECTED"
    CONTAINING = "CONTAINING"
    CONTAINED = "CONTAINED"
    INVESTIGATING = "INVESTIGATING"
    RESOLVED = "RESOLVED"


class ResponseAction(Enum):
    AGENT_ISOLATED = "AGENT_ISOLATED"
    TOOL_BLOCKED = "TOOL_BLOCKED"
    AGENT_QUARANTINED = "AGENT_QUARANTINED"
    CREDENTIALS_ROTATED = "CREDENTIALS_ROTATED"
    KILL_SWITCH = "KILL_SWITCH"
    TICKET_CREATED = "TICKET_CREATED"


@dataclass(frozen=True)
class IncidentCreatedEvent(DomainEvent):
    severity: str = ""


@dataclass(frozen=True)
class IncidentContainedEvent(DomainEvent):
    actions_taken: tuple[str, ...] = ()


@dataclass(frozen=True)
class Incident:
    id: str
    threat_ids: tuple[str, ...]
    affected_agent_ids: tuple[str, ...]
    severity: ThreatLevel
    status: IncidentStatus = IncidentStatus.DETECTED
    actions_taken: tuple[ResponseAction, ...] = ()
    blast_radius_agent_ids: tuple[str, ...] = ()
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    contained_at: datetime | None = None
    resolved_at: datetime | None = None
    domain_events: tuple[DomainEvent, ...] = field(default=())

    def add_response_action(self, action: ResponseAction) -> Incident:
        return replace(
            self,
            actions_taken=self.actions_taken + (action,),
            status=IncidentStatus.CONTAINING,
        )

    def mark_contained(self) -> Incident:
        return replace(
            self,
            status=IncidentStatus.CONTAINED,
            contained_at=datetime.now(UTC),
            domain_events=self.domain_events + (
                IncidentContainedEvent(
                    aggregate_id=self.id,
                    actions_taken=tuple(a.value for a in self.actions_taken),
                ),
            ),
        )

    def resolve(self) -> Incident:
        return replace(
            self,
            status=IncidentStatus.RESOLVED,
            resolved_at=datetime.now(UTC),
        )

    def expand_blast_radius(self, agent_ids: tuple[str, ...]) -> Incident:
        existing = set(self.blast_radius_agent_ids)
        new_ids = tuple(aid for aid in agent_ids if aid not in existing)
        return replace(
            self,
            blast_radius_agent_ids=self.blast_radius_agent_ids + new_ids,
        )

    @property
    def mean_time_to_contain_seconds(self) -> float | None:
        if self.contained_at is None:
            return None
        return (self.contained_at - self.created_at).total_seconds()
