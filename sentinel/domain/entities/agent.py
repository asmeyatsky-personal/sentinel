"""
Agent Entity

Represents a monitored agent in the SENTINEL™ estate.
Immutable — state changes produce new instances.
Aggregate root for agent-related operations.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from enum import Enum

from sentinel.domain.events.base import DomainEvent
from sentinel.domain.value_objects.vaid import VAID


class AgentStatus(Enum):
    ACTIVE = "ACTIVE"
    ISOLATED = "ISOLATED"
    QUARANTINED = "QUARANTINED"
    TERMINATED = "TERMINATED"


@dataclass(frozen=True)
class AgentIsolatedEvent(DomainEvent):
    reason: str = ""


@dataclass(frozen=True)
class AgentQuarantinedEvent(DomainEvent):
    reason: str = ""


@dataclass(frozen=True)
class AgentTerminatedEvent(DomainEvent):
    reason: str = ""


@dataclass(frozen=True)
class Agent:
    id: str
    name: str
    vaid: VAID
    framework: str
    model_id: str
    registered_tools: tuple[str, ...]
    status: AgentStatus = AgentStatus.ACTIVE
    last_seen_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    domain_events: tuple[DomainEvent, ...] = field(default=())

    def isolate(self, reason: str) -> Agent:
        if self.status is not AgentStatus.ACTIVE:
            raise ValueError(f"Cannot isolate agent in {self.status.value} state")
        return replace(
            self,
            status=AgentStatus.ISOLATED,
            domain_events=self.domain_events + (
                AgentIsolatedEvent(aggregate_id=self.id, reason=reason),
            ),
        )

    def quarantine(self, reason: str) -> Agent:
        if self.status not in (AgentStatus.ACTIVE, AgentStatus.ISOLATED):
            raise ValueError(f"Cannot quarantine agent in {self.status.value} state")
        return replace(
            self,
            status=AgentStatus.QUARANTINED,
            domain_events=self.domain_events + (
                AgentQuarantinedEvent(aggregate_id=self.id, reason=reason),
            ),
        )

    def terminate(self, reason: str) -> Agent:
        return replace(
            self,
            status=AgentStatus.TERMINATED,
            domain_events=self.domain_events + (
                AgentTerminatedEvent(aggregate_id=self.id, reason=reason),
            ),
        )

    def is_over_privileged(self, max_tools: int = 10) -> bool:
        return len(self.registered_tools) > max_tools

    def has_tool(self, tool_name: str) -> bool:
        return tool_name in self.registered_tools

    def heartbeat(self) -> Agent:
        return replace(self, last_seen_at=datetime.now(UTC))
