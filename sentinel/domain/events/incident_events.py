"""Domain events emitted by CONTAIN module."""

from __future__ import annotations

from dataclasses import dataclass

from sentinel.domain.events.base import DomainEvent


@dataclass(frozen=True)
class IncidentEscalatedEvent(DomainEvent):
    previous_severity: str = ""
    new_severity: str = ""
    reason: str = ""


@dataclass(frozen=True)
class AgentIsolationExecutedEvent(DomainEvent):
    target_agent_id: str = ""
    incident_id: str = ""


@dataclass(frozen=True)
class ToolCallBlockedEvent(DomainEvent):
    tool_call_id: str = ""
    tool_name: str = ""
    reason: str = ""


@dataclass(frozen=True)
class ForensicBundleGeneratedEvent(DomainEvent):
    incident_id: str = ""
    bundle_path: str = ""
