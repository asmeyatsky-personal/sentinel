"""Domain events emitted by RECON module."""

from __future__ import annotations

from dataclasses import dataclass

from sentinel.domain.events.base import DomainEvent


@dataclass(frozen=True)
class AgentDiscoveredEvent(DomainEvent):
    agent_name: str = ""
    framework: str = ""
    tool_count: int = 0


@dataclass(frozen=True)
class ShadowAgentDetectedEvent(DomainEvent):
    agent_name: str = ""
    endpoint: str = ""


@dataclass(frozen=True)
class MCPServerDiscoveredEvent(DomainEvent):
    server_name: str = ""
    tool_count: int = 0
    is_exposed: bool = False


@dataclass(frozen=True)
class ConfigurationDriftDetectedEvent(DomainEvent):
    resource_type: str = ""
    resource_id: str = ""
    changes: tuple[str, ...] = ()


@dataclass(frozen=True)
class OverPrivilegedAgentDetectedEvent(DomainEvent):
    tool_count: int = 0
    excess_tools: tuple[str, ...] = ()
