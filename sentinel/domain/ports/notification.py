"""Notification port — incident tickets, alerts, escalations."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True)
class IncidentTicket:
    title: str
    severity: str
    description: str
    affected_agents: tuple[str, ...]
    recommended_actions: tuple[str, ...]


class NotificationPort(Protocol):
    async def create_incident_ticket(self, ticket: IncidentTicket) -> str: ...
    async def send_alert(self, channel: str, message: str) -> None: ...
