"""Logging-based notification adapter implementing NotificationPort."""

from __future__ import annotations

import uuid

import structlog

from sentinel.domain.ports.notification import IncidentTicket

logger = structlog.get_logger(__name__)


class LoggingNotificationAdapter:
    """Logs incident tickets and alerts via structlog.

    Production implementation would integrate with PagerDuty, Jira, Slack, etc.
    """

    async def create_incident_ticket(self, ticket: IncidentTicket) -> str:
        ticket_id = f"TICKET-{uuid.uuid4().hex[:8].upper()}"
        logger.info(
            "incident_ticket_created",
            ticket_id=ticket_id,
            title=ticket.title,
            severity=ticket.severity,
            description=ticket.description,
            affected_agents=ticket.affected_agents,
            recommended_actions=ticket.recommended_actions,
        )
        return ticket_id

    async def send_alert(self, channel: str, message: str) -> None:
        logger.warning(
            "alert_sent",
            channel=channel,
            message=message,
        )
