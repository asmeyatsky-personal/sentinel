"""SIEM integration port — feeds Chronicle, Splunk, Datadog."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True)
class SIEMEvent:
    event_type: str
    severity: str
    source: str
    agent_id: str
    description: str
    evidence: dict
    timestamp: str


class SIEMIntegrationPort(Protocol):
    async def send_event(self, event: SIEMEvent) -> None: ...
    async def send_batch(self, events: list[SIEMEvent]) -> None: ...
