"""
Domain Event Base

Architectural Intent:
- Foundation for all domain events in SENTINEL™
- Immutable, timestamped, tied to an aggregate
- Used for cross-boundary communication between modules
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from uuid import uuid4


@dataclass(frozen=True)
class DomainEvent:
    aggregate_id: str
    event_id: str = field(default_factory=lambda: str(uuid4()))
    occurred_at: datetime = field(default_factory=lambda: datetime.now(UTC))
