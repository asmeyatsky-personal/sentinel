"""Event bus port for cross-boundary domain event communication."""

from __future__ import annotations

from typing import Callable, Protocol

from sentinel.domain.events.base import DomainEvent


class EventBusPort(Protocol):
    async def publish(self, events: list[DomainEvent]) -> None: ...
    async def subscribe(self, event_type: type, handler: Callable) -> None: ...
