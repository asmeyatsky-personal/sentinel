"""In-memory implementation of EventBusPort."""

from __future__ import annotations

import asyncio
import logging
from collections import defaultdict
from typing import Callable

from sentinel.domain.events.base import DomainEvent

logger = logging.getLogger(__name__)


class InMemoryEventBus:
    """Simple in-memory pub/sub event bus with async handler dispatch."""

    def __init__(self) -> None:
        self._handlers: dict[type, list[Callable]] = defaultdict(list)

    async def publish(self, events: list[DomainEvent]) -> None:
        for event in events:
            event_type = type(event)
            handlers = self._handlers.get(event_type, [])
            for handler in handlers:
                try:
                    result = handler(event)
                    if asyncio.iscoroutine(result):
                        await result
                except Exception:
                    logger.exception(
                        "Event handler %s failed for %s",
                        handler.__name__,
                        event_type.__name__,
                    )

    async def subscribe(self, event_type: type, handler: Callable) -> None:
        self._handlers[event_type].append(handler)
