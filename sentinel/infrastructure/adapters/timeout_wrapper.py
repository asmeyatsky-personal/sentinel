"""
Timeout Wrapper — Infrastructure adapter utility

Generic async timeout wrapper for port operations.
Returns a default value on timeout or re-raises if no default provided.
"""

from __future__ import annotations

import asyncio
from typing import Awaitable, TypeVar

T = TypeVar("T")


async def with_timeout(
    coro: Awaitable[T],
    timeout_ms: float = 5000.0,
    default: T | None = None,
) -> T:
    """Execute an awaitable with a timeout. Returns default on timeout."""
    try:
        return await asyncio.wait_for(coro, timeout=timeout_ms / 1000.0)
    except asyncio.TimeoutError:
        if default is not None:
            return default
        raise
