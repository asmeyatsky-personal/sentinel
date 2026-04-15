"""
VAID — Verifiable Agent Identity Document

The foundational trust primitive. Cryptographically signed, capability-scoped
identity carried by every monitored agent.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime


@dataclass(frozen=True)
class VAID:
    agent_id: str
    issuer: str
    capabilities: tuple[str, ...]
    issued_at: datetime
    expires_at: datetime
    signature: str

    def is_expired(self) -> bool:
        return datetime.now(UTC) > self.expires_at

    def has_capability(self, capability: str) -> bool:
        return capability in self.capabilities

    def is_valid(self) -> bool:
        return not self.is_expired() and bool(self.signature)
