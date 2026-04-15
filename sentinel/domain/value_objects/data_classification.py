"""Data classification tiers for SHIELD module."""

from __future__ import annotations

from enum import Enum


class DataClassification(Enum):
    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    CONFIDENTIAL = "CONFIDENTIAL"
    RESTRICTED = "RESTRICTED"

    def requires_redaction(self) -> bool:
        return self in (DataClassification.CONFIDENTIAL, DataClassification.RESTRICTED)

    def allows_external_transmission(self) -> bool:
        return self is DataClassification.PUBLIC
