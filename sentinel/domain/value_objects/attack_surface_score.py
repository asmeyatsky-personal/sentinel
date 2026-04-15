"""Attack surface composite score (0–100) for RECON module."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class AttackSurfaceScore:
    value: float

    def __post_init__(self) -> None:
        if not 0.0 <= self.value <= 100.0:
            raise ValueError(f"AttackSurfaceScore must be 0–100, got {self.value}")

    @property
    def risk_category(self) -> str:
        if self.value >= 80.0:
            return "CRITICAL"
        if self.value >= 60.0:
            return "HIGH"
        if self.value >= 40.0:
            return "MEDIUM"
        return "LOW"
