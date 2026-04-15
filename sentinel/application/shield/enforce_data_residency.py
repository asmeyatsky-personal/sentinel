"""
Enforce Data Residency Use Case — SHIELD module

Architectural Intent:
- Ensures agent operations respect jurisdictional data residency requirements
- Maps PII types to their home regions (e.g. Kenyan national IDs belong to KE)
- Checks whether detected PII is being sent to a region that is not its home
- Returns compliance result with any violations found
- Publishes DataLeakageDetectedEvent when cross-border PII transfer detected
"""

from __future__ import annotations

from sentinel.domain.events.detection_events import DataLeakageDetectedEvent
from sentinel.domain.ports.event_bus import EventBusPort
from sentinel.domain.services.pii_detection import PIIDetectionService


# Maps region codes to PII pattern names that are jurisdictionally bound there
REGION_PII_PATTERNS: dict[str, list[str]] = {
    "KE": ["kenyan_national_id"],
    "ZA": ["south_african_id"],
    "NG": ["nigerian_bvn"],
}

# Reverse lookup: PII pattern name -> home region
_PII_HOME_REGION: dict[str, str] = {
    pii_type: region
    for region, pii_types in REGION_PII_PATTERNS.items()
    for pii_type in pii_types
}


class EnforceDataResidencyUseCase:
    """Validates that PII is not transferred outside its home jurisdiction."""

    def __init__(
        self,
        pii_detection_service: PIIDetectionService,
        event_bus: EventBusPort,
    ) -> None:
        self._pii_service = pii_detection_service
        self._event_bus = event_bus

    async def execute(
        self,
        content: str,
        target_region: str,
        source_region: str,
        agent_id: str = "",
    ) -> dict:
        matches = self._pii_service.detect(content)

        violations: list[dict] = []

        for pattern, _matched_value in matches:
            home_region = _PII_HOME_REGION.get(pattern.name)
            if home_region is not None and home_region != target_region:
                violations.append({
                    "pii_type": pattern.name,
                    "home_region": home_region,
                    "target_region": target_region,
                })

        compliant = len(violations) == 0

        if not compliant:
            pii_types = tuple(v["pii_type"] for v in violations)
            await self._event_bus.publish([
                DataLeakageDetectedEvent(
                    aggregate_id=agent_id or "unknown",
                    pii_types=pii_types,
                    destination=target_region,
                    classification="RESTRICTED",
                ),
            ])

        return {
            "compliant": compliant,
            "violations": violations,
        }
