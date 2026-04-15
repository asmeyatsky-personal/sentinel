"""Composition root — wires all infrastructure implementations together."""

from __future__ import annotations

from dataclasses import dataclass

from sentinel.domain.services.anomaly_detection import AnomalyDetectionService
from sentinel.domain.services.behavioural_baseline import BehaviouralBaselineService
from sentinel.domain.services.pii_detection import PIIDetectionService
from sentinel.domain.services.threat_assessment import ThreatAssessmentService
from sentinel.infrastructure.adapters.in_memory_event_bus import InMemoryEventBus
from sentinel.infrastructure.adapters.notification_adapter import LoggingNotificationAdapter
from sentinel.infrastructure.adapters.pii_scanner import PIIScanner
from sentinel.infrastructure.adapters.rate_limiter import InMemoryRateLimiter
from sentinel.infrastructure.adapters.siem_adapter import LoggingSIEMAdapter
from sentinel.infrastructure.config.settings import SentinelSettings
from sentinel.infrastructure.detection.behavioural_analyser import (
    StatisticalBehaviouralAnalyser,
)
from sentinel.infrastructure.detection.prompt_injection_classifier import (
    PatternBasedInjectionDetector,
)
from sentinel.infrastructure.detection.rule_engine import RuleBasedDetectionEngine
from sentinel.infrastructure.repositories.in_memory_agent_repo import (
    InMemoryAgentRepository,
)
from sentinel.infrastructure.repositories.in_memory_incident_repo import (
    InMemoryIncidentRepository,
)
from sentinel.infrastructure.repositories.in_memory_mcp_server_repo import (
    InMemoryMCPServerRepository,
)
from sentinel.infrastructure.repositories.in_memory_threat_repo import (
    InMemoryThreatRepository,
)
from sentinel.infrastructure.repositories.in_memory_tool_call_repo import (
    InMemoryToolCallRepository,
)


@dataclass
class Container:
    """Dependency injection container holding all SENTINEL components.

    Attributes are typed against concrete implementations but satisfy the
    corresponding domain Protocol ports structurally.
    """

    # Settings
    settings: SentinelSettings

    # Repositories
    agent_repository: InMemoryAgentRepository
    threat_repository: InMemoryThreatRepository
    incident_repository: InMemoryIncidentRepository
    mcp_server_repository: InMemoryMCPServerRepository
    tool_call_repository: InMemoryToolCallRepository

    # Adapters
    event_bus: InMemoryEventBus
    rate_limiter: InMemoryRateLimiter
    siem_adapter: LoggingSIEMAdapter
    notification_adapter: LoggingNotificationAdapter
    pii_scanner: PIIScanner

    # Detection engines
    rule_engine: RuleBasedDetectionEngine
    prompt_injection_detector: PatternBasedInjectionDetector
    behavioural_analyser: StatisticalBehaviouralAnalyser

    # Domain services
    pii_detection_service: PIIDetectionService
    anomaly_detection_service: AnomalyDetectionService
    behavioural_baseline_service: BehaviouralBaselineService
    threat_assessment_service: ThreatAssessmentService


def create_container(settings: SentinelSettings | None = None) -> Container:
    """Instantiate and wire all infrastructure components.

    Parameters
    ----------
    settings:
        Optional pre-built settings. If *None*, settings are loaded from
        environment variables with ``SENTINEL_`` prefix.
    """
    if settings is None:
        settings = SentinelSettings()

    # Domain services (pure, no infra deps)
    pii_detection_service = PIIDetectionService()
    anomaly_detection_service = AnomalyDetectionService()
    behavioural_baseline_service = BehaviouralBaselineService()
    threat_assessment_service = ThreatAssessmentService()

    # Infrastructure adapters
    rate_limiter = InMemoryRateLimiter(
        window_seconds=settings.rate_limit_window_seconds,
        max_calls=settings.rate_limit_max_calls,
    )
    event_bus = InMemoryEventBus()
    siem_adapter = LoggingSIEMAdapter()
    notification_adapter = LoggingNotificationAdapter()
    pii_scanner = PIIScanner(pii_service=pii_detection_service)

    # Detection engines
    rule_engine = RuleBasedDetectionEngine(rate_limiter=rate_limiter)
    prompt_injection_detector = PatternBasedInjectionDetector()
    behavioural_analyser = StatisticalBehaviouralAnalyser()

    # Repositories
    agent_repository = InMemoryAgentRepository()
    threat_repository = InMemoryThreatRepository()
    incident_repository = InMemoryIncidentRepository()
    mcp_server_repository = InMemoryMCPServerRepository()
    tool_call_repository = InMemoryToolCallRepository()

    return Container(
        settings=settings,
        agent_repository=agent_repository,
        threat_repository=threat_repository,
        incident_repository=incident_repository,
        mcp_server_repository=mcp_server_repository,
        tool_call_repository=tool_call_repository,
        event_bus=event_bus,
        rate_limiter=rate_limiter,
        siem_adapter=siem_adapter,
        notification_adapter=notification_adapter,
        pii_scanner=pii_scanner,
        rule_engine=rule_engine,
        prompt_injection_detector=prompt_injection_detector,
        behavioural_analyser=behavioural_analyser,
        pii_detection_service=pii_detection_service,
        anomaly_detection_service=anomaly_detection_service,
        behavioural_baseline_service=behavioural_baseline_service,
        threat_assessment_service=threat_assessment_service,
    )
