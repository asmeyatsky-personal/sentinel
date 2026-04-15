"""SENTINEL platform configuration via Pydantic BaseSettings."""

from __future__ import annotations

from pydantic import SecretStr
from pydantic_settings import BaseSettings


class SentinelSettings(BaseSettings):
    """Central configuration for the SENTINEL platform.

    Values are loaded from environment variables prefixed with ``SENTINEL_``
    (e.g. ``SENTINEL_TIER1_THRESHOLD=70.0``).

    Secrets use SecretStr to prevent accidental exposure in logs/repr.
    """

    model_config = {"env_prefix": "SENTINEL_"}

    # Detection thresholds (0-100)
    tier1_threshold: float = 70.0
    tier2_threshold: float = 40.0

    # Rate limiter
    rate_limit_window_seconds: float = 60.0
    rate_limit_max_calls: int = 100

    # SIEM integration target
    siem_target: str = "logging"  # "logging" | "chronicle" | "splunk" | "datadog"
    siem_endpoint: str = ""
    siem_api_key: SecretStr = SecretStr("")

    # Notification
    notification_target: str = "logging"  # "logging" | "pagerduty" | "slack"
    slack_webhook_url: SecretStr = SecretStr("")
    pagerduty_routing_key: SecretStr = SecretStr("")

    # MCP server
    mcp_transport: str = "stdio"
    mcp_host: str = "127.0.0.1"
    mcp_port: int = 8765
    mcp_api_key: str = ""  # API key for privileged MCP operations (isolate)

    # Behavioural analysis
    baseline_window_size: int = 1000
    anomaly_alpha: float = 0.1

    # PII detection
    pii_redaction_enabled: bool = True

    # Data residency
    data_residency_enabled: bool = False
    allowed_regions: list[str] = []
