"""
Application DTOs — Pydantic models for API request/response serialisation.

Architectural Intent:
- Decouples presentation/API concerns from domain entities
- Provides validation via Pydantic for external input
- Ensures domain objects never leak directly to consumers
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field


# ── Agent DTO ────────────────────────────────────────────────────────────

class AgentDTO(BaseModel):
    id: str
    name: str
    framework: str
    model_id: str
    status: str
    registered_tools: list[str] = Field(default_factory=list)
    vaid_agent_id: str = ""
    vaid_capabilities: list[str] = Field(default_factory=list)
    vaid_expired: bool = False
    is_over_privileged: bool = False
    last_seen_at: datetime | None = None


# ── Threat DTO ───────────────────────────────────────────────────────────

class ThreatDTO(BaseModel):
    id: str
    agent_id: str
    category: str
    score: float
    level: str
    description: str
    evidence: dict = Field(default_factory=dict)
    status: str = "OPEN"
    detected_at: datetime | None = None
    detection_tier: int = 1


# ── Incident DTO ─────────────────────────────────────────────────────────

class IncidentDTO(BaseModel):
    id: str
    threat_ids: list[str] = Field(default_factory=list)
    affected_agent_ids: list[str] = Field(default_factory=list)
    severity: str
    status: str
    actions_taken: list[str] = Field(default_factory=list)
    blast_radius_agent_ids: list[str] = Field(default_factory=list)
    created_at: datetime | None = None
    contained_at: datetime | None = None
    resolved_at: datetime | None = None
    mean_time_to_contain_seconds: float | None = None


# ── MCP Server DTO ───────────────────────────────────────────────────────

class MCPServerToolDTO(BaseModel):
    name: str
    description: str
    input_schema: dict = Field(default_factory=dict)


class MCPServerDTO(BaseModel):
    id: str
    name: str
    transport: str
    endpoint: str
    status: str
    auth_required: bool = False
    tools: list[MCPServerToolDTO] = Field(default_factory=list)
    tool_count: int = 0
    is_exposed: bool = False
    is_shadow: bool = False
    discovered_at: datetime | None = None
    last_scanned_at: datetime | None = None


# ── Tool Call DTO ────────────────────────────────────────────────────────

class ToolCallDTO(BaseModel):
    id: str
    agent_id: str
    server_name: str
    tool_name: str
    arguments: dict = Field(default_factory=dict)
    response: dict | None = None
    latency_ms: float = 0.0
    timestamp: datetime | None = None


# ── Detection Result DTO ─────────────────────────────────────────────────

class DetectionResultDTO(BaseModel):
    detected: bool = False
    score: float = 0.0
    threat_level: str = "LOW"
    threat_id: str | None = None
    category: str | None = None
    description: str = ""
    requires_auto_block: bool = False
    requires_auto_contain: bool = False


# ── Shield Result DTO ────────────────────────────────────────────────────

class PIIMatchDTO(BaseModel):
    pii_type: str
    value: str


class ShieldResultDTO(BaseModel):
    has_pii: bool = False
    classification: str = "PUBLIC"
    matches: list[PIIMatchDTO] = Field(default_factory=list)
    redacted_content: str | None = None
    threat_id: str | None = None


# ── Attack Surface Report DTO ────────────────────────────────────────────

class AgentPrivilegeSummaryDTO(BaseModel):
    agent_id: str
    agent_name: str
    tool_count: int
    is_over_privileged: bool
    capabilities: list[str] = Field(default_factory=list)


class AttackSurfaceReportDTO(BaseModel):
    score: float
    risk_category: str
    total_agents: int = 0
    over_privileged_count: int = 0
    total_tools: int = 0
    agents: list[AgentPrivilegeSummaryDTO] = Field(default_factory=list)


# ── Incident Response DTO ────────────────────────────────────────────────

class IncidentResponseDTO(BaseModel):
    incident_id: str
    status: str
    actions_taken: list[str] = Field(default_factory=list)
    threat_level: str = "LOW"
    requires_human_escalation: bool = False
    justification: str = ""


# ── Governance Event DTO ─────────────────────────────────────────────────

class GovernanceEventDTO(BaseModel):
    event_type: str
    source: str = "SENTINEL"
    agent_id: str = ""
    severity: str = "LOW"
    description: str = ""
    evidence: dict = Field(default_factory=dict)
    timestamp: datetime | None = None


# ── Forensic Bundle DTO ──────────────────────────────────────────────────

class ForensicBundleDTO(BaseModel):
    incident_id: str
    incident: IncidentDTO
    threats: list[ThreatDTO] = Field(default_factory=list)
    tool_calls: list[ToolCallDTO] = Field(default_factory=list)
    agents: list[AgentDTO] = Field(default_factory=list)
    generated_at: datetime | None = None


# ── Rate Limit Decision DTO ──────────────────────────────────────────────

class RateLimitDecisionDTO(BaseModel):
    allowed: bool = True
    reason: str = ""
    current_count: int = 0
    limit: int = 0
    window_seconds: int = 60


# ── MCP Validation Result DTO ────────────────────────────────────────────

class MCPValidationResultDTO(BaseModel):
    valid: bool = True
    violations: list[str] = Field(default_factory=list)


# ── Cost Anomaly DTO ─────────────────────────────────────────────────────

class CostAnomalyDTO(BaseModel):
    is_anomaly: bool = False
    agent_id: str = ""
    expected_cost: float = 0.0
    actual_cost: float = 0.0
    ratio: float = 0.0
    threat_id: str | None = None
