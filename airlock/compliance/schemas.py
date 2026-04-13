from __future__ import annotations

"""Pydantic models for the compliance module."""

import logging
from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


class RiskLevel(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AgentInventoryEntry(BaseModel):
    """A single agent entry in the compliance inventory."""

    did: str
    display_name: str
    agent_type: str = "autonomous"
    risk_level: RiskLevel = RiskLevel.MEDIUM
    capabilities: list[str] = Field(default_factory=list)
    deployment_environment: str = "production"
    registered_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    last_assessed_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    compliance_status: str = "pending"
    owner: str = ""
    description: str = ""
    trust_score: float = 0.5
    trust_tier: int = 0


class RiskClassification(BaseModel):
    """Result of risk assessment for an agent."""

    did: str
    risk_level: RiskLevel
    risk_factors: list[str] = Field(default_factory=list)
    mitigation_measures: list[str] = Field(default_factory=list)
    assessed_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    assessed_by: str = "automated"
    confidence: float = 0.8


class IncidentReport(BaseModel):
    """A compliance incident report with hash-chain integrity."""

    incident_id: str
    agent_did: str
    severity: RiskLevel
    incident_type: str
    description: str
    detected_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    reported_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    status: str = "open"
    resolution: str = ""
    affected_users: int = 0
    previous_hash: str = ""
    incident_hash: str = ""


class ComplianceReport(BaseModel):
    """Aggregated compliance report for a given period."""

    report_id: str
    generated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    reporting_period_start: datetime
    reporting_period_end: datetime
    total_agents: int = 0
    agents_by_risk: dict[str, int] = Field(default_factory=dict)
    total_incidents: int = 0
    incidents_by_severity: dict[str, int] = Field(default_factory=dict)
    compliance_score: float = 0.0
    regulatory_mapping: dict[str, object] = Field(default_factory=dict)
    recommendations: list[str] = Field(default_factory=list)
    audit_summary: dict[str, object] = Field(default_factory=dict)
