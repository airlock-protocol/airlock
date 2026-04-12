"""Pydantic v2 models for the RBI FREE-AI compliance module."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class RiskLevel(StrEnum):
    """Agent risk classification levels."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AgentInventoryEntry(BaseModel):
    """AI Agent/Model inventory entry -- FREE-AI Rec #14."""

    did: str  # did:key:...
    display_name: str
    agent_type: str = "autonomous"  # autonomous, semi-autonomous, tool
    risk_level: RiskLevel = RiskLevel.MEDIUM
    capabilities: list[str] = Field(default_factory=list)
    deployment_environment: str = "production"
    registered_at: datetime
    last_assessed_at: datetime | None = None
    compliance_status: str = "pending"  # pending, compliant, non_compliant, under_review
    owner: str = ""
    description: str = ""
    trust_score: float | None = None
    trust_tier: int | None = None


class RiskClassification(BaseModel):
    """Risk assessment for an agent -- FREE-AI Rec #15."""

    did: str
    risk_level: RiskLevel
    risk_factors: list[str] = Field(default_factory=list)
    mitigation_measures: list[str] = Field(default_factory=list)
    assessed_at: datetime
    assessed_by: str = "automated"
    confidence: float = Field(default=0.8, ge=0.0, le=1.0)


class IncidentReport(BaseModel):
    """AI incident report -- FREE-AI Rec #13."""

    incident_id: str
    agent_did: str
    severity: RiskLevel
    incident_type: str  # bias, hallucination, unauthorized_action, data_leak, performance_degradation
    description: str
    detected_at: datetime
    reported_at: datetime
    status: str = "open"  # open, investigating, resolved, closed
    resolution: str | None = None
    affected_users: int = 0
    previous_hash: str = ""
    incident_hash: str = ""


class ComplianceReport(BaseModel):
    """Compliance report mapped to FREE-AI recommendations -- Rec #16."""

    report_id: str
    generated_at: datetime
    reporting_period_start: datetime
    reporting_period_end: datetime
    total_agents: int
    agents_by_risk: dict[str, int] = Field(default_factory=dict)
    total_incidents: int
    incidents_by_severity: dict[str, int] = Field(default_factory=dict)
    compliance_score: float = Field(default=0.0, ge=0.0, le=100.0)
    free_ai_mapping: dict[str, Any] = Field(default_factory=dict)
    recommendations: list[str] = Field(default_factory=list)
    audit_summary: dict[str, Any] = Field(default_factory=dict)
