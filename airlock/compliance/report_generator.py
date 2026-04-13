from __future__ import annotations

"""Compliance report generation."""

import logging
import uuid
from datetime import UTC, datetime

from airlock.compliance.regulatory_mapper import RegulatoryMapper
from airlock.compliance.incident import IncidentStore
from airlock.compliance.inventory import AgentInventory
from airlock.compliance.schemas import ComplianceReport

logger = logging.getLogger(__name__)


class ComplianceReportGenerator:
    """Generates compliance reports from inventory and incident data."""

    def __init__(
        self,
        inventory: AgentInventory,
        incident_store: IncidentStore,
    ) -> None:
        self._inventory = inventory
        self._incident_store = incident_store
        self._mapper = RegulatoryMapper()

    def generate(
        self,
        period_start: datetime,
        period_end: datetime,
    ) -> ComplianceReport:
        """Generate a full compliance report for the given period."""
        agents = self._inventory.list_all()
        incidents = self._incident_store.list_all()

        # Filter incidents to the reporting period
        period_incidents = [
            i
            for i in incidents
            if period_start <= i.detected_at <= period_end
        ]

        agents_by_risk = self._inventory.count_by_risk()
        incidents_by_severity = self._count_period_incidents(period_incidents)

        compliance_score = self._compute_compliance_score(
            total_agents=len(agents),
            agents_by_risk=agents_by_risk,
            total_incidents=len(period_incidents),
            incidents_by_severity=incidents_by_severity,
        )

        regulatory_mapping = self._mapper.map_compliance_status(
            self._inventory,
            self._incident_store,
        )

        recommendations = self._generate_recommendations(
            agents_by_risk=agents_by_risk,
            incidents_by_severity=incidents_by_severity,
        )

        return ComplianceReport(
            report_id=str(uuid.uuid4()),
            generated_at=datetime.now(UTC),
            reporting_period_start=period_start,
            reporting_period_end=period_end,
            total_agents=len(agents),
            agents_by_risk=agents_by_risk,
            total_incidents=len(period_incidents),
            incidents_by_severity=incidents_by_severity,
            compliance_score=compliance_score,
            regulatory_mapping=regulatory_mapping,
            recommendations=recommendations,
            audit_summary=self.generate_audit_summary(),
        )

    def generate_for_agent(
        self,
        did: str,
        period_start: datetime,
        period_end: datetime,
    ) -> ComplianceReport | None:
        """Generate a compliance report for a specific agent."""
        entry = self._inventory.get(did)
        if entry is None:
            return None

        incidents = self._incident_store.list_by_agent(did)
        period_incidents = [
            i
            for i in incidents
            if period_start <= i.detected_at <= period_end
        ]

        incidents_by_severity: dict[str, int] = {}
        for inc in period_incidents:
            key = inc.severity.value
            incidents_by_severity[key] = incidents_by_severity.get(key, 0) + 1

        agents_by_risk = {entry.risk_level.value: 1}
        compliance_score = self._compute_compliance_score(
            total_agents=1,
            agents_by_risk=agents_by_risk,
            total_incidents=len(period_incidents),
            incidents_by_severity=incidents_by_severity,
        )

        return ComplianceReport(
            report_id=str(uuid.uuid4()),
            generated_at=datetime.now(UTC),
            reporting_period_start=period_start,
            reporting_period_end=period_end,
            total_agents=1,
            agents_by_risk=agents_by_risk,
            total_incidents=len(period_incidents),
            incidents_by_severity=incidents_by_severity,
            compliance_score=compliance_score,
            regulatory_mapping={},
            recommendations=[],
            audit_summary={},
        )

    def generate_audit_summary(self) -> dict[str, object]:
        """Generate a summary of audit-relevant data."""
        agents = self._inventory.list_all()
        incidents = self._incident_store.list_all()

        open_incidents = [i for i in incidents if i.status == "open"]
        resolved_incidents = [i for i in incidents if i.status == "resolved"]

        return {
            "total_agents": len(agents),
            "agents_by_risk": self._inventory.count_by_risk(),
            "total_incidents": len(incidents),
            "open_incidents": len(open_incidents),
            "resolved_incidents": len(resolved_incidents),
            "incident_chain_hash": self._incident_store.last_hash,
        }

    def _count_period_incidents(
        self,
        incidents: list[object],
    ) -> dict[str, int]:
        """Count incidents by severity for a list of incidents."""
        from airlock.compliance.schemas import IncidentReport

        counts: dict[str, int] = {}
        for inc in incidents:
            if isinstance(inc, IncidentReport):
                key = inc.severity.value
                counts[key] = counts.get(key, 0) + 1
        return counts

    def _compute_compliance_score(
        self,
        total_agents: int,
        agents_by_risk: dict[str, int],
        total_incidents: int,
        incidents_by_severity: dict[str, int],
    ) -> float:
        """Compute a 0-100 compliance score."""
        if total_agents == 0:
            return 100.0

        score = 100.0

        # Deduct for high-risk agents
        high_risk = agents_by_risk.get("high", 0) + agents_by_risk.get("critical", 0)
        risk_ratio = high_risk / total_agents if total_agents > 0 else 0.0
        score -= risk_ratio * 30.0

        # Deduct for incidents
        critical_incidents = incidents_by_severity.get("critical", 0)
        high_incidents = incidents_by_severity.get("high", 0)
        score -= critical_incidents * 10.0
        score -= high_incidents * 5.0
        score -= total_incidents * 1.0

        return max(0.0, min(100.0, score))

    def _generate_recommendations(
        self,
        agents_by_risk: dict[str, int],
        incidents_by_severity: dict[str, int],
    ) -> list[str]:
        """Generate actionable recommendations based on current state."""
        recommendations: list[str] = []

        critical_count = agents_by_risk.get("critical", 0)
        high_count = agents_by_risk.get("high", 0)

        if critical_count > 0:
            recommendations.append(
                f"Immediate review required: {critical_count} agent(s) classified as critical risk"
            )
        if high_count > 0:
            recommendations.append(
                f"Schedule risk assessment for {high_count} high-risk agent(s)"
            )

        critical_incidents = incidents_by_severity.get("critical", 0)
        if critical_incidents > 0:
            recommendations.append(
                f"Escalate {critical_incidents} critical incident(s) to compliance officer"
            )

        if not recommendations:
            recommendations.append("No immediate compliance actions required")

        return recommendations
