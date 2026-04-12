"""Compliance report generation mapped to FREE-AI recommendations -- Rec #16."""

from __future__ import annotations

import logging
import uuid
from datetime import UTC, datetime
from typing import Any

from airlock.compliance.free_ai_mapper import FreeAIMapper
from airlock.compliance.incident import IncidentStore
from airlock.compliance.inventory import AgentInventory
from airlock.compliance.schemas import ComplianceReport

logger = logging.getLogger(__name__)


class ComplianceReportGenerator:
    """Generate compliance reports mapped to FREE-AI recommendations."""

    def __init__(
        self,
        inventory: AgentInventory,
        incident_store: IncidentStore,
        free_ai_mapper: FreeAIMapper,
    ) -> None:
        self._inventory = inventory
        self._incident_store = incident_store
        self._mapper = free_ai_mapper

    def generate(
        self,
        period_start: datetime,
        period_end: datetime,
    ) -> ComplianceReport:
        """Generate a full compliance report for the given period."""
        agents = self._inventory.list_all()
        agents_by_risk = self._inventory.count_by_risk()

        # Filter incidents to reporting period
        all_incidents = self._incident_store.list_all(limit=10000)
        period_incidents = [
            i
            for i in all_incidents
            if period_start <= i.detected_at <= period_end
        ]
        incidents_by_severity = self._incident_store.count_by_severity()

        # FREE-AI mapping
        free_ai_mapping = self._mapper.map_compliance_status(
            self._inventory, self._incident_store
        )

        # Calculate compliance score
        compliance_score = self._calculate_compliance_score(free_ai_mapping)

        # Generate recommendations
        recommendations = self._generate_recommendations(
            free_ai_mapping, agents_by_risk, incidents_by_severity
        )

        audit_summary = self.generate_audit_summary()

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
            free_ai_mapping=free_ai_mapping,
            recommendations=recommendations,
            audit_summary=audit_summary,
        )

    def generate_for_agent(
        self,
        did: str,
        period_start: datetime,
        period_end: datetime,
    ) -> ComplianceReport:
        """Generate a compliance report for a specific agent."""
        entry = self._inventory.get(did)

        agent_incidents = self._incident_store.list_by_agent(did)
        period_incidents = [
            i
            for i in agent_incidents
            if period_start <= i.detected_at <= period_end
        ]
        incidents_by_severity: dict[str, int] = {}
        for incident in period_incidents:
            key = incident.severity.value
            incidents_by_severity[key] = incidents_by_severity.get(key, 0) + 1

        agents_by_risk: dict[str, int] = {}
        if entry is not None:
            agents_by_risk[entry.risk_level.value] = 1

        free_ai_mapping = self._mapper.map_compliance_status(
            self._inventory, self._incident_store
        )
        compliance_score = self._calculate_compliance_score(free_ai_mapping)

        recommendations: list[str] = []
        if entry is not None and entry.compliance_status != "compliant":
            recommendations.append(
                f"Agent {did} compliance status is '{entry.compliance_status}'"
            )
        if period_incidents:
            recommendations.append(
                f"Agent has {len(period_incidents)} incident(s) in reporting period"
            )

        return ComplianceReport(
            report_id=str(uuid.uuid4()),
            generated_at=datetime.now(UTC),
            reporting_period_start=period_start,
            reporting_period_end=period_end,
            total_agents=1 if entry is not None else 0,
            agents_by_risk=agents_by_risk,
            total_incidents=len(period_incidents),
            incidents_by_severity=incidents_by_severity,
            compliance_score=compliance_score,
            free_ai_mapping=free_ai_mapping,
            recommendations=recommendations,
            audit_summary={},
        )

    def generate_audit_summary(self) -> dict[str, Any]:
        """Generate a summary of the current compliance state."""
        agents = self._inventory.list_all()
        compliant_count = sum(
            1 for a in agents if a.compliance_status == "compliant"
        )
        total = len(agents)

        chain_valid, chain_msg = self._incident_store.verify_chain()

        return {
            "total_agents": total,
            "compliant_agents": compliant_count,
            "compliance_rate": (
                round(compliant_count / total, 4) if total > 0 else 0.0
            ),
            "total_incidents": len(self._incident_store),
            "incident_chain_valid": chain_valid,
            "incident_chain_message": chain_msg,
            "sutra_summary": self._mapper.get_sutra_summary(
                self._inventory, self._incident_store
            ),
        }

    def _calculate_compliance_score(
        self, mapping: dict[str, dict[str, Any]]
    ) -> float:
        """Calculate overall compliance score (0-100) from FREE-AI mapping."""
        if not mapping:
            return 0.0

        status_scores = {
            "compliant": 100.0,
            "partial": 50.0,
            "not_implemented": 0.0,
            "unknown": 0.0,
        }

        total = 0.0
        count = 0
        for rec_data in mapping.values():
            status = rec_data.get("status", "unknown")
            total += status_scores.get(status, 0.0)
            count += 1

        return round(total / count, 2) if count > 0 else 0.0

    def _generate_recommendations(
        self,
        mapping: dict[str, dict[str, Any]],
        agents_by_risk: dict[str, int],
        incidents_by_severity: dict[str, int],
    ) -> list[str]:
        """Generate actionable recommendations based on current state."""
        recs: list[str] = []

        # Check for non-compliant FREE-AI recommendations
        for rec_id, rec_data in mapping.items():
            status = rec_data.get("status", "unknown")
            if status == "not_implemented":
                title = rec_data.get("title", rec_id)
                recs.append(f"Implement {title} ({rec_id})")
            elif status == "partial":
                title = rec_data.get("title", rec_id)
                recs.append(f"Complete implementation of {title} ({rec_id})")

        # Risk-based recommendations
        critical = agents_by_risk.get("critical", 0)
        high = agents_by_risk.get("high", 0)
        if critical > 0:
            recs.append(
                f"{critical} agent(s) classified as critical risk -- immediate review required"
            )
        if high > 0:
            recs.append(
                f"{high} agent(s) classified as high risk -- schedule assessment"
            )

        # Incident-based recommendations
        critical_incidents = incidents_by_severity.get("critical", 0)
        if critical_incidents > 0:
            recs.append(
                f"{critical_incidents} critical incident(s) recorded -- ensure root cause analysis"
            )

        return recs
