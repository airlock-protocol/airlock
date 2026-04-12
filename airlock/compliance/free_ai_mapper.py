"""Maps Airlock data to RBI FREE-AI 7 Sutras and 26 recommendations."""

from __future__ import annotations

import logging
from typing import Any

from airlock.compliance.incident import IncidentStore
from airlock.compliance.inventory import AgentInventory

logger = logging.getLogger(__name__)

# FREE-AI Sutras
SUTRAS: dict[str, str] = {
    "sutra_1": "Governance & Oversight",
    "sutra_2": "Risk Management",
    "sutra_3": "Data Privacy & Security",
    "sutra_4": "Transparency & Explainability",
    "sutra_5": "Fairness & Non-discrimination",
    "sutra_6": "Accountability & Audit",
    "sutra_7": "Consumer Protection",
}

# Recommendation -> Airlock feature mapping
RECOMMENDATION_MAP: dict[str, dict[str, str]] = {
    "rec_13": {
        "title": "Incident Reporting",
        "airlock_feature": "incident_tracking",
        "sutra": "sutra_2",
    },
    "rec_14": {
        "title": "AI Model Inventory",
        "airlock_feature": "agent_inventory",
        "sutra": "sutra_1",
    },
    "rec_15": {
        "title": "Auditor Assessment by Risk Profile",
        "airlock_feature": "risk_classification",
        "sutra": "sutra_2",
    },
    "rec_16": {
        "title": "AI Disclosures in Annual Reports",
        "airlock_feature": "compliance_reports",
        "sutra": "sutra_4",
    },
    "rec_19": {
        "title": "Internal Audit Proportional to Risk",
        "airlock_feature": "audit_trail",
        "sutra": "sutra_6",
    },
    "rec_20": {
        "title": "Red Teaming",
        "airlock_feature": "adversarial_testing",
        "sutra": "sutra_2",
    },
}


class FreeAIMapper:
    """Map Airlock compliance state to FREE-AI recommendations."""

    def map_compliance_status(
        self,
        inventory: AgentInventory,
        incident_store: IncidentStore,
    ) -> dict[str, dict[str, Any]]:
        """Map current Airlock state to FREE-AI recommendation compliance status.

        Returns a dict keyed by recommendation ID with compliance details.
        """
        result: dict[str, dict[str, Any]] = {}
        for rec_id, rec_info in RECOMMENDATION_MAP.items():
            result[rec_id] = self.get_recommendation_status(
                rec_id, inventory, incident_store
            )
        return result

    def get_recommendation_status(
        self,
        rec_id: str,
        inventory: AgentInventory,
        incident_store: IncidentStore,
    ) -> dict[str, Any]:
        """Get compliance status for a specific recommendation."""
        rec_info = RECOMMENDATION_MAP.get(rec_id)
        if rec_info is None:
            return {
                "status": "unknown",
                "title": "Unknown Recommendation",
                "details": f"Recommendation {rec_id} not mapped",
            }

        feature = rec_info["airlock_feature"]
        sutra = rec_info["sutra"]
        title = rec_info["title"]

        status = self._assess_feature_status(feature, inventory, incident_store)

        return {
            "rec_id": rec_id,
            "title": title,
            "sutra": sutra,
            "sutra_name": SUTRAS.get(sutra, "Unknown"),
            "airlock_feature": feature,
            "status": status,
        }

    def get_sutra_summary(
        self,
        inventory: AgentInventory,
        incident_store: IncidentStore,
    ) -> dict[str, dict[str, Any]]:
        """Get compliance summary grouped by Sutra."""
        full_mapping = self.map_compliance_status(inventory, incident_store)

        sutra_summary: dict[str, dict[str, Any]] = {}
        for sutra_id, sutra_name in SUTRAS.items():
            recs = [
                v
                for v in full_mapping.values()
                if v.get("sutra") == sutra_id
            ]
            compliant = sum(1 for r in recs if r.get("status") == "compliant")
            total = len(recs)
            sutra_summary[sutra_id] = {
                "name": sutra_name,
                "recommendations": total,
                "compliant": compliant,
                "status": "compliant" if compliant == total and total > 0 else "partial",
            }
        return sutra_summary

    def _assess_feature_status(
        self,
        feature: str,
        inventory: AgentInventory,
        incident_store: IncidentStore,
    ) -> str:
        """Assess whether a specific Airlock feature meets compliance."""
        if feature == "agent_inventory":
            # Compliant if at least one agent is registered
            return "compliant" if len(inventory) > 0 else "not_implemented"

        if feature == "risk_classification":
            # Compliant if agents have been assessed
            entries = inventory.list_all()
            if not entries:
                return "not_implemented"
            assessed = sum(1 for e in entries if e.last_assessed_at is not None)
            return "compliant" if assessed > 0 else "partial"

        if feature == "incident_tracking":
            # Feature is available (store exists), compliant
            return "compliant"

        if feature == "compliance_reports":
            # Feature is available (generator exists), compliant
            return "compliant"

        if feature == "audit_trail":
            # Audit trail is always available in Airlock
            return "compliant"

        if feature == "adversarial_testing":
            # Red teaming is a process, not a feature -- mark as partial
            return "partial"

        return "unknown"
