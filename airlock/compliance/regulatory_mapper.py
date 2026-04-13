from __future__ import annotations

"""Maps Airlock Protocol features to regulatory compliance framework principles."""

import logging
from typing import Any

from airlock.compliance.incident import IncidentStore
from airlock.compliance.inventory import AgentInventory

logger = logging.getLogger(__name__)

# Compliance framework: 7 core principles
PRINCIPLES: dict[str, str] = {
    "principle_1": "Governance & Oversight",
    "principle_2": "Risk Management",
    "principle_3": "Data Governance",
    "principle_4": "Model Development & Validation",
    "principle_5": "Fairness & Bias",
    "principle_6": "Transparency & Explainability",
    "principle_7": "Accountability & Audit",
}

# Regulatory recommendations mapped to Airlock features
RECOMMENDATION_MAP: dict[str, dict[str, str]] = {
    "rec_01": {
        "title": "AI Model Inventory",
        "airlock_feature": "agent_inventory",
        "principle": "principle_1",
    },
    "rec_02": {
        "title": "Risk Classification",
        "airlock_feature": "risk_classifier",
        "principle": "principle_2",
    },
    "rec_03": {
        "title": "Incident Reporting",
        "airlock_feature": "incident_store",
        "principle": "principle_2",
    },
    "rec_04": {
        "title": "Audit Trail",
        "airlock_feature": "audit_trail",
        "principle": "principle_7",
    },
    "rec_05": {
        "title": "Bias Detection",
        "airlock_feature": "bias_detector",
        "principle": "principle_5",
    },
    "rec_06": {
        "title": "Trust Scoring Transparency",
        "airlock_feature": "trust_scoring",
        "principle": "principle_6",
    },
    "rec_07": {
        "title": "Identity Verification",
        "airlock_feature": "did_verification",
        "principle": "principle_1",
    },
    "rec_08": {
        "title": "Capability Assessment",
        "airlock_feature": "vc_capability",
        "principle": "principle_4",
    },
    "rec_09": {
        "title": "Data Privacy Controls",
        "airlock_feature": "privacy_mode",
        "principle": "principle_3",
    },
    "rec_10": {
        "title": "Compliance Reporting",
        "airlock_feature": "compliance_reports",
        "principle": "principle_7",
    },
}


class RegulatoryMapper:
    """Maps Airlock compliance status to regulatory framework principles."""

    def map_compliance_status(
        self,
        inventory: AgentInventory,
        incident_store: IncidentStore,
    ) -> dict[str, Any]:
        """Map current compliance state to framework principles and recommendations."""
        agents = inventory.list_all()
        incidents = incident_store.list_all()

        principle_status: dict[str, dict[str, Any]] = {}
        for principle_id, principle_name in PRINCIPLES.items():
            mapped_recs = [
                rec_id
                for rec_id, rec_data in RECOMMENDATION_MAP.items()
                if rec_data["principle"] == principle_id
            ]
            principle_status[principle_id] = {
                "name": principle_name,
                "recommendation_count": len(mapped_recs),
                "recommendations": mapped_recs,
                "status": "active" if agents else "pending",
            }

        recommendation_status: dict[str, dict[str, Any]] = {}
        for rec_id, rec_data in RECOMMENDATION_MAP.items():
            recommendation_status[rec_id] = self.get_recommendation_status(
                rec_id,
                inventory=inventory,
                incident_store=incident_store,
            )

        return {
            "framework": "airlock-compliance",
            "principles": principle_status,
            "recommendations": recommendation_status,
            "total_agents_tracked": len(agents),
            "total_incidents": len(incidents),
        }

    def get_recommendation_status(
        self,
        rec_id: str,
        inventory: AgentInventory | None = None,
        incident_store: IncidentStore | None = None,
    ) -> dict[str, Any]:
        """Get the implementation status of a specific recommendation."""
        rec_data = RECOMMENDATION_MAP.get(rec_id)
        if rec_data is None:
            return {"error": f"Unknown recommendation: {rec_id}"}

        feature = rec_data["airlock_feature"]
        implemented = True
        active = False

        if feature == "agent_inventory" and inventory is not None:
            active = len(inventory.list_all()) > 0
        elif feature == "incident_store" and incident_store is not None:
            active = len(incident_store.list_all()) > 0
        elif feature in (
            "risk_classifier",
            "bias_detector",
            "trust_scoring",
            "did_verification",
            "vc_capability",
            "privacy_mode",
            "audit_trail",
            "compliance_reports",
        ):
            active = True

        return {
            "rec_id": rec_id,
            "title": rec_data["title"],
            "principle": rec_data["principle"],
            "airlock_feature": feature,
            "implemented": implemented,
            "active": active,
        }
