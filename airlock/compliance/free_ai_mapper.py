from __future__ import annotations

"""Maps Airlock Protocol features to RBI FREE-AI Framework sutras and recommendations."""

import logging
from typing import Any

from airlock.compliance.incident import IncidentStore
from airlock.compliance.inventory import AgentInventory

logger = logging.getLogger(__name__)

# RBI FREE-AI Framework: 7 Sutras
SUTRAS: dict[str, str] = {
    "sutra_1": "Governance & Oversight",
    "sutra_2": "Risk Management",
    "sutra_3": "Data Governance",
    "sutra_4": "Model Development & Validation",
    "sutra_5": "Fairness & Bias",
    "sutra_6": "Transparency & Explainability",
    "sutra_7": "Accountability & Audit",
}

# Selected RBI FREE-AI recommendations mapped to Airlock features
RECOMMENDATION_MAP: dict[str, dict[str, str]] = {
    "rec_14": {
        "title": "AI Model Inventory",
        "airlock_feature": "agent_inventory",
        "sutra": "sutra_1",
    },
    "rec_15": {
        "title": "Risk Classification",
        "airlock_feature": "risk_classifier",
        "sutra": "sutra_2",
    },
    "rec_16": {
        "title": "Incident Reporting",
        "airlock_feature": "incident_store",
        "sutra": "sutra_2",
    },
    "rec_17": {
        "title": "Audit Trail",
        "airlock_feature": "audit_trail",
        "sutra": "sutra_7",
    },
    "rec_18": {
        "title": "Bias Detection",
        "airlock_feature": "bias_detector",
        "sutra": "sutra_5",
    },
    "rec_19": {
        "title": "Trust Scoring Transparency",
        "airlock_feature": "trust_scoring",
        "sutra": "sutra_6",
    },
    "rec_20": {
        "title": "Identity Verification",
        "airlock_feature": "did_verification",
        "sutra": "sutra_1",
    },
    "rec_21": {
        "title": "Capability Assessment",
        "airlock_feature": "vc_capability",
        "sutra": "sutra_4",
    },
    "rec_22": {
        "title": "Data Privacy Controls",
        "airlock_feature": "privacy_mode",
        "sutra": "sutra_3",
    },
    "rec_23": {
        "title": "Compliance Reporting",
        "airlock_feature": "compliance_reports",
        "sutra": "sutra_7",
    },
}


class FreeAIMapper:
    """Maps Airlock compliance status to RBI FREE-AI framework."""

    def map_compliance_status(
        self,
        inventory: AgentInventory,
        incident_store: IncidentStore,
    ) -> dict[str, Any]:
        """Map current compliance state to FREE-AI sutras and recommendations."""
        agents = inventory.list_all()
        incidents = incident_store.list_all()

        sutra_status: dict[str, dict[str, Any]] = {}
        for sutra_id, sutra_name in SUTRAS.items():
            mapped_recs = [
                rec_id
                for rec_id, rec_data in RECOMMENDATION_MAP.items()
                if rec_data["sutra"] == sutra_id
            ]
            sutra_status[sutra_id] = {
                "name": sutra_name,
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
            "framework": "RBI FREE-AI",
            "sutras": sutra_status,
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
        implemented = True  # All mapped features exist in the codebase
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
            active = True  # Core features are always active

        return {
            "rec_id": rec_id,
            "title": rec_data["title"],
            "sutra": rec_data["sutra"],
            "airlock_feature": feature,
            "implemented": implemented,
            "active": active,
        }
