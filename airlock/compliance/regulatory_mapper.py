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


# ---------------------------------------------------------------------------
# Framework control profiles (evidence-pack mapping)
# ---------------------------------------------------------------------------
#
# Each profile lists published control references from the named framework and
# the evidence categories the Airlock platform can collect for them.  These are
# factual citations of publicly documented control identifiers only: mapping
# evidence to a control reference does NOT assert that the control is satisfied
# and is not a legal-compliance claim (see the evidence-pack disclaimer).

EVIDENCE_AGENT_INVENTORY = "agent_inventory"
EVIDENCE_RISK_CLASSIFICATIONS = "risk_classifications"
EVIDENCE_INCIDENT_LOG = "incident_log"
EVIDENCE_AUDIT_TRAIL = "audit_trail"
EVIDENCE_SIGNED_MANIFEST = "signed_manifest"

FRAMEWORK_PROFILES: dict[str, dict[str, Any]] = {
    "RBI-FREE-AI": {
        "name": "RBI FREE-AI",
        "issuer": (
            "Reserve Bank of India — Framework for Responsible and Ethical Enablement "
            "of Artificial Intelligence (FREE-AI Committee report, August 2025)"
        ),
        "reference_note": (
            "Committee framework of 7 sutras, 6 pillars and 26 recommendations for AI "
            "in the financial sector. Control identifiers cite the report's numbered "
            "recommendations."
        ),
        "controls": [
            {
                "control_id": "Recommendation 16",
                "title": "AI System Governance Framework",
                "section": "Governance",
                "evidence": [EVIDENCE_RISK_CLASSIFICATIONS, EVIDENCE_AGENT_INVENTORY],
            },
            {
                "control_id": "Recommendation 19",
                "title": "Cybersecurity Measures",
                "section": "Protection",
                "evidence": [EVIDENCE_AUDIT_TRAIL, EVIDENCE_SIGNED_MANIFEST],
            },
            {
                "control_id": "Recommendation 22",
                "title": "AI Incident Reporting and Sectoral Risk Intelligence Framework",
                "section": "Protection",
                "evidence": [EVIDENCE_INCIDENT_LOG],
            },
            {
                "control_id": "Recommendation 23",
                "title": "AI Inventory within REs and Sector-Wide Repository",
                "section": "Assurance",
                "evidence": [EVIDENCE_AGENT_INVENTORY],
            },
            {
                "control_id": "Recommendation 24",
                "title": "AI Audit Framework",
                "section": "Assurance",
                "evidence": [EVIDENCE_AUDIT_TRAIL, EVIDENCE_INCIDENT_LOG],
            },
        ],
    },
    "EU-AI-Act": {
        "name": "EU AI Act",
        "issuer": "European Union — Regulation (EU) 2024/1689 (Artificial Intelligence Act)",
        "reference_note": (
            "Control identifiers cite articles of Regulation (EU) 2024/1689. Article "
            "obligations apply per the regulation's own scoping (e.g. high-risk AI "
            "systems); citation here is informational."
        ),
        "controls": [
            {
                "control_id": "Article 9",
                "title": "Risk management system",
                "section": "Chapter III, Section 2",
                "evidence": [EVIDENCE_RISK_CLASSIFICATIONS],
            },
            {
                "control_id": "Article 11",
                "title": "Technical documentation",
                "section": "Chapter III, Section 2",
                "evidence": [EVIDENCE_AGENT_INVENTORY],
            },
            {
                "control_id": "Article 12",
                "title": "Record-keeping",
                "section": "Chapter III, Section 2",
                "evidence": [EVIDENCE_AUDIT_TRAIL],
            },
            {
                "control_id": "Article 14",
                "title": "Human oversight",
                "section": "Chapter III, Section 2",
                "evidence": [EVIDENCE_RISK_CLASSIFICATIONS],
            },
            {
                "control_id": "Article 19",
                "title": "Automatically generated logs",
                "section": "Chapter III, Section 3",
                "evidence": [EVIDENCE_AUDIT_TRAIL],
            },
            {
                "control_id": "Article 72",
                "title": "Post-market monitoring by providers",
                "section": "Chapter IX, Section 1",
                "evidence": [EVIDENCE_AGENT_INVENTORY, EVIDENCE_INCIDENT_LOG],
            },
            {
                "control_id": "Article 73",
                "title": "Reporting of serious incidents",
                "section": "Chapter IX, Section 2",
                "evidence": [EVIDENCE_INCIDENT_LOG],
            },
        ],
    },
    "ISO-42001": {
        "name": "ISO/IEC 42001",
        "issuer": (
            "ISO/IEC 42001:2023 — Information technology — Artificial intelligence — "
            "Management system"
        ),
        "reference_note": (
            "Control identifiers cite ISO/IEC 42001:2023 clauses and Annex A controls. "
            "Citation here is informational and is not an ISO certification claim."
        ),
        "controls": [
            {
                "control_id": "Clause 6.1.2",
                "title": "AI risk assessment",
                "section": "Planning",
                "evidence": [EVIDENCE_RISK_CLASSIFICATIONS],
            },
            {
                "control_id": "Clause 7.5",
                "title": "Documented information",
                "section": "Support",
                "evidence": [EVIDENCE_AGENT_INVENTORY, EVIDENCE_AUDIT_TRAIL],
            },
            {
                "control_id": "Clause 9.1",
                "title": "Monitoring, measurement, analysis and evaluation",
                "section": "Performance evaluation",
                "evidence": [EVIDENCE_AUDIT_TRAIL, EVIDENCE_INCIDENT_LOG],
            },
            {
                "control_id": "Clause 10.2",
                "title": "Nonconformity and corrective action",
                "section": "Improvement",
                "evidence": [EVIDENCE_INCIDENT_LOG],
            },
            {
                "control_id": "A.4.2",
                "title": "Resource documentation",
                "section": "Annex A — Resources for AI systems",
                "evidence": [EVIDENCE_AGENT_INVENTORY],
            },
            {
                "control_id": "A.6.2.6",
                "title": "AI system operation and monitoring",
                "section": "Annex A — AI system life cycle",
                "evidence": [EVIDENCE_AGENT_INVENTORY, EVIDENCE_AUDIT_TRAIL],
            },
            {
                "control_id": "A.6.2.8",
                "title": "AI system recording of event logs",
                "section": "Annex A — AI system life cycle",
                "evidence": [EVIDENCE_AUDIT_TRAIL],
            },
            {
                "control_id": "A.8.4",
                "title": "Communication of incidents",
                "section": "Annex A — Information for interested parties",
                "evidence": [EVIDENCE_INCIDENT_LOG],
            },
        ],
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

    def list_framework_profiles(self) -> list[str]:
        """Return the identifiers of the available framework control profiles."""
        return list(FRAMEWORK_PROFILES.keys())

    def map_evidence_to_framework(
        self,
        profile_id: str,
        evidence_counts: dict[str, int],
    ) -> dict[str, Any]:
        """Map collected evidence categories to one framework profile's control references.

        ``evidence_counts`` maps evidence category keys (see ``EVIDENCE_*``
        constants) to the number of collected items in that category.  The
        result records, per control reference, which evidence categories apply
        and how many items were collected — it does not assert that any control
        is satisfied.

        Raises ``KeyError`` for an unknown ``profile_id``.
        """
        profile = FRAMEWORK_PROFILES.get(profile_id)
        if profile is None:
            raise KeyError(
                f"Unknown framework profile: {profile_id!r} "
                f"(available: {', '.join(FRAMEWORK_PROFILES)})"
            )

        controls: list[dict[str, Any]] = []
        for control in profile["controls"]:
            categories: list[str] = list(control["evidence"])
            counts = {category: evidence_counts.get(category, 0) for category in categories}
            controls.append(
                {
                    "control_id": control["control_id"],
                    "title": control["title"],
                    "section": control["section"],
                    "evidence_categories": categories,
                    "evidence_item_counts": counts,
                    "evidence_present": any(count > 0 for count in counts.values()),
                }
            )

        return {
            "profile_id": profile_id,
            "name": profile["name"],
            "issuer": profile["issuer"],
            "reference_note": profile["reference_note"],
            "controls": controls,
        }
