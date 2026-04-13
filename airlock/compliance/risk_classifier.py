from __future__ import annotations

"""Risk classification engine for agent compliance assessment."""

import logging
from datetime import UTC, datetime

from airlock.compliance.schemas import AgentInventoryEntry, RiskClassification, RiskLevel

logger = logging.getLogger(__name__)

HIGH_RISK_CAPABILITIES: list[str] = [
    "financial_transaction",
    "data_access",
    "user_impersonation",
    "system_admin",
]


class RiskClassifier:
    """Classifies agents into risk tiers based on capabilities and trust."""

    def classify(
        self,
        entry: AgentInventoryEntry,
        trust_score: float | None = None,
    ) -> RiskClassification:
        """Classify an agent's risk level based on its profile and trust score."""
        score = trust_score if trust_score is not None else entry.trust_score
        risk_factors: list[str] = []
        mitigation_measures: list[str] = []

        # Count high-risk capabilities
        high_risk_caps = [c for c in entry.capabilities if c in HIGH_RISK_CAPABILITIES]
        has_high_risk_caps = len(high_risk_caps) > 0
        many_capabilities = len(entry.capabilities) >= 5

        if has_high_risk_caps:
            risk_factors.append(f"high_risk_capabilities: {', '.join(high_risk_caps)}")
            mitigation_measures.append("enhanced_monitoring")

        if many_capabilities:
            risk_factors.append(f"broad_capability_surface: {len(entry.capabilities)} capabilities")
            mitigation_measures.append("periodic_capability_review")

        if score < 0.3:
            risk_factors.append(f"low_trust_score: {score:.2f}")
            mitigation_measures.append("trust_score_remediation")

        if entry.agent_type == "autonomous":
            risk_factors.append("autonomous_agent")
            mitigation_measures.append("human_oversight_required")

        # Determine risk level
        risk_level = self._compute_risk_level(
            high_risk_caps=len(high_risk_caps),
            total_capabilities=len(entry.capabilities),
            trust_score=score,
            agent_type=entry.agent_type,
        )

        return RiskClassification(
            did=entry.did,
            risk_level=risk_level,
            risk_factors=risk_factors,
            mitigation_measures=mitigation_measures,
            assessed_at=datetime.now(UTC),
            assessed_by="automated",
            confidence=self._compute_confidence(score, entry),
        )

    def _compute_risk_level(
        self,
        high_risk_caps: int,
        total_capabilities: int,
        trust_score: float,
        agent_type: str,
    ) -> RiskLevel:
        """Determine risk level based on weighted factors."""
        # Critical: multiple high-risk capabilities with low trust
        if high_risk_caps >= 2 and trust_score < 0.4:
            return RiskLevel.CRITICAL

        # High: any high-risk capability OR very low trust
        if high_risk_caps >= 1 and trust_score < 0.5:
            return RiskLevel.HIGH
        if trust_score < 0.2:
            return RiskLevel.HIGH

        # Medium: autonomous agent or moderate indicators
        if agent_type == "autonomous" and trust_score < 0.7:
            return RiskLevel.MEDIUM
        if high_risk_caps >= 1:
            return RiskLevel.MEDIUM
        if total_capabilities >= 5:
            return RiskLevel.MEDIUM

        # Low: trusted agent with limited capabilities
        return RiskLevel.LOW

    def _compute_confidence(
        self,
        trust_score: float,
        entry: AgentInventoryEntry,
    ) -> float:
        """Compute confidence in the risk classification (0.0-1.0)."""
        confidence = 0.6  # base confidence

        # More data points increase confidence
        if len(entry.capabilities) > 0:
            confidence += 0.1
        if trust_score > 0.0:
            confidence += 0.1
        if entry.agent_type != "":
            confidence += 0.1

        return min(confidence, 1.0)
