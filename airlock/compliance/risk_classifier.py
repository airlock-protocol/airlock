"""Risk classification engine -- FREE-AI Rec #15."""

from __future__ import annotations

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

MEDIUM_RISK_CAPABILITIES: list[str] = [
    "data_read",
    "api_call",
    "message_send",
]

# Agent type risk ordering (higher index = higher base risk).
_AGENT_TYPE_RISK: dict[str, RiskLevel] = {
    "tool": RiskLevel.LOW,
    "semi-autonomous": RiskLevel.MEDIUM,
    "autonomous": RiskLevel.HIGH,
}


class RiskClassifier:
    """Classify agents by risk level based on capabilities, trust, and behavior."""

    def classify(
        self,
        entry: AgentInventoryEntry,
        trust_score: float | None = None,
    ) -> RiskClassification:
        """Classify agent risk based on capabilities, trust score, and agent type."""
        factors: list[str] = []
        risk_levels: list[RiskLevel] = []

        # Capability risk
        cap_risk = self._assess_capability_risk(entry.capabilities)
        risk_levels.append(cap_risk)
        if cap_risk in (RiskLevel.HIGH, RiskLevel.CRITICAL):
            factors.append(f"high_risk_capabilities:{cap_risk.value}")

        # Trust score risk
        score = trust_score if trust_score is not None else entry.trust_score
        trust_risk = self._assess_trust_risk(score)
        risk_levels.append(trust_risk)
        if trust_risk in (RiskLevel.HIGH, RiskLevel.CRITICAL):
            factors.append(f"low_trust_score:{score}")

        # Agent type risk
        type_risk = _AGENT_TYPE_RISK.get(entry.agent_type, RiskLevel.MEDIUM)
        risk_levels.append(type_risk)
        if type_risk in (RiskLevel.HIGH, RiskLevel.CRITICAL):
            factors.append(f"agent_type:{entry.agent_type}")

        combined = self._combine_risk_factors(risk_levels)

        mitigations = self._suggest_mitigations(combined, factors)

        confidence = 0.9 if score is not None else 0.7

        return RiskClassification(
            did=entry.did,
            risk_level=combined,
            risk_factors=factors,
            mitigation_measures=mitigations,
            assessed_at=datetime.now(UTC),
            assessed_by="automated",
            confidence=confidence,
        )

    def _assess_capability_risk(self, capabilities: list[str]) -> RiskLevel:
        """Assess risk based on agent capabilities."""
        if not capabilities:
            return RiskLevel.LOW

        has_high = any(cap in HIGH_RISK_CAPABILITIES for cap in capabilities)
        has_medium = any(cap in MEDIUM_RISK_CAPABILITIES for cap in capabilities)
        high_count = sum(1 for cap in capabilities if cap in HIGH_RISK_CAPABILITIES)

        if high_count >= 2:
            return RiskLevel.CRITICAL
        if has_high:
            return RiskLevel.HIGH
        if has_medium or len(capabilities) > 3:
            return RiskLevel.MEDIUM
        return RiskLevel.LOW

    def _assess_trust_risk(self, trust_score: float | None) -> RiskLevel:
        """Assess risk based on trust score (lower score = higher risk)."""
        if trust_score is None:
            return RiskLevel.MEDIUM
        if trust_score < 0.2:
            return RiskLevel.CRITICAL
        if trust_score < 0.4:
            return RiskLevel.HIGH
        if trust_score < 0.6:
            return RiskLevel.MEDIUM
        return RiskLevel.LOW

    def _combine_risk_factors(self, factors: list[RiskLevel]) -> RiskLevel:
        """Combine multiple risk assessments into a single level (highest wins)."""
        order = [RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL]
        max_idx = 0
        for factor in factors:
            idx = order.index(factor)
            if idx > max_idx:
                max_idx = idx
        return order[max_idx]

    def _suggest_mitigations(
        self, risk_level: RiskLevel, factors: list[str]
    ) -> list[str]:
        """Suggest mitigation measures based on risk level and factors."""
        mitigations: list[str] = []
        if risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL):
            mitigations.append("Implement enhanced monitoring and logging")
            mitigations.append("Require human-in-the-loop for critical operations")
        if risk_level == RiskLevel.CRITICAL:
            mitigations.append("Consider restricting deployment environment")
            mitigations.append("Schedule immediate security review")
        if any("low_trust_score" in f for f in factors):
            mitigations.append("Increase verification frequency")
        if any("high_risk_capabilities" in f for f in factors):
            mitigations.append("Apply principle of least privilege to capabilities")
        return mitigations
