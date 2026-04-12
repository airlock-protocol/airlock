"""Tests for risk classification engine."""

from __future__ import annotations

from datetime import UTC, datetime

from fastapi.testclient import TestClient

from airlock.compliance.risk_classifier import (
    RiskClassifier,
)
from airlock.compliance.schemas import AgentInventoryEntry, RiskLevel
from airlock.config import AirlockConfig
from airlock.gateway.app import create_app


def _make_entry(
    did: str = "did:key:z6MkRisk1",
    agent_type: str = "autonomous",
    capabilities: list[str] | None = None,
    trust_score: float | None = None,
) -> AgentInventoryEntry:
    return AgentInventoryEntry(
        did=did,
        display_name="Risk Agent",
        agent_type=agent_type,
        capabilities=capabilities or [],
        registered_at=datetime.now(UTC),
        trust_score=trust_score,
    )


# ---------------------------------------------------------------------------
# Unit tests: RiskClassifier
# ---------------------------------------------------------------------------


def test_low_risk_tool_agent():
    """Tool agent with few capabilities should be low risk."""
    classifier = RiskClassifier()
    entry = _make_entry(agent_type="tool", capabilities=["logging"], trust_score=0.8)
    result = classifier.classify(entry)
    assert result.risk_level == RiskLevel.LOW


def test_medium_risk_semi_autonomous():
    """Semi-autonomous agent with moderate capabilities should be medium risk."""
    classifier = RiskClassifier()
    entry = _make_entry(
        agent_type="semi-autonomous",
        capabilities=["data_read", "api_call"],
        trust_score=0.6,
    )
    result = classifier.classify(entry)
    assert result.risk_level == RiskLevel.MEDIUM


def test_high_risk_autonomous_financial():
    """Autonomous agent with financial capability should be high risk."""
    classifier = RiskClassifier()
    entry = _make_entry(
        agent_type="autonomous",
        capabilities=["financial_transaction"],
        trust_score=0.5,
    )
    result = classifier.classify(entry)
    assert result.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL)


def test_critical_risk_multiple_high_caps():
    """Agent with multiple high-risk capabilities should be critical."""
    classifier = RiskClassifier()
    entry = _make_entry(
        agent_type="autonomous",
        capabilities=["financial_transaction", "data_access", "user_impersonation"],
        trust_score=0.1,
    )
    result = classifier.classify(entry)
    assert result.risk_level == RiskLevel.CRITICAL


def test_trust_score_impact_on_risk():
    """Low trust score should increase risk level."""
    classifier = RiskClassifier()

    high_trust = _make_entry(agent_type="tool", capabilities=["logging"], trust_score=0.9)
    low_trust = _make_entry(agent_type="tool", capabilities=["logging"], trust_score=0.1)

    high_result = classifier.classify(high_trust)
    low_result = classifier.classify(low_trust)

    risk_order = [RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL]
    assert risk_order.index(low_result.risk_level) >= risk_order.index(high_result.risk_level)


def test_capability_risk_assessment():
    """Verify capability risk assessment logic directly."""
    classifier = RiskClassifier()

    assert classifier._assess_capability_risk([]) == RiskLevel.LOW
    assert classifier._assess_capability_risk(["logging"]) == RiskLevel.LOW
    assert classifier._assess_capability_risk(["data_read"]) == RiskLevel.MEDIUM
    assert classifier._assess_capability_risk(["financial_transaction"]) == RiskLevel.HIGH
    assert (
        classifier._assess_capability_risk(["financial_transaction", "data_access"])
        == RiskLevel.CRITICAL
    )


def test_trust_risk_assessment():
    """Verify trust risk assessment logic directly."""
    classifier = RiskClassifier()

    assert classifier._assess_trust_risk(None) == RiskLevel.MEDIUM
    assert classifier._assess_trust_risk(0.1) == RiskLevel.CRITICAL
    assert classifier._assess_trust_risk(0.3) == RiskLevel.HIGH
    assert classifier._assess_trust_risk(0.5) == RiskLevel.MEDIUM
    assert classifier._assess_trust_risk(0.8) == RiskLevel.LOW


def test_risk_classification_includes_factors():
    """Risk classification should include risk factors for high/critical."""
    classifier = RiskClassifier()
    entry = _make_entry(
        agent_type="autonomous",
        capabilities=["financial_transaction", "system_admin"],
        trust_score=0.15,
    )
    result = classifier.classify(entry)
    assert len(result.risk_factors) > 0


def test_risk_classification_includes_mitigations():
    """High/critical risk should have mitigation suggestions."""
    classifier = RiskClassifier()
    entry = _make_entry(
        agent_type="autonomous",
        capabilities=["financial_transaction", "data_access"],
        trust_score=0.1,
    )
    result = classifier.classify(entry)
    assert len(result.mitigation_measures) > 0


def test_combine_risk_factors():
    """Highest risk factor should win in combination."""
    classifier = RiskClassifier()
    factors = [RiskLevel.LOW, RiskLevel.HIGH, RiskLevel.MEDIUM]
    assert classifier._combine_risk_factors(factors) == RiskLevel.HIGH


def test_confidence_with_trust_score():
    """Confidence should be higher when trust score is available."""
    classifier = RiskClassifier()
    entry_with = _make_entry(trust_score=0.5)
    entry_without = _make_entry(trust_score=None)
    result_with = classifier.classify(entry_with)
    result_without = classifier.classify(entry_without)
    assert result_with.confidence > result_without.confidence


# ---------------------------------------------------------------------------
# Route tests: risk endpoint
# ---------------------------------------------------------------------------


def test_risk_endpoint(tmp_path):
    cfg = AirlockConfig(
        lancedb_path=str(tmp_path / "risk.lance"),
        compliance_enabled=True,
    )
    app = create_app(cfg)
    with TestClient(app) as c:
        # Register agent first
        c.post(
            "/compliance/inventory",
            json={
                "did": "did:key:z6MkRiskRoute",
                "display_name": "Risk Route Agent",
                "agent_type": "autonomous",
                "capabilities": ["financial_transaction"],
                "registered_at": datetime.now(UTC).isoformat(),
            },
        )
        r = c.get("/compliance/risk/did:key:z6MkRiskRoute")
        assert r.status_code == 200
        data = r.json()
        assert "risk_level" in data
        assert "risk_factors" in data
        assert "mitigation_measures" in data


def test_risk_endpoint_nonexistent_agent(tmp_path):
    cfg = AirlockConfig(
        lancedb_path=str(tmp_path / "risk2.lance"),
        compliance_enabled=True,
    )
    app = create_app(cfg)
    with TestClient(app) as c:
        r = c.get("/compliance/risk/did:key:z6MkNope")
        assert r.status_code == 404
