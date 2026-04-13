from __future__ import annotations

"""Tests for the compliance risk classifier."""

import pytest
from asgi_lifespan import LifespanManager
from httpx import ASGITransport, AsyncClient

from airlock.compliance.risk_classifier import HIGH_RISK_CAPABILITIES, RiskClassifier
from airlock.compliance.schemas import AgentInventoryEntry, RiskLevel
from airlock.config import AirlockConfig
from airlock.gateway.app import create_app

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_entry(
    did: str = "did:key:z6MkClassify",
    capabilities: list[str] | None = None,
    trust_score: float = 0.5,
    agent_type: str = "autonomous",
) -> AgentInventoryEntry:
    return AgentInventoryEntry(
        did=did,
        display_name="Test Agent",
        capabilities=capabilities or [],
        trust_score=trust_score,
        trust_tier=0,
        agent_type=agent_type,
    )


# ---------------------------------------------------------------------------
# Classification tests
# ---------------------------------------------------------------------------


class TestRiskClassifier:
    def test_low_risk_agent(self) -> None:
        classifier = RiskClassifier()
        entry = _make_entry(
            capabilities=["read_only"],
            trust_score=0.9,
            agent_type="supervised",
        )
        result = classifier.classify(entry)
        assert result.risk_level == RiskLevel.LOW
        assert result.did == entry.did

    def test_medium_risk_autonomous_agent(self) -> None:
        classifier = RiskClassifier()
        entry = _make_entry(
            capabilities=["read_write"],
            trust_score=0.5,
            agent_type="autonomous",
        )
        result = classifier.classify(entry)
        assert result.risk_level == RiskLevel.MEDIUM

    def test_high_risk_financial_capability(self) -> None:
        classifier = RiskClassifier()
        entry = _make_entry(
            capabilities=["financial_transaction"],
            trust_score=0.4,
        )
        result = classifier.classify(entry)
        assert result.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL)

    def test_critical_risk_multiple_high_caps_low_trust(self) -> None:
        classifier = RiskClassifier()
        entry = _make_entry(
            capabilities=["financial_transaction", "data_access", "user_impersonation"],
            trust_score=0.2,
        )
        result = classifier.classify(entry)
        assert result.risk_level == RiskLevel.CRITICAL

    def test_very_low_trust_is_high_risk(self) -> None:
        classifier = RiskClassifier()
        entry = _make_entry(trust_score=0.1, capabilities=[])
        result = classifier.classify(entry)
        assert result.risk_level == RiskLevel.HIGH

    def test_trust_score_override(self) -> None:
        classifier = RiskClassifier()
        entry = _make_entry(trust_score=0.9, capabilities=["financial_transaction"])
        # High trust + single high-risk cap => medium
        result = classifier.classify(entry, trust_score=0.9)
        assert result.risk_level == RiskLevel.MEDIUM

    def test_many_capabilities_is_medium(self) -> None:
        classifier = RiskClassifier()
        entry = _make_entry(
            capabilities=["a", "b", "c", "d", "e"],
            trust_score=0.8,
            agent_type="supervised",
        )
        result = classifier.classify(entry)
        assert result.risk_level == RiskLevel.MEDIUM

    def test_classification_has_risk_factors(self) -> None:
        classifier = RiskClassifier()
        entry = _make_entry(
            capabilities=["financial_transaction"],
            trust_score=0.3,
        )
        result = classifier.classify(entry)
        assert len(result.risk_factors) > 0
        assert any("financial_transaction" in f for f in result.risk_factors)

    def test_classification_has_mitigation_measures(self) -> None:
        classifier = RiskClassifier()
        entry = _make_entry(
            capabilities=["system_admin"],
            trust_score=0.4,
        )
        result = classifier.classify(entry)
        assert len(result.mitigation_measures) > 0

    def test_confidence_increases_with_data(self) -> None:
        classifier = RiskClassifier()
        sparse = _make_entry(capabilities=[], trust_score=0.0, agent_type="")
        rich = _make_entry(
            capabilities=["data_access"],
            trust_score=0.7,
            agent_type="autonomous",
        )
        c_sparse = classifier.classify(sparse)
        c_rich = classifier.classify(rich)
        assert c_rich.confidence >= c_sparse.confidence

    def test_high_risk_capabilities_list(self) -> None:
        assert "financial_transaction" in HIGH_RISK_CAPABILITIES
        assert "data_access" in HIGH_RISK_CAPABILITIES
        assert "user_impersonation" in HIGH_RISK_CAPABILITIES
        assert "system_admin" in HIGH_RISK_CAPABILITIES


# ---------------------------------------------------------------------------
# Route tests
# ---------------------------------------------------------------------------


@pytest.fixture
def risk_config(tmp_path):
    return AirlockConfig(
        lancedb_path=str(tmp_path / "comp_risk.lance"),
        compliance_enabled=True,
    )


@pytest.fixture
async def risk_app(risk_config):
    app = create_app(risk_config)
    async with LifespanManager(app):
        yield app


async def test_route_risk_classification(risk_app):
    transport = ASGITransport(app=risk_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Register an agent first
        await client.post(
            "/compliance/inventory",
            json={
                "did": "did:key:z6MkRiskRoute",
                "display_name": "Risk Route Agent",
                "capabilities": ["financial_transaction"],
                "trust_score": 0.4,
                "trust_tier": 0,
            },
        )

        r = await client.get("/compliance/risk/did:key:z6MkRiskRoute")
    assert r.status_code == 200
    body = r.json()
    assert "risk_level" in body
    assert "risk_factors" in body


async def test_route_risk_not_found(risk_app):
    transport = ASGITransport(app=risk_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        r = await client.get("/compliance/risk/did:key:z6MkNonexistent")
    assert r.status_code == 404
