from __future__ import annotations

"""Tests for RFC 7662 token introspection with live trust data."""


import jwt
import pytest
from asgi_lifespan import LifespanManager
from httpx import ASGITransport, AsyncClient

from airlock.config import AirlockConfig
from airlock.crypto.keys import KeyPair
from airlock.gateway.app import create_app
from airlock.oauth.introspection import introspect_token
from airlock.oauth.models import OAuthToken
from airlock.oauth.store import OAuthStore
from airlock.oauth.token_generator import generate_access_token

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

SEED_AGENT = b"introspect_agent_seed___________"
SEED_GW = b"introspect_gw_seed______________"


def _issue_token(
    gw_kp: KeyPair,
    agent_kp: KeyPair,
    store: OAuthStore,
    *,
    scope: str = "verify:read",
    ttl: int = 3600,
    trust_score: float = 0.8,
    trust_tier: int = 2,
) -> str:
    """Issue a token and register it in the store."""
    encoded, jti, expires_at = generate_access_token(
        signing_key=gw_kp.signing_key,
        issuer_did=gw_kp.did,
        subject_did=agent_kp.did,
        client_id="test_client",
        scope=scope,
        trust_score=trust_score,
        trust_tier=trust_tier,
        ttl_seconds=ttl,
    )
    record = OAuthToken(
        access_token=encoded,
        expires_in=ttl,
        scope=scope,
        subject_did=agent_kp.did,
        trust_score=trust_score,
        trust_tier=trust_tier,
        expires_at=expires_at,
        jti=jti,
    )
    store.store_token(record)
    return encoded


# ---------------------------------------------------------------------------
# Tests: Introspection (unit)
# ---------------------------------------------------------------------------


class TestIntrospectionUnit:
    def test_valid_token_introspection(self):
        gw_kp = KeyPair.from_seed(SEED_GW)
        agent_kp = KeyPair.from_seed(SEED_AGENT)
        store = OAuthStore()

        token = _issue_token(gw_kp, agent_kp, store)

        result = introspect_token(
            token,
            verify_key=gw_kp.verify_key,
            issuer_did=gw_kp.did,
            oauth_store=store,
        )

        assert result.active is True
        assert result.sub == agent_kp.did
        assert result.scope == "verify:read"
        assert result.client_id == "test_client"

    def test_expired_token_inactive(self):
        gw_kp = KeyPair.from_seed(SEED_GW)
        agent_kp = KeyPair.from_seed(SEED_AGENT)
        store = OAuthStore()

        # Issue with negative TTL
        encoded, jti, expires_at = generate_access_token(
            signing_key=gw_kp.signing_key,
            issuer_did=gw_kp.did,
            subject_did=agent_kp.did,
            client_id="test_client",
            scope="verify:read",
            ttl_seconds=1,
        )

        # Manually create an expired token record
        import time

        time.sleep(1.1)

        result = introspect_token(
            encoded,
            verify_key=gw_kp.verify_key,
            issuer_did=gw_kp.did,
            oauth_store=store,
        )

        assert result.active is False

    def test_revoked_token_inactive(self):
        gw_kp = KeyPair.from_seed(SEED_GW)
        agent_kp = KeyPair.from_seed(SEED_AGENT)
        store = OAuthStore()

        token = _issue_token(gw_kp, agent_kp, store)

        # Revoke it
        decoded = jwt.decode(token, options={"verify_signature": False}, algorithms=["EdDSA"])
        store.revoke_token(decoded["jti"])

        result = introspect_token(
            token,
            verify_key=gw_kp.verify_key,
            issuer_did=gw_kp.did,
            oauth_store=store,
        )

        assert result.active is False

    def test_garbage_token_inactive(self):
        gw_kp = KeyPair.from_seed(SEED_GW)
        store = OAuthStore()

        result = introspect_token(
            "not.a.valid.jwt",
            verify_key=gw_kp.verify_key,
            issuer_did=gw_kp.did,
            oauth_store=store,
        )

        assert result.active is False

    def test_wrong_issuer_inactive(self):
        gw_kp = KeyPair.from_seed(SEED_GW)
        other_kp = KeyPair.generate()
        agent_kp = KeyPair.from_seed(SEED_AGENT)
        store = OAuthStore()

        # Issue from a different key
        encoded, _, _ = generate_access_token(
            signing_key=other_kp.signing_key,
            issuer_did=other_kp.did,
            subject_did=agent_kp.did,
            client_id="test_client",
            scope="verify:read",
        )

        result = introspect_token(
            encoded,
            verify_key=gw_kp.verify_key,
            issuer_did=gw_kp.did,
            oauth_store=store,
        )

        assert result.active is False

    def test_live_trust_score_lookup(self):
        gw_kp = KeyPair.from_seed(SEED_GW)
        agent_kp = KeyPair.from_seed(SEED_AGENT)
        store = OAuthStore()

        token = _issue_token(gw_kp, agent_kp, store, trust_score=0.5, trust_tier=1)

        # Live lookup returns updated score
        def _lookup(did: str) -> tuple[float, int]:
            return 0.95, 3

        result = introspect_token(
            token,
            verify_key=gw_kp.verify_key,
            issuer_did=gw_kp.did,
            oauth_store=store,
            trust_score_lookup=_lookup,
        )

        assert result.active is True
        # Live score should override token-embedded score
        result_dict = result.model_dump(by_alias=True)
        assert result_dict["airlock:trust_score"] == 0.95
        assert result_dict["airlock:trust_tier"] == 3


# ---------------------------------------------------------------------------
# Tests: Introspection endpoint (integration)
# ---------------------------------------------------------------------------


@pytest.fixture
def gateway_config(tmp_path):
    return AirlockConfig(
        lancedb_path=str(tmp_path / "rep.lance"),
        oauth_enabled=True,
    )


@pytest.fixture
async def gateway_app(gateway_config):
    app = create_app(gateway_config)
    async with LifespanManager(app):
        yield app


@pytest.mark.asyncio
async def test_introspect_endpoint_valid(gateway_app):
    """POST /oauth/introspect with valid token returns active=true."""
    kp = gateway_app.state.airlock_kp
    agent_kp = KeyPair.from_seed(SEED_AGENT)
    store = gateway_app.state.oauth_store

    token = _issue_token(kp, agent_kp, store)

    async with AsyncClient(
        transport=ASGITransport(app=gateway_app), base_url="http://test"
    ) as client:
        resp = await client.post("/oauth/introspect", data={"token": token})

    assert resp.status_code == 200
    data = resp.json()
    assert data["active"] is True
    assert data["sub"] == agent_kp.did


@pytest.mark.asyncio
async def test_introspect_endpoint_invalid(gateway_app):
    """POST /oauth/introspect with invalid token returns active=false."""
    async with AsyncClient(
        transport=ASGITransport(app=gateway_app), base_url="http://test"
    ) as client:
        resp = await client.post("/oauth/introspect", data={"token": "invalid.jwt.here"})

    assert resp.status_code == 200
    data = resp.json()
    assert data["active"] is False


@pytest.mark.asyncio
async def test_introspect_endpoint_missing_token(gateway_app):
    """POST /oauth/introspect without token returns error."""
    async with AsyncClient(
        transport=ASGITransport(app=gateway_app), base_url="http://test"
    ) as client:
        resp = await client.post("/oauth/introspect", data={})

    assert resp.status_code == 400
