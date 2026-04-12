from __future__ import annotations

"""Tests for OAuth token introspection with live trust data."""

import pytest

from airlock.crypto.keys import KeyPair
from airlock.oauth.introspection import introspect_token
from airlock.oauth.store import OAuthStore
from airlock.oauth.token_generator import generate_access_token

GATEWAY_SEED = b"intro_gateway_seed__000000000000"
AGENT_SEED = b"intro_agent_seed____000000000000"


def _mint_token(
    gateway_kp: KeyPair,
    agent_kp: KeyPair,
    *,
    ttl: int = 3600,
    trust_score: float | None = 0.85,
    trust_tier: int | None = 2,
    scope: str = "verify:read",
) -> str:
    return generate_access_token(
        subject_did=agent_kp.did,
        client_id="test-client-id",
        scope=scope,
        signing_key=gateway_kp.signing_key,
        issuer_did=gateway_kp.did,
        ttl_seconds=ttl,
        trust_score=trust_score,
        trust_tier=trust_tier,
    )


class TestIntrospection:
    @pytest.fixture
    def gateway_kp(self) -> KeyPair:
        return KeyPair.from_seed(GATEWAY_SEED)

    @pytest.fixture
    def agent_kp(self) -> KeyPair:
        return KeyPair.from_seed(AGENT_SEED)

    async def test_valid_token(self, gateway_kp: KeyPair, agent_kp: KeyPair) -> None:
        store = OAuthStore()
        token = _mint_token(gateway_kp, agent_kp)
        result = await introspect_token(token, store, None, gateway_kp.verify_key)

        assert result.active is True
        assert result.sub == agent_kp.did
        assert result.client_id == "test-client-id"
        assert result.scope == "verify:read"
        assert result.trust_score == pytest.approx(0.85)
        assert result.trust_tier == 2

    async def test_expired_token(self, gateway_kp: KeyPair, agent_kp: KeyPair) -> None:
        store = OAuthStore()
        # Build an already-expired token via direct jwt encoding
        from datetime import UTC, datetime, timedelta

        import jwt as pyjwt
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        crypto_key = Ed25519PrivateKey.from_private_bytes(gateway_kp.signing_key.encode())
        now = datetime.now(UTC)
        expired_token = pyjwt.encode(
            {
                "sub": agent_kp.did,
                "iss": gateway_kp.did,
                "aud": "airlock-agent",
                "iat": now - timedelta(seconds=7200),
                "exp": now - timedelta(seconds=3600),
                "scope": "verify:read",
                "jti": "expired-jti",
            },
            crypto_key,
            algorithm="EdDSA",
        )
        result = await introspect_token(expired_token, store, None, gateway_kp.verify_key)
        assert result.active is False

    async def test_revoked_token(self, gateway_kp: KeyPair, agent_kp: KeyPair) -> None:
        store = OAuthStore()
        token = _mint_token(gateway_kp, agent_kp)

        # Decode to get the jti, then revoke it
        from airlock.oauth.token_validator import validate_access_token

        claims = validate_access_token(token, gateway_kp.verify_key)
        store.revoke_token(claims["jti"])

        result = await introspect_token(token, store, None, gateway_kp.verify_key)
        assert result.active is False

    async def test_invalid_token(self, gateway_kp: KeyPair) -> None:
        store = OAuthStore()
        result = await introspect_token("garbage.token.here", store, None, gateway_kp.verify_key)
        assert result.active is False

    async def test_wrong_key(self, gateway_kp: KeyPair, agent_kp: KeyPair) -> None:
        """Token signed by a different key should be inactive."""
        other_kp = KeyPair.generate()
        token = _mint_token(other_kp, agent_kp)
        store = OAuthStore()
        result = await introspect_token(token, store, None, gateway_kp.verify_key)
        assert result.active is False
