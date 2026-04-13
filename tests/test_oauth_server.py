from __future__ import annotations

"""Tests for the OAuth 2.1 authorization server — token endpoint and client credentials."""

from datetime import UTC, datetime, timedelta
from typing import Any

import jwt as pyjwt
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from airlock.config import AirlockConfig
from airlock.crypto.keys import KeyPair
from airlock.oauth.models import TokenRequest
from airlock.oauth.registration import register_client
from airlock.oauth.server import OAuthServerError, process_token_request, validate_client_assertion
from airlock.oauth.store import OAuthStore
from airlock.oauth.token_validator import validate_access_token

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

GATEWAY_SEED = b"oauth_gateway_seed__000000000000"
AGENT_SEED = b"oauth_agent_seed____000000000000"


def _make_client_assertion(
    kp: KeyPair,
    client_id: str,
    *,
    audience: str = "airlock-gateway",
    ttl_seconds: int = 300,
    extra: dict[str, Any] | None = None,
) -> str:
    """Build a signed client assertion JWT."""
    now = datetime.now(UTC)
    payload: dict[str, Any] = {
        "iss": client_id,
        "sub": client_id,
        "aud": audience,
        "iat": now,
        "exp": now + timedelta(seconds=ttl_seconds),
    }
    if extra:
        payload.update(extra)
    crypto_key = Ed25519PrivateKey.from_private_bytes(kp.signing_key.encode())
    return pyjwt.encode(payload, crypto_key, algorithm="EdDSA")


def _setup_store_and_client(
    agent_kp: KeyPair | None = None,
) -> tuple[OAuthStore, str, KeyPair]:
    """Register a client and return (store, client_id, agent_keypair)."""
    store = OAuthStore()
    kp = agent_kp or KeyPair.from_seed(AGENT_SEED)
    client = register_client(did=kp.did, client_name="test-agent", store=store)
    return store, client.client_id, kp


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestValidateClientAssertion:
    def test_valid_assertion(self) -> None:
        store, client_id, kp = _setup_store_and_client()
        assertion = _make_client_assertion(kp, client_id)
        client = validate_client_assertion(assertion, store)
        assert client.client_id == client_id
        assert client.did == kp.did

    def test_unknown_client_id(self) -> None:
        store = OAuthStore()
        kp = KeyPair.from_seed(AGENT_SEED)
        assertion = _make_client_assertion(kp, "unknown-id")
        with pytest.raises(OAuthServerError, match="Unknown client"):
            validate_client_assertion(assertion, store)

    def test_wrong_key_signature(self) -> None:
        store, client_id, _ = _setup_store_and_client()
        wrong_kp = KeyPair.generate()
        assertion = _make_client_assertion(wrong_kp, client_id)
        with pytest.raises(OAuthServerError, match="signature verification failed"):
            validate_client_assertion(assertion, store)

    def test_inactive_client(self) -> None:
        store, client_id, kp = _setup_store_and_client()
        c = store.get_client(client_id)
        assert c is not None
        c.status = "suspended"
        store.register_client(c)
        assertion = _make_client_assertion(kp, client_id)
        with pytest.raises(OAuthServerError, match="suspended"):
            validate_client_assertion(assertion, store)


class TestClientCredentialsGrant:
    def test_successful_token_issuance(self) -> None:
        gateway_kp = KeyPair.from_seed(GATEWAY_SEED)
        store, client_id, agent_kp = _setup_store_and_client()
        assertion = _make_client_assertion(agent_kp, client_id)
        config = AirlockConfig()

        request = TokenRequest(
            grant_type="client_credentials",
            client_assertion=assertion,
            client_assertion_type="urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            scope="verify:read trust:write",
        )
        response = process_token_request(
            request, store, signing_key=gateway_kp.signing_key, issuer_did=gateway_kp.did, config=config,
        )
        assert response.access_token
        assert response.token_type == "Bearer"
        assert response.expires_in == 3600
        assert "verify:read" in response.scope

    def test_token_contains_trust_claims(self) -> None:
        gateway_kp = KeyPair.from_seed(GATEWAY_SEED)
        store, client_id, agent_kp = _setup_store_and_client()
        assertion = _make_client_assertion(agent_kp, client_id)
        config = AirlockConfig()

        request = TokenRequest(
            grant_type="client_credentials",
            client_assertion=assertion,
            scope="verify:read",
        )
        response = process_token_request(
            request, store, signing_key=gateway_kp.signing_key, issuer_did=gateway_kp.did, config=config,
        )

        # Decode the access token and check structure
        claims = validate_access_token(response.access_token, gateway_kp.verify_key)
        assert claims["sub"] == agent_kp.did
        assert claims["iss"] == gateway_kp.did
        assert claims["scope"] == "verify:read"
        assert "jti" in claims

    def test_missing_assertion(self) -> None:
        gateway_kp = KeyPair.from_seed(GATEWAY_SEED)
        store = OAuthStore()
        config = AirlockConfig()

        request = TokenRequest(grant_type="client_credentials")
        with pytest.raises(OAuthServerError, match="client_assertion is required"):
            process_token_request(
                request, store, signing_key=gateway_kp.signing_key, issuer_did=gateway_kp.did, config=config,
            )

    def test_invalid_scope(self) -> None:
        gateway_kp = KeyPair.from_seed(GATEWAY_SEED)
        store, client_id, agent_kp = _setup_store_and_client()
        assertion = _make_client_assertion(agent_kp, client_id)
        config = AirlockConfig()

        request = TokenRequest(
            grant_type="client_credentials",
            client_assertion=assertion,
            scope="nonexistent:scope",
        )
        with pytest.raises(OAuthServerError, match="No valid scopes"):
            process_token_request(
                request, store, signing_key=gateway_kp.signing_key, issuer_did=gateway_kp.did, config=config,
            )

    def test_unsupported_grant_type(self) -> None:
        gateway_kp = KeyPair.from_seed(GATEWAY_SEED)
        store = OAuthStore()
        config = AirlockConfig()

        request = TokenRequest(grant_type="authorization_code")
        with pytest.raises(OAuthServerError, match="not supported"):
            process_token_request(
                request, store, signing_key=gateway_kp.signing_key, issuer_did=gateway_kp.did, config=config,
            )
