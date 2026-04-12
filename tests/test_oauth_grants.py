from __future__ import annotations

"""Tests for OAuth grant types: scope validation, private_key_jwt verification."""

import uuid
from datetime import UTC, datetime, timedelta

import jwt
import pytest

from airlock.crypto.keys import KeyPair
from airlock.oauth.grants.client_credentials import (
    ClientCredentialsError,
    handle_client_credentials,
    verify_client_assertion,
)
from airlock.oauth.models import OAuthClient
from airlock.oauth.scopes import AIRLOCK_SCOPES, is_scope_subset, validate_scopes
from airlock.oauth.store import OAuthStore
from airlock.oauth.token_generator import _ed25519_private_key_pem

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

SEED_A = b"32_byte_deterministic_seed______"
SEED_GW = b"gw_oauth_grant_test_seed________"
TOKEN_ENDPOINT = "http://test/oauth/token"


def _make_assertion(
    kp: KeyPair,
    client_id: str,
    audience: str,
    *,
    expires_in: int = 60,
    iss: str | None = None,
    sub: str | None = None,
) -> str:
    now = datetime.now(UTC)
    payload = {
        "iss": iss or client_id,
        "sub": sub or client_id,
        "aud": audience,
        "iat": now,
        "exp": now + timedelta(seconds=expires_in),
        "jti": str(uuid.uuid4()),
    }
    pem = _ed25519_private_key_pem(kp.signing_key)
    return jwt.encode(payload, pem, algorithm="EdDSA")


def _make_client(kp: KeyPair, client_id: str = "test_client") -> OAuthClient:
    return OAuthClient(
        client_id=client_id,
        client_name="Test",
        did=kp.did,
        public_key_multibase=kp.public_key_multibase,
        grant_types=["client_credentials"],
        scope="verify:read trust:write",
    )


# ---------------------------------------------------------------------------
# Tests: Scope validation
# ---------------------------------------------------------------------------


class TestScopeValidation:
    def test_validate_known_scopes(self):
        result = validate_scopes("verify:read trust:write")
        assert result == ["verify:read", "trust:write"]

    def test_validate_unknown_scope_raises(self):
        with pytest.raises(ValueError, match="Unknown scope"):
            validate_scopes("nonexistent:scope")

    def test_validate_empty_string(self):
        assert validate_scopes("") == []
        assert validate_scopes("  ") == []

    def test_validate_with_allowed_subset(self):
        result = validate_scopes("verify:read", allowed_scopes="verify:read,trust:write")
        assert result == ["verify:read"]

    def test_validate_scope_not_permitted(self):
        with pytest.raises(ValueError, match="not permitted"):
            validate_scopes("agent:manage", allowed_scopes="verify:read")

    def test_all_scopes_known(self):
        all_scopes = " ".join(AIRLOCK_SCOPES.keys())
        result = validate_scopes(all_scopes)
        assert len(result) == len(AIRLOCK_SCOPES)


class TestScopeSubset:
    def test_subset_true(self):
        assert is_scope_subset("verify:read", "verify:read trust:write")

    def test_subset_false(self):
        assert not is_scope_subset("agent:manage", "verify:read trust:write")

    def test_empty_child_is_subset(self):
        assert is_scope_subset("", "verify:read")

    def test_empty_parent_is_not_superset(self):
        assert not is_scope_subset("verify:read", "")

    def test_equal_sets(self):
        assert is_scope_subset("verify:read trust:write", "trust:write verify:read")


# ---------------------------------------------------------------------------
# Tests: Client assertion verification
# ---------------------------------------------------------------------------


class TestClientAssertionVerification:
    def test_valid_assertion(self):
        kp = KeyPair.from_seed(SEED_A)
        client = _make_client(kp)
        assertion = _make_assertion(kp, client.client_id, TOKEN_ENDPOINT)
        payload = verify_client_assertion(assertion, client, TOKEN_ENDPOINT)
        assert payload["sub"] == client.client_id
        assert payload["iss"] == client.client_id

    def test_wrong_key_raises(self):
        kp = KeyPair.from_seed(SEED_A)
        wrong_kp = KeyPair.generate()
        client = _make_client(kp)
        assertion = _make_assertion(wrong_kp, client.client_id, TOKEN_ENDPOINT)
        with pytest.raises(ClientCredentialsError, match="signature invalid"):
            verify_client_assertion(assertion, client, TOKEN_ENDPOINT)

    def test_expired_assertion_raises(self):
        kp = KeyPair.from_seed(SEED_A)
        client = _make_client(kp)
        assertion = _make_assertion(kp, client.client_id, TOKEN_ENDPOINT, expires_in=-10)
        with pytest.raises(ClientCredentialsError, match="expired"):
            verify_client_assertion(assertion, client, TOKEN_ENDPOINT)

    def test_wrong_audience_raises(self):
        kp = KeyPair.from_seed(SEED_A)
        client = _make_client(kp)
        assertion = _make_assertion(kp, client.client_id, "http://wrong/endpoint")
        with pytest.raises(ClientCredentialsError, match="audience"):
            verify_client_assertion(assertion, client, TOKEN_ENDPOINT)

    def test_sub_mismatch_raises(self):
        kp = KeyPair.from_seed(SEED_A)
        client = _make_client(kp)
        assertion = _make_assertion(
            kp, client.client_id, TOKEN_ENDPOINT, sub="wrong_client_id"
        )
        with pytest.raises(ClientCredentialsError, match="sub"):
            verify_client_assertion(assertion, client, TOKEN_ENDPOINT)


# ---------------------------------------------------------------------------
# Tests: Full client credentials grant
# ---------------------------------------------------------------------------


class TestClientCredentialsGrant:
    def test_successful_grant(self):
        agent_kp = KeyPair.from_seed(SEED_A)
        gw_kp = KeyPair.from_seed(SEED_GW)
        store = OAuthStore()
        client = _make_client(agent_kp)
        store.register_client(client)

        assertion = _make_assertion(agent_kp, client.client_id, TOKEN_ENDPOINT)

        response = handle_client_credentials(
            client_assertion=assertion,
            client_assertion_type="urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            requested_scope="verify:read",
            oauth_store=store,
            signing_key=gw_kp.signing_key,
            issuer_did=gw_kp.did,
            token_endpoint=TOKEN_ENDPOINT,
            ttl_seconds=3600,
            trust_score=0.75,
            trust_tier=2,
        )

        assert response.token_type == "Bearer"
        assert response.expires_in == 3600
        assert response.scope == "verify:read"
        assert response.access_token

    def test_suspended_client_rejected(self):
        agent_kp = KeyPair.from_seed(SEED_A)
        gw_kp = KeyPair.from_seed(SEED_GW)
        store = OAuthStore()
        client = _make_client(agent_kp)
        store.register_client(client)
        store.suspend_client(client.client_id)

        assertion = _make_assertion(agent_kp, client.client_id, TOKEN_ENDPOINT)

        with pytest.raises(ClientCredentialsError, match="suspended"):
            handle_client_credentials(
                client_assertion=assertion,
                client_assertion_type="urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                requested_scope=None,
                oauth_store=store,
                signing_key=gw_kp.signing_key,
                issuer_did=gw_kp.did,
                token_endpoint=TOKEN_ENDPOINT,
            )

    def test_token_stored_in_store(self):
        agent_kp = KeyPair.from_seed(SEED_A)
        gw_kp = KeyPair.from_seed(SEED_GW)
        store = OAuthStore()
        client = _make_client(agent_kp)
        store.register_client(client)

        assertion = _make_assertion(agent_kp, client.client_id, TOKEN_ENDPOINT)

        response = handle_client_credentials(
            client_assertion=assertion,
            client_assertion_type="urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            requested_scope="verify:read",
            oauth_store=store,
            signing_key=gw_kp.signing_key,
            issuer_did=gw_kp.did,
            token_endpoint=TOKEN_ENDPOINT,
        )

        # Token should be stored
        decoded = jwt.decode(
            response.access_token, options={"verify_signature": False}, algorithms=["EdDSA"]
        )
        jti = decoded["jti"]
        stored = store.get_token(jti)
        assert stored is not None
        assert stored.subject_did == agent_kp.did
        assert not stored.revoked
