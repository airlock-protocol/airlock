from __future__ import annotations

"""Tests for OAuth grants — scope validation, private_key_jwt verification, error cases."""

from datetime import UTC, datetime, timedelta
from typing import Any

import jwt as pyjwt
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from airlock.crypto.keys import KeyPair
from airlock.oauth.models import OAuthClient
from airlock.oauth.registration import register_client
from airlock.oauth.scopes import AIRLOCK_SCOPES, is_scope_subset, validate_scopes
from airlock.oauth.server import OAuthServerError, validate_client_assertion
from airlock.oauth.store import OAuthStore

AGENT_SEED = b"grant_agent_seed____000000000000"


def _make_assertion(kp: KeyPair, client_id: str, **overrides: Any) -> str:
    now = datetime.now(UTC)
    payload: dict[str, Any] = {
        "iss": client_id,
        "sub": client_id,
        "aud": "airlock-gateway",
        "iat": now,
        "exp": now + timedelta(seconds=300),
    }
    payload.update(overrides)
    crypto_key = Ed25519PrivateKey.from_private_bytes(kp.signing_key.encode())
    return pyjwt.encode(payload, crypto_key, algorithm="EdDSA")


class TestScopeValidation:
    def test_valid_scope_intersection(self) -> None:
        result = validate_scopes("verify:read trust:write", "verify:read trust:write agent:manage")
        tokens = set(result.split())
        assert tokens == {"verify:read", "trust:write"}

    def test_empty_intersection_raises(self) -> None:
        with pytest.raises(ValueError, match="No valid scopes"):
            validate_scopes("nonexistent:scope", "verify:read")

    def test_unknown_scope_stripped(self) -> None:
        result = validate_scopes("verify:read fake:scope", "verify:read trust:write")
        assert result == "verify:read"

    def test_comma_separated_scopes(self) -> None:
        result = validate_scopes("verify:read,trust:write", "verify:read,trust:write,agent:manage")
        tokens = set(result.split())
        assert tokens == {"verify:read", "trust:write"}

    def test_all_known_scopes(self) -> None:
        all_scopes = " ".join(AIRLOCK_SCOPES.keys())
        result = validate_scopes(all_scopes, all_scopes)
        assert set(result.split()) == set(AIRLOCK_SCOPES.keys())


class TestScopeSubset:
    def test_subset_true(self) -> None:
        assert is_scope_subset("verify:read", "verify:read trust:write") is True

    def test_subset_false(self) -> None:
        assert is_scope_subset("verify:read agent:manage", "verify:read") is False

    def test_equal_sets(self) -> None:
        assert is_scope_subset("verify:read trust:write", "trust:write verify:read") is True

    def test_empty_child(self) -> None:
        # Empty string splits to empty set, which is a subset of anything
        assert is_scope_subset("", "verify:read") is True


class TestPrivateKeyJwtVerification:
    def test_assertion_via_did_lookup(self) -> None:
        """Client assertion with iss/sub set to the DID should resolve."""
        store = OAuthStore()
        kp = KeyPair.from_seed(AGENT_SEED)
        client = register_client(did=kp.did, client_name="test", store=store)
        # Use DID as the sub/iss instead of client_id
        assertion = _make_assertion(kp, kp.did)
        result = validate_client_assertion(assertion, store)
        assert result.client_id == client.client_id

    def test_assertion_with_client_id(self) -> None:
        store = OAuthStore()
        kp = KeyPair.from_seed(AGENT_SEED)
        client = register_client(did=kp.did, client_name="test", store=store)
        assertion = _make_assertion(kp, client.client_id)
        result = validate_client_assertion(assertion, store)
        assert result.did == kp.did

    def test_garbled_jwt(self) -> None:
        store = OAuthStore()
        with pytest.raises(OAuthServerError, match="Cannot decode"):
            validate_client_assertion("not.a.valid.jwt", store)

    def test_missing_sub_and_iss(self) -> None:
        store = OAuthStore()
        kp = KeyPair.from_seed(AGENT_SEED)
        crypto_key = Ed25519PrivateKey.from_private_bytes(kp.signing_key.encode())
        token = pyjwt.encode(
            {"aud": "test", "exp": datetime.now(UTC) + timedelta(seconds=60)},
            crypto_key,
            algorithm="EdDSA",
        )
        with pytest.raises(OAuthServerError, match="must contain"):
            validate_client_assertion(token, store)


class TestOAuthStore:
    def test_register_and_get_client(self) -> None:
        store = OAuthStore()
        client = OAuthClient(
            client_id="c1",
            client_name="test",
            did="did:key:z6Mk" + "a" * 44,
            public_key_multibase="z6Mk" + "a" * 44,
            grant_types=["client_credentials"],
            scope="verify:read",
            registered_at=datetime.now(UTC),
        )
        store.register_client(client)
        assert store.get_client("c1") is not None
        assert store.get_client("missing") is None

    def test_get_client_by_did(self) -> None:
        store = OAuthStore()
        kp = KeyPair.from_seed(AGENT_SEED)
        register_client(did=kp.did, client_name="test", store=store)
        assert store.get_client_by_did(kp.did) is not None
        assert store.get_client_by_did("did:key:z6MkUnknown") is None

    def test_delete_client(self) -> None:
        store = OAuthStore()
        kp = KeyPair.from_seed(AGENT_SEED)
        client = register_client(did=kp.did, client_name="test", store=store)
        assert store.delete_client(client.client_id) is True
        assert store.get_client(client.client_id) is None
        assert store.delete_client("missing") is False

    def test_list_clients(self) -> None:
        store = OAuthStore()
        kp1 = KeyPair.from_seed(AGENT_SEED)
        kp2 = KeyPair.from_seed(b"grant_agent_seed2___000000000000")
        register_client(did=kp1.did, client_name="a", store=store)
        register_client(did=kp2.did, client_name="b", store=store)
        assert len(store.list_clients()) == 2

    def test_token_revocation(self) -> None:
        store = OAuthStore()
        assert store.is_token_revoked("jti-1") is False
        store.revoke_token("jti-1")
        assert store.is_token_revoked("jti-1") is True
