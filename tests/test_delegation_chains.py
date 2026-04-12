from __future__ import annotations

"""Tests for RFC 8693 token exchange, scope narrowing, depth limits, and cascade revocation."""


import jwt
import pytest

from airlock.crypto.keys import KeyPair
from airlock.oauth.grants.token_exchange import TokenExchangeError, handle_token_exchange
from airlock.oauth.models import OAuthClient, OAuthToken
from airlock.oauth.store import OAuthStore
from airlock.oauth.token_generator import generate_access_token
from airlock.oauth.token_validator import TokenValidationError, validate_access_token

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

SEED_GW = b"delegation_gw_seed______________"
SEED_AGENT_A = b"delegation_agent_a______________"
SEED_AGENT_B = b"delegation_agent_b______________"
SEED_AGENT_C = b"delegation_agent_c______________"


def _register_client(store: OAuthStore, kp: KeyPair, client_id: str) -> OAuthClient:
    client = OAuthClient(
        client_id=client_id,
        did=kp.did,
        public_key_multibase=kp.public_key_multibase,
        grant_types=["client_credentials", "urn:ietf:params:oauth:grant-type:token-exchange"],
        scope="verify:read trust:write agent:manage",
    )
    store.register_client(client)
    return client


def _issue_root_token(
    gw_kp: KeyPair,
    subject_did: str,
    client_id: str,
    store: OAuthStore,
    *,
    scope: str = "verify:read trust:write agent:manage",
    ttl: int = 3600,
) -> str:
    encoded, jti, expires_at = generate_access_token(
        signing_key=gw_kp.signing_key,
        issuer_did=gw_kp.did,
        subject_did=subject_did,
        client_id=client_id,
        scope=scope,
        trust_score=0.8,
        trust_tier=2,
        ttl_seconds=ttl,
    )
    record = OAuthToken(
        access_token=encoded,
        expires_in=ttl,
        scope=scope,
        subject_did=subject_did,
        trust_score=0.8,
        trust_tier=2,
        expires_at=expires_at,
        jti=jti,
    )
    store.store_token(record)
    return encoded


# ---------------------------------------------------------------------------
# Tests: Basic token exchange
# ---------------------------------------------------------------------------


class TestTokenExchange:
    def test_successful_exchange(self):
        gw_kp = KeyPair.from_seed(SEED_GW)
        agent_a = KeyPair.from_seed(SEED_AGENT_A)
        agent_b = KeyPair.from_seed(SEED_AGENT_B)
        store = OAuthStore()

        _register_client(store, agent_a, "client_a")
        _register_client(store, agent_b, "client_b")

        parent_token = _issue_root_token(gw_kp, agent_a.did, "client_a", store)

        result = handle_token_exchange(
            subject_token=parent_token,
            subject_token_type="urn:ietf:params:oauth:token-type:jwt",
            requested_scope="verify:read",
            oauth_store=store,
            signing_key=gw_kp.signing_key,
            verify_key=gw_kp.verify_key,
            issuer_did=gw_kp.did,
            actor_did=agent_b.did,
            actor_client_id="client_b",
        )

        assert result.token_type == "Bearer"
        assert result.scope == "verify:read"

        # Child token should have act claim
        decoded = jwt.decode(
            result.access_token, options={"verify_signature": False}, algorithms=["EdDSA"]
        )
        assert "act" in decoded
        assert decoded["act"]["sub"] == agent_b.did
        # Original subject preserved
        assert decoded["sub"] == agent_a.did

    def test_invalid_subject_token_type(self):
        gw_kp = KeyPair.from_seed(SEED_GW)
        agent_b = KeyPair.from_seed(SEED_AGENT_B)
        store = OAuthStore()

        with pytest.raises(TokenExchangeError, match="subject_token_type"):
            handle_token_exchange(
                subject_token="some.token",
                subject_token_type="invalid",
                requested_scope=None,
                oauth_store=store,
                signing_key=gw_kp.signing_key,
                verify_key=gw_kp.verify_key,
                issuer_did=gw_kp.did,
                actor_did=agent_b.did,
                actor_client_id="client_b",
            )


# ---------------------------------------------------------------------------
# Tests: Scope narrowing
# ---------------------------------------------------------------------------


class TestScopeNarrowing:
    def test_child_scope_must_be_subset(self):
        gw_kp = KeyPair.from_seed(SEED_GW)
        agent_a = KeyPair.from_seed(SEED_AGENT_A)
        agent_b = KeyPair.from_seed(SEED_AGENT_B)
        store = OAuthStore()

        _register_client(store, agent_a, "client_a")
        parent_token = _issue_root_token(
            gw_kp, agent_a.did, "client_a", store, scope="verify:read"
        )

        with pytest.raises(TokenExchangeError, match="not a subset"):
            handle_token_exchange(
                subject_token=parent_token,
                subject_token_type="urn:ietf:params:oauth:token-type:jwt",
                requested_scope="agent:manage",  # not in parent scope
                oauth_store=store,
                signing_key=gw_kp.signing_key,
                verify_key=gw_kp.verify_key,
                issuer_did=gw_kp.did,
                actor_did=agent_b.did,
                actor_client_id="client_b",
            )

    def test_child_inherits_parent_scope_when_none_requested(self):
        gw_kp = KeyPair.from_seed(SEED_GW)
        agent_a = KeyPair.from_seed(SEED_AGENT_A)
        agent_b = KeyPair.from_seed(SEED_AGENT_B)
        store = OAuthStore()

        _register_client(store, agent_a, "client_a")
        parent_token = _issue_root_token(
            gw_kp, agent_a.did, "client_a", store, scope="verify:read trust:write"
        )

        result = handle_token_exchange(
            subject_token=parent_token,
            subject_token_type="urn:ietf:params:oauth:token-type:jwt",
            requested_scope=None,
            oauth_store=store,
            signing_key=gw_kp.signing_key,
            verify_key=gw_kp.verify_key,
            issuer_did=gw_kp.did,
            actor_did=agent_b.did,
            actor_client_id="client_b",
        )

        assert set(result.scope.split()) == {"verify:read", "trust:write"}

    def test_narrowed_scope_preserved(self):
        gw_kp = KeyPair.from_seed(SEED_GW)
        agent_a = KeyPair.from_seed(SEED_AGENT_A)
        agent_b = KeyPair.from_seed(SEED_AGENT_B)
        store = OAuthStore()

        _register_client(store, agent_a, "client_a")
        parent_token = _issue_root_token(
            gw_kp, agent_a.did, "client_a", store, scope="verify:read trust:write agent:manage"
        )

        result = handle_token_exchange(
            subject_token=parent_token,
            subject_token_type="urn:ietf:params:oauth:token-type:jwt",
            requested_scope="verify:read",
            oauth_store=store,
            signing_key=gw_kp.signing_key,
            verify_key=gw_kp.verify_key,
            issuer_did=gw_kp.did,
            actor_did=agent_b.did,
            actor_client_id="client_b",
        )

        assert result.scope == "verify:read"


# ---------------------------------------------------------------------------
# Tests: Delegation depth limits
# ---------------------------------------------------------------------------


class TestDelegationDepth:
    def test_depth_limit_enforced(self):
        gw_kp = KeyPair.from_seed(SEED_GW)
        agent_a = KeyPair.from_seed(SEED_AGENT_A)
        store = OAuthStore()

        _register_client(store, agent_a, "client_a")

        # Build a chain at max depth
        current_token = _issue_root_token(
            gw_kp, agent_a.did, "client_a", store, scope="verify:read"
        )

        # Create agents for each delegation step
        _depth_seeds = [
            b"delegation_depth_0_test_________",
            b"delegation_depth_1_test_________",
            b"delegation_depth_2_test_________",
            b"delegation_depth_3_test_________",
            b"delegation_depth_4_test_________",
        ]
        for i in range(5):
            delegate_kp = KeyPair.from_seed(_depth_seeds[i])
            _register_client(store, delegate_kp, f"client_depth_{i}")

            result = handle_token_exchange(
                subject_token=current_token,
                subject_token_type="urn:ietf:params:oauth:token-type:jwt",
                requested_scope="verify:read",
                oauth_store=store,
                signing_key=gw_kp.signing_key,
                verify_key=gw_kp.verify_key,
                issuer_did=gw_kp.did,
                actor_did=delegate_kp.did,
                actor_client_id=f"client_depth_{i}",
                max_delegation_depth=5,
            )
            current_token = result.access_token

        # The 6th exchange should fail
        final_kp = KeyPair.from_seed(b"delegation_final________________")
        _register_client(store, final_kp, "client_final")

        with pytest.raises(TokenExchangeError, match="depth"):
            handle_token_exchange(
                subject_token=current_token,
                subject_token_type="urn:ietf:params:oauth:token-type:jwt",
                requested_scope="verify:read",
                oauth_store=store,
                signing_key=gw_kp.signing_key,
                verify_key=gw_kp.verify_key,
                issuer_did=gw_kp.did,
                actor_did=final_kp.did,
                actor_client_id="client_final",
                max_delegation_depth=5,
            )

    def test_single_delegation_allowed(self):
        gw_kp = KeyPair.from_seed(SEED_GW)
        agent_a = KeyPair.from_seed(SEED_AGENT_A)
        agent_b = KeyPair.from_seed(SEED_AGENT_B)
        store = OAuthStore()

        _register_client(store, agent_a, "client_a")
        _register_client(store, agent_b, "client_b")

        parent_token = _issue_root_token(
            gw_kp, agent_a.did, "client_a", store, scope="verify:read"
        )

        # Depth limit of 1 should allow exactly one exchange
        result = handle_token_exchange(
            subject_token=parent_token,
            subject_token_type="urn:ietf:params:oauth:token-type:jwt",
            requested_scope="verify:read",
            oauth_store=store,
            signing_key=gw_kp.signing_key,
            verify_key=gw_kp.verify_key,
            issuer_did=gw_kp.did,
            actor_did=agent_b.did,
            actor_client_id="client_b",
            max_delegation_depth=1,
        )

        assert result.access_token

        # Second exchange should fail at depth 1
        agent_c = KeyPair.from_seed(SEED_AGENT_C)
        _register_client(store, agent_c, "client_c")

        with pytest.raises(TokenExchangeError, match="depth"):
            handle_token_exchange(
                subject_token=result.access_token,
                subject_token_type="urn:ietf:params:oauth:token-type:jwt",
                requested_scope="verify:read",
                oauth_store=store,
                signing_key=gw_kp.signing_key,
                verify_key=gw_kp.verify_key,
                issuer_did=gw_kp.did,
                actor_did=agent_c.did,
                actor_client_id="client_c",
                max_delegation_depth=1,
            )


# ---------------------------------------------------------------------------
# Tests: Cascade revocation
# ---------------------------------------------------------------------------


class TestCascadeRevocation:
    def test_cascade_revokes_children(self):
        gw_kp = KeyPair.from_seed(SEED_GW)
        agent_a = KeyPair.from_seed(SEED_AGENT_A)
        agent_b = KeyPair.from_seed(SEED_AGENT_B)
        agent_c = KeyPair.from_seed(SEED_AGENT_C)
        store = OAuthStore()

        _register_client(store, agent_a, "client_a")
        _register_client(store, agent_b, "client_b")
        _register_client(store, agent_c, "client_c")

        # Create chain: root -> child_b -> child_c
        root_token = _issue_root_token(
            gw_kp, agent_a.did, "client_a", store, scope="verify:read trust:write"
        )
        root_jti = jwt.decode(
            root_token, options={"verify_signature": False}, algorithms=["EdDSA"]
        )["jti"]

        child_b = handle_token_exchange(
            subject_token=root_token,
            subject_token_type="urn:ietf:params:oauth:token-type:jwt",
            requested_scope="verify:read",
            oauth_store=store,
            signing_key=gw_kp.signing_key,
            verify_key=gw_kp.verify_key,
            issuer_did=gw_kp.did,
            actor_did=agent_b.did,
            actor_client_id="client_b",
        )
        child_b_jti = jwt.decode(
            child_b.access_token, options={"verify_signature": False}, algorithms=["EdDSA"]
        )["jti"]

        child_c = handle_token_exchange(
            subject_token=child_b.access_token,
            subject_token_type="urn:ietf:params:oauth:token-type:jwt",
            requested_scope="verify:read",
            oauth_store=store,
            signing_key=gw_kp.signing_key,
            verify_key=gw_kp.verify_key,
            issuer_did=gw_kp.did,
            actor_did=agent_c.did,
            actor_client_id="client_c",
        )
        child_c_jti = jwt.decode(
            child_c.access_token, options={"verify_signature": False}, algorithms=["EdDSA"]
        )["jti"]

        # All tokens should be active
        assert store.is_token_active(root_jti)
        assert store.is_token_active(child_b_jti)
        assert store.is_token_active(child_c_jti)

        # Revoke root -> should cascade to all children
        count = store.revoke_cascade(root_jti)
        assert count == 3

        # All should now be revoked
        assert not store.is_token_active(root_jti)
        assert not store.is_token_active(child_b_jti)
        assert not store.is_token_active(child_c_jti)

    def test_cascade_from_middle(self):
        gw_kp = KeyPair.from_seed(SEED_GW)
        agent_a = KeyPair.from_seed(SEED_AGENT_A)
        agent_b = KeyPair.from_seed(SEED_AGENT_B)
        agent_c = KeyPair.from_seed(SEED_AGENT_C)
        store = OAuthStore()

        _register_client(store, agent_a, "client_a")
        _register_client(store, agent_b, "client_b")
        _register_client(store, agent_c, "client_c")

        root_token = _issue_root_token(
            gw_kp, agent_a.did, "client_a", store, scope="verify:read"
        )
        root_jti = jwt.decode(
            root_token, options={"verify_signature": False}, algorithms=["EdDSA"]
        )["jti"]

        child_b = handle_token_exchange(
            subject_token=root_token,
            subject_token_type="urn:ietf:params:oauth:token-type:jwt",
            requested_scope="verify:read",
            oauth_store=store,
            signing_key=gw_kp.signing_key,
            verify_key=gw_kp.verify_key,
            issuer_did=gw_kp.did,
            actor_did=agent_b.did,
            actor_client_id="client_b",
        )
        child_b_jti = jwt.decode(
            child_b.access_token, options={"verify_signature": False}, algorithms=["EdDSA"]
        )["jti"]

        child_c = handle_token_exchange(
            subject_token=child_b.access_token,
            subject_token_type="urn:ietf:params:oauth:token-type:jwt",
            requested_scope="verify:read",
            oauth_store=store,
            signing_key=gw_kp.signing_key,
            verify_key=gw_kp.verify_key,
            issuer_did=gw_kp.did,
            actor_did=agent_c.did,
            actor_client_id="client_c",
        )
        child_c_jti = jwt.decode(
            child_c.access_token, options={"verify_signature": False}, algorithms=["EdDSA"]
        )["jti"]

        # Revoke from middle -> root stays, children revoked
        count = store.revoke_cascade(child_b_jti)
        assert count == 2

        assert store.is_token_active(root_jti)  # root unaffected
        assert not store.is_token_active(child_b_jti)
        assert not store.is_token_active(child_c_jti)

    def test_revoked_parent_blocks_exchange(self):
        gw_kp = KeyPair.from_seed(SEED_GW)
        agent_a = KeyPair.from_seed(SEED_AGENT_A)
        agent_b = KeyPair.from_seed(SEED_AGENT_B)
        store = OAuthStore()

        _register_client(store, agent_a, "client_a")
        _register_client(store, agent_b, "client_b")

        root_token = _issue_root_token(
            gw_kp, agent_a.did, "client_a", store, scope="verify:read"
        )
        root_jti = jwt.decode(
            root_token, options={"verify_signature": False}, algorithms=["EdDSA"]
        )["jti"]

        # Revoke the root
        store.revoke_token(root_jti)

        # Attempting exchange should fail
        with pytest.raises(TokenExchangeError, match="revoked"):
            handle_token_exchange(
                subject_token=root_token,
                subject_token_type="urn:ietf:params:oauth:token-type:jwt",
                requested_scope="verify:read",
                oauth_store=store,
                signing_key=gw_kp.signing_key,
                verify_key=gw_kp.verify_key,
                issuer_did=gw_kp.did,
                actor_did=agent_b.did,
                actor_client_id="client_b",
            )


# ---------------------------------------------------------------------------
# Tests: Token validation with delegation
# ---------------------------------------------------------------------------


class TestDelegatedTokenValidation:
    def test_validate_delegated_token(self):
        gw_kp = KeyPair.from_seed(SEED_GW)
        agent_a = KeyPair.from_seed(SEED_AGENT_A)
        agent_b = KeyPair.from_seed(SEED_AGENT_B)
        store = OAuthStore()

        _register_client(store, agent_a, "client_a")
        _register_client(store, agent_b, "client_b")

        root_token = _issue_root_token(
            gw_kp, agent_a.did, "client_a", store, scope="verify:read"
        )

        child = handle_token_exchange(
            subject_token=root_token,
            subject_token_type="urn:ietf:params:oauth:token-type:jwt",
            requested_scope="verify:read",
            oauth_store=store,
            signing_key=gw_kp.signing_key,
            verify_key=gw_kp.verify_key,
            issuer_did=gw_kp.did,
            actor_did=agent_b.did,
            actor_client_id="client_b",
        )

        payload = validate_access_token(
            child.access_token,
            verify_key=gw_kp.verify_key,
            expected_issuer=gw_kp.did,
        )

        assert payload["sub"] == agent_a.did
        assert payload["act"]["sub"] == agent_b.did

    def test_validate_rejects_excessive_depth(self):
        gw_kp = KeyPair.from_seed(SEED_GW)
        agent_a = KeyPair.from_seed(SEED_AGENT_A)
        store = OAuthStore()

        _register_client(store, agent_a, "client_a")

        current_token = _issue_root_token(
            gw_kp, agent_a.did, "client_a", store, scope="verify:read"
        )

        _val_seeds = [
            b"val_depth_0_test________________",
            b"val_depth_1_test________________",
            b"val_depth_2_test________________",
        ]
        for i in range(3):
            kp = KeyPair.from_seed(_val_seeds[i])
            _register_client(store, kp, f"val_depth_{i}")

            result = handle_token_exchange(
                subject_token=current_token,
                subject_token_type="urn:ietf:params:oauth:token-type:jwt",
                requested_scope="verify:read",
                oauth_store=store,
                signing_key=gw_kp.signing_key,
                verify_key=gw_kp.verify_key,
                issuer_did=gw_kp.did,
                actor_did=kp.did,
                actor_client_id=f"val_depth_{i}",
                max_delegation_depth=5,
            )
            current_token = result.access_token

        # Validate with max_delegation_depth=2 should fail (token has depth 3)
        with pytest.raises(TokenValidationError, match="depth"):
            validate_access_token(
                current_token,
                verify_key=gw_kp.verify_key,
                expected_issuer=gw_kp.did,
                max_delegation_depth=2,
            )


# ---------------------------------------------------------------------------
# Tests: Actor chain storage
# ---------------------------------------------------------------------------


class TestActorChainStorage:
    def test_actor_chain_recorded(self):
        gw_kp = KeyPair.from_seed(SEED_GW)
        agent_a = KeyPair.from_seed(SEED_AGENT_A)
        agent_b = KeyPair.from_seed(SEED_AGENT_B)
        store = OAuthStore()

        _register_client(store, agent_a, "client_a")
        _register_client(store, agent_b, "client_b")

        root_token = _issue_root_token(
            gw_kp, agent_a.did, "client_a", store, scope="verify:read"
        )

        child = handle_token_exchange(
            subject_token=root_token,
            subject_token_type="urn:ietf:params:oauth:token-type:jwt",
            requested_scope="verify:read",
            oauth_store=store,
            signing_key=gw_kp.signing_key,
            verify_key=gw_kp.verify_key,
            issuer_did=gw_kp.did,
            actor_did=agent_b.did,
            actor_client_id="client_b",
        )

        child_jti = jwt.decode(
            child.access_token, options={"verify_signature": False}, algorithms=["EdDSA"]
        )["jti"]

        record = store.get_token(child_jti)
        assert record is not None
        assert record.delegation_depth == 1
        assert len(record.actor_chain) == 1
        assert record.actor_chain[0]["sub"] == agent_b.did
