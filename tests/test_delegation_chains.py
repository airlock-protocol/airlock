from __future__ import annotations

"""Tests for RFC 8693 Token Exchange and delegation chains."""

from datetime import UTC, datetime, timedelta
from typing import Any

import jwt as pyjwt
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from airlock.config import AirlockConfig
from airlock.crypto.keys import KeyPair
from airlock.oauth.models import TokenRequest
from airlock.oauth.registration import register_client
from airlock.oauth.server import OAuthServerError, process_token_request
from airlock.oauth.store import OAuthStore
from airlock.oauth.token_generator import generate_access_token
from airlock.oauth.token_validator import OAuthTokenError, validate_access_token

GATEWAY_SEED = b"deleg_gateway_seed__000000000000"
AGENT_A_SEED = b"deleg_agent_a_seed__000000000000"
AGENT_B_SEED = b"deleg_agent_b_seed__000000000000"
AGENT_C_SEED = b"deleg_agent_c_seed__000000000000"


def _assertion(kp: KeyPair, client_id: str) -> str:
    now = datetime.now(UTC)
    payload: dict[str, Any] = {
        "iss": client_id,
        "sub": client_id,
        "aud": "airlock-gateway",
        "iat": now,
        "exp": now + timedelta(seconds=300),
    }
    crypto_key = Ed25519PrivateKey.from_private_bytes(kp.signing_key.encode())
    return pyjwt.encode(payload, crypto_key, algorithm="EdDSA")


class TestTokenExchange:
    @pytest.fixture
    def gateway_kp(self) -> KeyPair:
        return KeyPair.from_seed(GATEWAY_SEED)

    @pytest.fixture
    def agent_a_kp(self) -> KeyPair:
        return KeyPair.from_seed(AGENT_A_SEED)

    @pytest.fixture
    def agent_b_kp(self) -> KeyPair:
        return KeyPair.from_seed(AGENT_B_SEED)

    @pytest.fixture
    def agent_c_kp(self) -> KeyPair:
        return KeyPair.from_seed(AGENT_C_SEED)

    @pytest.fixture
    def config(self) -> AirlockConfig:
        return AirlockConfig(oauth_max_delegation_depth=2)

    def test_basic_token_exchange(
        self, gateway_kp: KeyPair, agent_a_kp: KeyPair, agent_b_kp: KeyPair, config: AirlockConfig
    ) -> None:
        store = OAuthStore()
        client_a = register_client(did=agent_a_kp.did, client_name="agent-a", store=store)
        client_b = register_client(did=agent_b_kp.did, client_name="agent-b", store=store)

        # Agent A gets a direct token
        subject_token = generate_access_token(
            subject_did=agent_a_kp.did,
            client_id=client_a.client_id,
            scope="verify:read trust:write",
            signing_key=gateway_kp.signing_key,
            issuer_did=gateway_kp.did,
            ttl_seconds=3600,
        )

        # Agent B requests token exchange
        request = TokenRequest(
            grant_type="urn:ietf:params:oauth:grant-type:token-exchange",
            client_assertion=_assertion(agent_b_kp, client_b.client_id),
            subject_token=subject_token,
            subject_token_type="urn:ietf:params:oauth:token-type:access_token",
            scope="verify:read",
        )

        response = process_token_request(
            request,
            store,
            signing_key=gateway_kp.signing_key,
            issuer_did=gateway_kp.did,
            config=config,
            verify_key=gateway_kp.verify_key,
        )
        assert response.access_token
        assert response.scope == "verify:read"

        # Verify the delegation chain in the token
        claims = validate_access_token(response.access_token, gateway_kp.verify_key)
        assert claims["sub"] == agent_b_kp.did
        assert "act" in claims
        assert claims["act"]["sub"] == agent_a_kp.did

    def test_scope_narrowing(
        self, gateway_kp: KeyPair, agent_a_kp: KeyPair, agent_b_kp: KeyPair, config: AirlockConfig
    ) -> None:
        store = OAuthStore()
        client_a = register_client(did=agent_a_kp.did, client_name="agent-a", store=store)
        client_b = register_client(did=agent_b_kp.did, client_name="agent-b", store=store)

        subject_token = generate_access_token(
            subject_did=agent_a_kp.did,
            client_id=client_a.client_id,
            scope="verify:read",
            signing_key=gateway_kp.signing_key,
            issuer_did=gateway_kp.did,
            ttl_seconds=3600,
        )

        # Request broader scope than subject token allows
        request = TokenRequest(
            grant_type="urn:ietf:params:oauth:grant-type:token-exchange",
            client_assertion=_assertion(agent_b_kp, client_b.client_id),
            subject_token=subject_token,
            scope="verify:read trust:write",  # trust:write not in subject
        )

        with pytest.raises(OAuthServerError, match="exceed subject token"):
            process_token_request(
                request,
                store,
                signing_key=gateway_kp.signing_key,
                issuer_did=gateway_kp.did,
                config=config,
                verify_key=gateway_kp.verify_key,
            )

    def test_max_delegation_depth(
        self,
        gateway_kp: KeyPair,
        agent_a_kp: KeyPair,
        agent_b_kp: KeyPair,
        agent_c_kp: KeyPair,
        config: AirlockConfig,
    ) -> None:
        """With max_depth=2, a three-agent chain (A->B->C) should be rejected."""
        store = OAuthStore()
        client_a = register_client(did=agent_a_kp.did, client_name="agent-a", store=store)
        client_b = register_client(did=agent_b_kp.did, client_name="agent-b", store=store)
        client_c = register_client(did=agent_c_kp.did, client_name="agent-c", store=store)

        # Token for A
        token_a = generate_access_token(
            subject_did=agent_a_kp.did,
            client_id=client_a.client_id,
            scope="verify:read",
            signing_key=gateway_kp.signing_key,
            issuer_did=gateway_kp.did,
            ttl_seconds=3600,
        )

        # B exchanges A's token
        req_b = TokenRequest(
            grant_type="urn:ietf:params:oauth:grant-type:token-exchange",
            client_assertion=_assertion(agent_b_kp, client_b.client_id),
            subject_token=token_a,
            scope="verify:read",
        )
        resp_b = process_token_request(
            req_b,
            store,
            signing_key=gateway_kp.signing_key,
            issuer_did=gateway_kp.did,
            config=config,
            verify_key=gateway_kp.verify_key,
        )

        # C exchanges B's token (chain: A -> B -> C = depth 3, which is the max)
        req_c = TokenRequest(
            grant_type="urn:ietf:params:oauth:grant-type:token-exchange",
            client_assertion=_assertion(agent_c_kp, client_c.client_id),
            subject_token=resp_b.access_token,
            scope="verify:read",
        )
        with pytest.raises(OAuthServerError, match="exceed maximum depth"):
            process_token_request(
                req_c,
                store,
                signing_key=gateway_kp.signing_key,
                issuer_did=gateway_kp.did,
                config=config,
                verify_key=gateway_kp.verify_key,
            )

    def test_missing_subject_token(
        self, gateway_kp: KeyPair, agent_b_kp: KeyPair, config: AirlockConfig
    ) -> None:
        store = OAuthStore()
        client_b = register_client(did=agent_b_kp.did, client_name="agent-b", store=store)

        request = TokenRequest(
            grant_type="urn:ietf:params:oauth:grant-type:token-exchange",
            client_assertion=_assertion(agent_b_kp, client_b.client_id),
        )
        with pytest.raises(OAuthServerError, match="subject_token is required"):
            process_token_request(
                request,
                store,
                signing_key=gateway_kp.signing_key,
                issuer_did=gateway_kp.did,
                config=config,
                verify_key=gateway_kp.verify_key,
            )

    def test_cascade_revocation(
        self, gateway_kp: KeyPair, agent_a_kp: KeyPair, agent_b_kp: KeyPair, config: AirlockConfig
    ) -> None:
        """Revoking the parent token's jti makes exchange fail when used as subject_token."""
        store = OAuthStore()
        client_a = register_client(did=agent_a_kp.did, client_name="agent-a", store=store)
        client_b = register_client(did=agent_b_kp.did, client_name="agent-b", store=store)

        subject_token = generate_access_token(
            subject_did=agent_a_kp.did,
            client_id=client_a.client_id,
            scope="verify:read",
            signing_key=gateway_kp.signing_key,
            issuer_did=gateway_kp.did,
            ttl_seconds=3600,
        )

        # Revoke the subject token
        claims = validate_access_token(subject_token, gateway_kp.verify_key)
        store.revoke_token(claims["jti"])

        # Try to exchange — should fail
        request = TokenRequest(
            grant_type="urn:ietf:params:oauth:grant-type:token-exchange",
            client_assertion=_assertion(agent_b_kp, client_b.client_id),
            subject_token=subject_token,
            scope="verify:read",
        )
        with pytest.raises(OAuthServerError, match="Invalid subject token"):
            process_token_request(
                request,
                store,
                signing_key=gateway_kp.signing_key,
                issuer_did=gateway_kp.did,
                config=config,
                verify_key=gateway_kp.verify_key,
            )


class TestTokenValidator:
    def test_validate_good_token(self) -> None:
        gw = KeyPair.from_seed(GATEWAY_SEED)
        agent = KeyPair.from_seed(AGENT_A_SEED)
        token = generate_access_token(
            subject_did=agent.did,
            client_id="c1",
            scope="verify:read",
            signing_key=gw.signing_key,
            issuer_did=gw.did,
            ttl_seconds=3600,
        )
        claims = validate_access_token(token, gw.verify_key)
        assert claims["sub"] == agent.did

    def test_revoked_token_rejected(self) -> None:
        gw = KeyPair.from_seed(GATEWAY_SEED)
        agent = KeyPair.from_seed(AGENT_A_SEED)
        token = generate_access_token(
            subject_did=agent.did,
            client_id="c1",
            scope="verify:read",
            signing_key=gw.signing_key,
            issuer_did=gw.did,
            ttl_seconds=3600,
        )
        claims = validate_access_token(token, gw.verify_key)
        jti = claims["jti"]

        with pytest.raises(OAuthTokenError, match="revoked"):
            validate_access_token(token, gw.verify_key, revocation_check=lambda j: j == jti)

    def test_wrong_audience(self) -> None:
        gw = KeyPair.from_seed(GATEWAY_SEED)
        agent = KeyPair.from_seed(AGENT_A_SEED)
        token = generate_access_token(
            subject_did=agent.did,
            client_id="c1",
            scope="verify:read",
            signing_key=gw.signing_key,
            issuer_did=gw.did,
            ttl_seconds=3600,
        )
        with pytest.raises(OAuthTokenError, match="Token validation failed"):
            validate_access_token(token, gw.verify_key, audience="wrong-audience")
