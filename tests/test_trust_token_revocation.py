"""Trust token revocation check tests.

Ensures that revoked/suspended DIDs are rejected at token decode time,
the introspect endpoint honours revocation, the default TTL is 120s,
and backward compatibility is preserved when no revocation store is provided.
"""

from __future__ import annotations

import pytest
from asgi_lifespan import LifespanManager
from httpx import ASGITransport, AsyncClient

from airlock.config import AirlockConfig, _reset_config
from airlock.gateway.app import create_app
from airlock.gateway.revocation import RevocationReason, RevocationStore
from airlock.trust_jwt import (
    TokenRevokedError,
    decode_trust_token,
    is_token_revoked,
    mint_verified_trust_token,
)

SECRET = "revocation_test_hs256_secret_value_ok"


# ---- helpers ---------------------------------------------------------------


def _mint(subject_did: str = "did:key:z6MkAgent1", ttl: int = 300) -> str:
    return mint_verified_trust_token(
        subject_did=subject_did,
        session_id="sess-rev-1",
        trust_score=0.80,
        issuer_did="did:key:z6MkGateway",
        secret=SECRET,
        ttl_seconds=ttl,
    )


# ---- unit tests: decode_trust_token with revocation -----------------------


def test_valid_token_with_revocation_check() -> None:
    """A non-revoked DID passes the revocation check."""
    store = RevocationStore()
    token = _mint()
    claims = decode_trust_token(token, SECRET, revocation_store=store)
    assert claims["sub"] == "did:key:z6MkAgent1"
    assert claims["ver"] == "VERIFIED"


@pytest.mark.asyncio
async def test_revoked_did_token_rejected() -> None:
    """A permanently revoked DID's token is rejected even when not expired."""
    store = RevocationStore()
    await store.revoke("did:key:z6MkAgent1", RevocationReason.KEY_COMPROMISE)

    token = _mint()
    with pytest.raises(TokenRevokedError) as exc_info:
        decode_trust_token(token, SECRET, revocation_store=store)
    assert "did:key:z6MkAgent1" in str(exc_info.value)


@pytest.mark.asyncio
async def test_suspended_did_token_rejected() -> None:
    """A suspended DID's token is also rejected (suspension counts as revoked)."""
    store = RevocationStore()
    await store.suspend("did:key:z6MkAgent1")

    token = _mint()
    with pytest.raises(TokenRevokedError):
        decode_trust_token(token, SECRET, revocation_store=store)


def test_no_store_skips_check() -> None:
    """Backward compat: when no revocation_store is passed, no check is performed."""
    token = _mint()
    # Should succeed even though no store to consult
    claims = decode_trust_token(token, SECRET)
    assert claims["sub"] == "did:key:z6MkAgent1"

    # Explicit None is equivalent
    claims2 = decode_trust_token(token, SECRET, revocation_store=None)
    assert claims2["sub"] == "did:key:z6MkAgent1"


# ---- unit test: is_token_revoked utility -----------------------------------


@pytest.mark.asyncio
async def test_is_token_revoked_true() -> None:
    store = RevocationStore()
    await store.revoke("did:key:z6MkBad")
    payload = {"sub": "did:key:z6MkBad", "ver": "VERIFIED"}
    assert is_token_revoked(payload, store) is True


def test_is_token_revoked_false() -> None:
    store = RevocationStore()
    payload = {"sub": "did:key:z6MkGood", "ver": "VERIFIED"}
    assert is_token_revoked(payload, store) is False


def test_is_token_revoked_missing_sub() -> None:
    store = RevocationStore()
    assert is_token_revoked({}, store) is False


# ---- config test: reduced default TTL -------------------------------------


def test_reduced_default_ttl() -> None:
    """Default trust_token_ttl_seconds is now 120 (was 600)."""
    _reset_config()
    try:
        cfg = AirlockConfig(lancedb_path="/tmp/ttl_test.lance")
        assert cfg.trust_token_ttl_seconds == 120
    finally:
        _reset_config()


def test_ttl_still_accepts_600() -> None:
    """Backward compat: operators can still set TTL up to 86400."""
    _reset_config()
    try:
        cfg = AirlockConfig(
            lancedb_path="/tmp/ttl_test.lance",
            trust_token_ttl_seconds=600,
        )
        assert cfg.trust_token_ttl_seconds == 600
    finally:
        _reset_config()


# ---- integration test: introspect endpoint revocation ----------------------


@pytest.mark.asyncio
async def test_introspect_revoked_returns_inactive(tmp_path) -> None:
    """POST /token/introspect returns {active: false, reason: did_revoked} for revoked DID."""
    _reset_config()
    try:
        cfg = AirlockConfig(
            lancedb_path=str(tmp_path / "revoc.lance"),
            trust_token_secret="introspect_revocation_test_secret_value",
        )
        app = create_app(cfg)
        async with LifespanManager(app):
            # Mint a valid token using the app's secret
            token = mint_verified_trust_token(
                subject_did="did:key:z6MkRevokedAgent",
                session_id="sess-introspect-rev",
                trust_score=0.75,
                issuer_did=app.state.airlock_kp.did,
                secret=cfg.trust_token_secret,
                ttl_seconds=300,
            )

            # Revoke the DID
            store = app.state.revocation_store
            await store.revoke(
                "did:key:z6MkRevokedAgent",
                RevocationReason.KEY_COMPROMISE,
            )

            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://test"
            ) as client:
                resp = await client.post("/token/introspect", json={"token": token})

        assert resp.status_code == 200
        body = resp.json()
        assert body["active"] is False
        assert body["reason"] == "did_revoked"
    finally:
        _reset_config()


@pytest.mark.asyncio
async def test_introspect_valid_token_still_active(tmp_path) -> None:
    """POST /token/introspect returns active=true for non-revoked DID."""
    _reset_config()
    try:
        cfg = AirlockConfig(
            lancedb_path=str(tmp_path / "ok.lance"),
            trust_token_secret="introspect_ok_test_secret_value_here",
        )
        app = create_app(cfg)
        async with LifespanManager(app):
            token = mint_verified_trust_token(
                subject_did="did:key:z6MkGoodAgent",
                session_id="sess-introspect-ok",
                trust_score=0.90,
                issuer_did=app.state.airlock_kp.did,
                secret=cfg.trust_token_secret,
                ttl_seconds=300,
            )

            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://test"
            ) as client:
                resp = await client.post("/token/introspect", json={"token": token})

        assert resp.status_code == 200
        body = resp.json()
        assert body["active"] is True
        assert body["claims"]["sub"] == "did:key:z6MkGoodAgent"
    finally:
        _reset_config()
