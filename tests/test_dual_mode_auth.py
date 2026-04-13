"""Tests for dual-mode identity verification (Ed25519 + OAuth)."""
from __future__ import annotations

import os
import shutil
import uuid
from datetime import UTC, datetime
from unittest.mock import MagicMock

import pytest

from airlock.config import _reset_config, get_config
from airlock.crypto import KeyPair, issue_credential, sign_model
from airlock.engine.orchestrator import VerificationOrchestrator
from airlock.reputation.scoring import THRESHOLD_HIGH
from airlock.reputation.store import ReputationStore
from airlock.schemas import (
    AgentDID,
    HandshakeIntent,
    HandshakeReceived,
    HandshakeRequest,
    TrustScore,
    TrustVerdict,
    create_envelope,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def tmp_db(tmp_path):
    db_dir = str(tmp_path / "reputation.lance")
    yield db_dir
    if os.path.exists(db_dir):
        shutil.rmtree(db_dir, ignore_errors=True)


@pytest.fixture
def reputation_store(tmp_db):
    store = ReputationStore(db_path=tmp_db)
    store.open()
    yield store
    store.close()


@pytest.fixture
def airlock_keypair():
    return KeyPair.from_seed(b"airlock_test_key_seed_00000000_x")


@pytest.fixture
def agent_keypair():
    return KeyPair.from_seed(b"agent__test_key_seed_00000000_xx")


@pytest.fixture
def issuer_keypair():
    return KeyPair.from_seed(b"issuer_test_key_seed_00000000_xx")


@pytest.fixture
def target_keypair():
    return KeyPair.from_seed(b"target_test_key_seed_00000000_xx")


def _make_handshake(
    agent_kp: KeyPair,
    issuer_kp: KeyPair,
    target_did: str,
    session_id: str | None = None,
    sign: bool = True,
) -> HandshakeRequest:
    vc = issue_credential(
        issuer_key=issuer_kp,
        subject_did=agent_kp.did,
        credential_type="AgentAuthorization",
        claims={"role": "agent", "scope": "test"},
        validity_days=365,
    )
    envelope = create_envelope(sender_did=agent_kp.did)
    request = HandshakeRequest(
        envelope=envelope,
        session_id=session_id or str(uuid.uuid4()),
        initiator=AgentDID(did=agent_kp.did, public_key_multibase=agent_kp.public_key_multibase),
        intent=HandshakeIntent(
            action="connect",
            description="Dual-mode auth test",
            target_did=target_did,
        ),
        credential=vc,
        signature=None,
    )
    if sign:
        request.signature = sign_model(request, agent_kp.signing_key)
    return request


def _make_orchestrator(
    reputation_store: ReputationStore,
    airlock_kp: KeyPair,
    on_verdict=None,
    on_seal=None,
) -> VerificationOrchestrator:
    return VerificationOrchestrator(
        reputation_store=reputation_store,
        agent_registry={},
        airlock_did=airlock_kp.did,
        litellm_model="ollama/llama3",
        litellm_api_base=None,
        on_verdict=on_verdict,
        on_seal=on_seal,
        airlock_keypair=airlock_kp,
    )


def _seed_high_score(reputation_store: ReputationStore, did: str) -> None:
    now = datetime.now(UTC)
    reputation_store.upsert(
        TrustScore(
            agent_did=did,
            score=THRESHOLD_HIGH + 0.05,
            interaction_count=10,
            successful_verifications=10,
            failed_verifications=0,
            last_interaction=now,
            decay_rate=0.02,
            created_at=now,
            updated_at=now,
        )
    )


# ===========================================================================
# 1. Ed25519 verification still works (backward compat)
# ===========================================================================


@pytest.mark.asyncio
async def test_ed25519_still_works(
    reputation_store, airlock_keypair, agent_keypair, issuer_keypair, target_keypair
):
    """Ed25519 signature verification continues to work after rename."""
    _seed_high_score(reputation_store, agent_keypair.did)

    verdicts: list[TrustVerdict] = []

    async def on_verdict(sid, verdict, attestation):
        verdicts.append(verdict)

    orchestrator = _make_orchestrator(reputation_store, airlock_keypair, on_verdict=on_verdict)

    session_id = str(uuid.uuid4())
    request = _make_handshake(agent_keypair, issuer_keypair, target_keypair.did, session_id)
    event = HandshakeReceived(
        session_id=session_id,
        timestamp=datetime.now(UTC),
        request=request,
        callback_url=None,
    )

    await orchestrator.handle_event(event)

    assert len(verdicts) == 1
    assert verdicts[0] == TrustVerdict.VERIFIED


# ===========================================================================
# 2. Challenge disabled routes to issue_verdict
# ===========================================================================


@pytest.mark.asyncio
async def test_challenge_disabled_routes_to_verdict(
    reputation_store, airlock_keypair, agent_keypair, issuer_keypair, target_keypair
):
    """When challenge_fallback_mode='disabled', medium-reputation agents skip challenge."""
    _reset_config()
    try:
        verdicts: list[TrustVerdict] = []

        async def on_verdict(sid, verdict, attestation):
            verdicts.append(verdict)

        orchestrator = _make_orchestrator(
            reputation_store, airlock_keypair, on_verdict=on_verdict
        )

        session_id = str(uuid.uuid4())
        request = _make_handshake(agent_keypair, issuer_keypair, target_keypair.did, session_id)
        event = HandshakeReceived(
            session_id=session_id,
            timestamp=datetime.now(UTC),
            request=request,
            callback_url=None,
        )

        await orchestrator.handle_event(event)

        # With disabled challenge, should get verdict (VERIFIED) instead of pending challenge
        assert len(verdicts) == 1
        assert verdicts[0] == TrustVerdict.VERIFIED
    finally:
        _reset_config()


# ===========================================================================
# 3. OAuth import failure -> graceful fallback to Ed25519
# ===========================================================================


@pytest.mark.asyncio
async def test_oauth_import_failure_falls_back_to_ed25519(
    reputation_store, airlock_keypair, agent_keypair, issuer_keypair, target_keypair
):
    """When OAuth module is not installed, bearer token is ignored and Ed25519 works."""
    _seed_high_score(reputation_store, agent_keypair.did)

    verdicts: list[TrustVerdict] = []

    async def on_verdict(sid, verdict, attestation):
        verdicts.append(verdict)

    orchestrator = _make_orchestrator(reputation_store, airlock_keypair, on_verdict=on_verdict)

    session_id = str(uuid.uuid4())
    request = _make_handshake(agent_keypair, issuer_keypair, target_keypair.did, session_id)
    event = HandshakeReceived(
        session_id=session_id,
        timestamp=datetime.now(UTC),
        request=request,
        callback_url=None,
        bearer_token="some-invalid-oauth-token",
    )

    await orchestrator.handle_event(event)

    # OAuth module doesn't exist, so it falls back to Ed25519 which succeeds
    assert len(verdicts) == 1
    assert verdicts[0] == TrustVerdict.VERIFIED


# ===========================================================================
# 4. Config default changed from "ambiguous" to "disabled"
# ===========================================================================


def test_config_default_challenge_mode_is_disabled():
    """Verify that the default challenge_fallback_mode is now 'disabled'."""
    _reset_config()
    try:
        cfg = get_config()
        assert cfg.challenge_fallback_mode == "disabled"
    finally:
        _reset_config()


# ===========================================================================
# 5. Bearer token field on HandshakeReceived event
# ===========================================================================


def test_handshake_received_bearer_token_field(agent_keypair, issuer_keypair, target_keypair):
    """HandshakeReceived event should accept an optional bearer_token."""
    hs = _make_handshake(agent_keypair, issuer_keypair, target_keypair.did)

    event = HandshakeReceived(
        session_id="test-session",
        timestamp=datetime.now(UTC),
        request=hs,
        callback_url=None,
        bearer_token="test-token",
    )
    assert event.bearer_token == "test-token"

    event_no_token = HandshakeReceived(
        session_id="test-session",
        timestamp=datetime.now(UTC),
        request=hs,
        callback_url=None,
    )
    assert event_no_token.bearer_token is None


# ===========================================================================
# 6. Bearer token extraction helper
# ===========================================================================


def test_extract_bearer_token():
    """_extract_bearer_token should parse Authorization: Bearer header."""
    from airlock.gateway.handlers import _extract_bearer_token

    mock_request = MagicMock()

    # Valid bearer token
    mock_request.headers.get.return_value = "Bearer my-token-123"
    assert _extract_bearer_token(mock_request) == "my-token-123"

    # No auth header
    mock_request.headers.get.return_value = ""
    assert _extract_bearer_token(mock_request) is None

    # Basic auth (not bearer)
    mock_request.headers.get.return_value = "Basic dXNlcjpwYXNz"
    assert _extract_bearer_token(mock_request) is None

    # Case insensitive
    mock_request.headers.get.return_value = "BEARER token-456"
    assert _extract_bearer_token(mock_request) == "token-456"


# ===========================================================================
# 7. Ed25519 rejection still works after rename
# ===========================================================================


@pytest.mark.asyncio
async def test_unsigned_request_rejected(
    reputation_store, airlock_keypair, agent_keypair, issuer_keypair, target_keypair
):
    """An unsigned handshake should be rejected at identity verification."""
    _seed_high_score(reputation_store, agent_keypair.did)

    verdicts: list[TrustVerdict] = []

    async def on_verdict(sid, verdict, attestation):
        verdicts.append(verdict)

    orchestrator = _make_orchestrator(reputation_store, airlock_keypair, on_verdict=on_verdict)

    session_id = str(uuid.uuid4())
    # Create unsigned request
    request = _make_handshake(
        agent_keypair, issuer_keypair, target_keypair.did, session_id, sign=False
    )
    event = HandshakeReceived(
        session_id=session_id,
        timestamp=datetime.now(UTC),
        request=request,
        callback_url=None,
    )

    await orchestrator.handle_event(event)

    assert len(verdicts) == 1
    assert verdicts[0] == TrustVerdict.REJECTED
