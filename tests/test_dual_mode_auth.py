"""Tests for dual-mode authentication (Ed25519 + OAuth bearer token).

Covers:
  1. Standard Ed25519 verification still works (backward compatibility)
  2. Challenge disabled by default - routing skips semantic_challenge
  3. OAuth module not installed - graceful fallback to Ed25519
  4. Mock OAuth token validation - dual-mode path works
  5. Bearer token extraction helper
"""

from __future__ import annotations

import os
import shutil
import uuid
from datetime import UTC, datetime
from unittest.mock import MagicMock, patch

import pytest

from airlock.config import AirlockConfig
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
def tmp_db(tmp_path: object) -> str:
    db_dir = str(tmp_path / "reputation.lance")  # type: ignore[operator]
    yield db_dir  # type: ignore[misc]
    if os.path.exists(db_dir):
        shutil.rmtree(db_dir, ignore_errors=True)


@pytest.fixture
def reputation_store(tmp_db: str) -> ReputationStore:
    store = ReputationStore(db_path=tmp_db)
    store.open()
    yield store  # type: ignore[misc]
    store.close()


@pytest.fixture
def airlock_keypair() -> KeyPair:
    return KeyPair.from_seed(b"airlock_test_key_seed_00000000_x")


@pytest.fixture
def agent_keypair() -> KeyPair:
    return KeyPair.from_seed(b"agent__test_key_seed_00000000_xx")


@pytest.fixture
def issuer_keypair() -> KeyPair:
    return KeyPair.from_seed(b"issuer_test_key_seed_00000000_xx")


@pytest.fixture
def target_keypair() -> KeyPair:
    return KeyPair.from_seed(b"target_test_key_seed_00000000_xx")


def _make_handshake(
    agent_kp: KeyPair,
    issuer_kp: KeyPair,
    target_did: str,
    session_id: str | None = None,
    sign: bool = True,
) -> HandshakeRequest:
    """Build a signed HandshakeRequest with a valid VC."""
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
    on_challenge: object = None,
    on_verdict: object = None,
    on_seal: object = None,
) -> VerificationOrchestrator:
    return VerificationOrchestrator(
        reputation_store=reputation_store,
        agent_registry={},
        airlock_did=airlock_kp.did,
        litellm_model="ollama/llama3",
        litellm_api_base=None,
        on_challenge=on_challenge,
        on_verdict=on_verdict,
        on_seal=on_seal,
        airlock_keypair=airlock_kp,
    )


def _seed_high_score(reputation_store: ReputationStore, agent_did: str) -> None:
    """Seed a high trust score so the agent hits the fast-path."""
    now = datetime.now(UTC)
    reputation_store.upsert(
        TrustScore(
            agent_did=agent_did,
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
# 1. Ed25519 backward compatibility (standard path still works)
# ===========================================================================


@pytest.mark.asyncio
async def test_ed25519_still_works(
    reputation_store: ReputationStore,
    airlock_keypair: KeyPair,
    agent_keypair: KeyPair,
    issuer_keypair: KeyPair,
    target_keypair: KeyPair,
) -> None:
    """Standard Ed25519 verification continues to work with the renamed node."""
    _seed_high_score(reputation_store, agent_keypair.did)

    verdicts: list[TrustVerdict] = []

    async def on_verdict(sid: str, verdict: TrustVerdict, attestation: object) -> None:
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
# 2. Challenge disabled by default - routes to issue_verdict
# ===========================================================================


@pytest.mark.asyncio
async def test_challenge_disabled_skips_semantic_challenge(
    reputation_store: ReputationStore,
    airlock_keypair: KeyPair,
    agent_keypair: KeyPair,
    issuer_keypair: KeyPair,
    target_keypair: KeyPair,
) -> None:
    """When challenge_fallback_mode='disabled', unknown-reputation agents
    skip the semantic challenge and go straight to verdict."""
    challenges_issued: list[object] = []
    verdicts: list[TrustVerdict] = []

    async def on_challenge(sid: str, challenge: object) -> None:
        challenges_issued.append(challenge)

    async def on_verdict(sid: str, verdict: TrustVerdict, attestation: object) -> None:
        verdicts.append(verdict)

    orchestrator = _make_orchestrator(
        reputation_store,
        airlock_keypair,
        on_challenge=on_challenge,
        on_verdict=on_verdict,
    )

    session_id = str(uuid.uuid4())
    request = _make_handshake(agent_keypair, issuer_keypair, target_keypair.did, session_id)
    event = HandshakeReceived(
        session_id=session_id,
        timestamp=datetime.now(UTC),
        request=request,
        callback_url=None,
    )

    # Default config has challenge_fallback_mode="disabled"
    await orchestrator.handle_event(event)

    # No challenge should be issued
    assert len(challenges_issued) == 0
    # A verdict should be issued directly
    assert len(verdicts) == 1
    assert verdicts[0] == TrustVerdict.VERIFIED


# ===========================================================================
# 3. OAuth module not installed - graceful fallback to Ed25519
# ===========================================================================


@pytest.mark.asyncio
async def test_oauth_import_error_falls_back_to_ed25519(
    reputation_store: ReputationStore,
    airlock_keypair: KeyPair,
    agent_keypair: KeyPair,
    issuer_keypair: KeyPair,
    target_keypair: KeyPair,
) -> None:
    """When OAuth module is not installed, the node gracefully falls back
    to Ed25519 signature verification."""
    _seed_high_score(reputation_store, agent_keypair.did)

    verdicts: list[TrustVerdict] = []

    async def on_verdict(sid: str, verdict: TrustVerdict, attestation: object) -> None:
        verdicts.append(verdict)

    orchestrator = _make_orchestrator(reputation_store, airlock_keypair, on_verdict=on_verdict)

    session_id = str(uuid.uuid4())
    request = _make_handshake(agent_keypair, issuer_keypair, target_keypair.did, session_id)
    event = HandshakeReceived(
        session_id=session_id,
        timestamp=datetime.now(UTC),
        request=request,
        callback_url=None,
        bearer_token="some.fake.jwt.token",
    )

    await orchestrator.handle_event(event)

    # Should still succeed via Ed25519 fallback
    assert len(verdicts) == 1
    assert verdicts[0] == TrustVerdict.VERIFIED


# ===========================================================================
# 4. Mock OAuth token validation - dual-mode path works
# ===========================================================================


@pytest.mark.asyncio
async def test_oauth_bearer_token_validates(
    reputation_store: ReputationStore,
    airlock_keypair: KeyPair,
    agent_keypair: KeyPair,
    issuer_keypair: KeyPair,
    target_keypair: KeyPair,
) -> None:
    """When a valid OAuth bearer token is present and the subject matches,
    identity is verified via OAuth without needing Ed25519 signature."""
    _seed_high_score(reputation_store, agent_keypair.did)

    verdicts: list[TrustVerdict] = []
    seals: list[object] = []

    async def on_verdict(sid: str, verdict: TrustVerdict, attestation: object) -> None:
        verdicts.append(verdict)

    async def on_seal(sid: str, seal: object) -> None:
        seals.append(seal)

    orchestrator = _make_orchestrator(
        reputation_store, airlock_keypair, on_verdict=on_verdict, on_seal=on_seal
    )

    session_id = str(uuid.uuid4())
    # Build request WITHOUT a signature to prove OAuth path works alone
    request = _make_handshake(
        agent_keypair, issuer_keypair, target_keypair.did, session_id, sign=False
    )
    event = HandshakeReceived(
        session_id=session_id,
        timestamp=datetime.now(UTC),
        request=request,
        callback_url=None,
        bearer_token="valid.oauth.token",
    )

    # Mock the OAuth module so it validates successfully
    mock_validator = MagicMock()
    mock_validator.validate_access_token.return_value = {"sub": agent_keypair.did}

    with patch.dict(
        "sys.modules",
        {"airlock.oauth": MagicMock(), "airlock.oauth.token_validator": mock_validator},
    ):
        await orchestrator.handle_event(event)

    assert len(verdicts) == 1
    assert verdicts[0] == TrustVerdict.VERIFIED
    assert len(seals) == 1


# ===========================================================================
# 5. OAuth token subject mismatch falls back to Ed25519
# ===========================================================================


@pytest.mark.asyncio
async def test_oauth_subject_mismatch_falls_back(
    reputation_store: ReputationStore,
    airlock_keypair: KeyPair,
    agent_keypair: KeyPair,
    issuer_keypair: KeyPair,
    target_keypair: KeyPair,
) -> None:
    """If OAuth token subject does not match initiator DID, falls back to Ed25519."""
    _seed_high_score(reputation_store, agent_keypair.did)

    verdicts: list[TrustVerdict] = []

    async def on_verdict(sid: str, verdict: TrustVerdict, attestation: object) -> None:
        verdicts.append(verdict)

    orchestrator = _make_orchestrator(reputation_store, airlock_keypair, on_verdict=on_verdict)

    session_id = str(uuid.uuid4())
    request = _make_handshake(agent_keypair, issuer_keypair, target_keypair.did, session_id)
    event = HandshakeReceived(
        session_id=session_id,
        timestamp=datetime.now(UTC),
        request=request,
        callback_url=None,
        bearer_token="valid.oauth.token",
    )

    # Mock OAuth module but return wrong subject
    mock_validator = MagicMock()
    mock_validator.validate_access_token.return_value = {"sub": "did:key:zWrongDID"}

    with patch.dict(
        "sys.modules",
        {"airlock.oauth": MagicMock(), "airlock.oauth.token_validator": mock_validator},
    ):
        await orchestrator.handle_event(event)

    # Should still succeed via Ed25519 fallback (request is signed)
    assert len(verdicts) == 1
    assert verdicts[0] == TrustVerdict.VERIFIED


# ===========================================================================
# 6. Bearer token extraction helper
# ===========================================================================


def test_extract_bearer_token_present() -> None:
    """_extract_bearer_token correctly extracts token from Authorization header."""
    from airlock.gateway.handlers import _extract_bearer_token

    mock_request = MagicMock()
    mock_request.headers = {"authorization": "Bearer my-secret-token"}
    assert _extract_bearer_token(mock_request) == "my-secret-token"


def test_extract_bearer_token_absent() -> None:
    """_extract_bearer_token returns None when no Authorization header."""
    from airlock.gateway.handlers import _extract_bearer_token

    mock_request = MagicMock()
    mock_request.headers = {}
    assert _extract_bearer_token(mock_request) is None


def test_extract_bearer_token_not_bearer() -> None:
    """_extract_bearer_token returns None for non-Bearer auth schemes."""
    from airlock.gateway.handlers import _extract_bearer_token

    mock_request = MagicMock()
    mock_request.headers = {"authorization": "Basic dXNlcjpwYXNz"}
    assert _extract_bearer_token(mock_request) is None


def test_extract_bearer_token_case_insensitive() -> None:
    """_extract_bearer_token handles case-insensitive 'bearer' prefix."""
    from airlock.gateway.handlers import _extract_bearer_token

    mock_request = MagicMock()
    mock_request.headers = {"authorization": "BEARER upper-case-token"}
    assert _extract_bearer_token(mock_request) == "upper-case-token"


# ===========================================================================
# 7. Challenge fallback mode override
# ===========================================================================


@pytest.mark.asyncio
async def test_challenge_enabled_routes_to_challenge(
    reputation_store: ReputationStore,
    airlock_keypair: KeyPair,
    agent_keypair: KeyPair,
    issuer_keypair: KeyPair,
    target_keypair: KeyPair,
) -> None:
    """When challenge_fallback_mode is explicitly set to 'ambiguous',
    unknown-reputation agents are routed to semantic challenge."""
    challenges_issued: list[object] = []
    verdicts: list[TrustVerdict] = []

    async def on_challenge(sid: str, challenge: object) -> None:
        challenges_issued.append(challenge)

    async def on_verdict(sid: str, verdict: TrustVerdict, attestation: object) -> None:
        verdicts.append(verdict)

    orchestrator = _make_orchestrator(
        reputation_store,
        airlock_keypair,
        on_challenge=on_challenge,
        on_verdict=on_verdict,
    )

    session_id = str(uuid.uuid4())
    request = _make_handshake(agent_keypair, issuer_keypair, target_keypair.did, session_id)
    event = HandshakeReceived(
        session_id=session_id,
        timestamp=datetime.now(UTC),
        request=request,
        callback_url=None,
    )

    # Override config to re-enable challenge
    with patch("airlock.engine.orchestrator.get_config") as mock_cfg:
        cfg = AirlockConfig(challenge_fallback_mode="ambiguous")
        mock_cfg.return_value = cfg
        # Also patch generate_challenge to avoid actual LLM call
        with patch("airlock.engine.orchestrator.generate_challenge") as mock_gen:
            from airlock.schemas.challenge import ChallengeRequest as ChalReq
            from airlock.schemas.envelope import create_envelope as mk_env

            mock_gen.return_value = ChalReq(
                envelope=mk_env(sender_did=airlock_keypair.did),
                session_id=session_id,
                challenge_id=str(uuid.uuid4()),
                challenge_type="semantic",
                question="Test challenge question",
                context="Test context for dual-mode auth",
                expires_at=datetime.now(UTC),
            )
            await orchestrator.handle_event(event)

    # Challenge should be issued, no verdict yet
    assert len(challenges_issued) == 1
    assert len(verdicts) == 0
