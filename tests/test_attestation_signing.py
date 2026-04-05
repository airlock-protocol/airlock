"""Tests for attestation signing (H-08): gateway signs AirlockAttestation with Ed25519."""

from __future__ import annotations

import os
import shutil
import uuid
from datetime import UTC, datetime

import pytest

from airlock.crypto import KeyPair, issue_credential, sign_model
from airlock.crypto.signing import sign_attestation, verify_attestation
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
from airlock.schemas.verdict import AirlockAttestation, CheckResult, VerificationCheck

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def tmp_db(tmp_path):
    db_dir = str(tmp_path / "attsig_rep.lance")
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
    return KeyPair.from_seed(b"airlock_attsig_seed_000000000000")


@pytest.fixture
def agent_keypair():
    return KeyPair.from_seed(b"agent___attsig_seed_000000000000")


@pytest.fixture
def issuer_keypair():
    return KeyPair.from_seed(b"issuer__attsig_seed_000000000000")


@pytest.fixture
def target_keypair():
    return KeyPair.from_seed(b"target__attsig_seed_000000000000")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_handshake(
    agent_kp: KeyPair,
    issuer_kp: KeyPair,
    target_did: str,
    session_id: str | None = None,
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
            description="Attestation signing test",
            target_did=target_did,
        ),
        credential=vc,
        signature=None,
    )
    request.signature = sign_model(request, agent_kp.signing_key)
    return request


def _make_orchestrator(
    reputation_store: ReputationStore,
    airlock_kp: KeyPair,
    on_verdict=None,
) -> VerificationOrchestrator:
    return VerificationOrchestrator(
        reputation_store=reputation_store,
        agent_registry={},
        airlock_did=airlock_kp.did,
        litellm_model="ollama/llama3",
        litellm_api_base=None,
        on_verdict=on_verdict,
        airlock_keypair=airlock_kp,
    )


def _seed_high_score(reputation_store: ReputationStore, agent_did: str) -> None:
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
# 1. test_attestation_has_signature
# ===========================================================================


@pytest.mark.asyncio
async def test_attestation_has_signature(
    reputation_store, airlock_keypair, agent_keypair, issuer_keypair, target_keypair
):
    """After a full fast-path verification flow, airlock_signature is populated."""
    _seed_high_score(reputation_store, agent_keypair.did)

    captured: list[AirlockAttestation] = []

    async def on_verdict(sid: str, verdict: TrustVerdict, att: AirlockAttestation) -> None:
        captured.append(att)

    orch = _make_orchestrator(reputation_store, airlock_keypair, on_verdict=on_verdict)

    hs = _make_handshake(agent_keypair, issuer_keypair, target_keypair.did)
    event = HandshakeReceived(
        session_id=hs.session_id,
        timestamp=datetime.now(UTC),
        request=hs,
    )
    await orch.handle_event(event)

    assert len(captured) == 1
    attestation = captured[0]
    assert attestation.airlock_signature is not None
    assert isinstance(attestation.airlock_signature, str)
    assert len(attestation.airlock_signature) > 0


# ===========================================================================
# 2. test_attestation_signature_verifiable
# ===========================================================================


@pytest.mark.asyncio
async def test_attestation_signature_verifiable(
    reputation_store, airlock_keypair, agent_keypair, issuer_keypair, target_keypair
):
    """The signature on the attestation verifies against the gateway public key."""
    _seed_high_score(reputation_store, agent_keypair.did)

    captured: list[AirlockAttestation] = []

    async def on_verdict(sid: str, verdict: TrustVerdict, att: AirlockAttestation) -> None:
        captured.append(att)

    orch = _make_orchestrator(reputation_store, airlock_keypair, on_verdict=on_verdict)

    hs = _make_handshake(agent_keypair, issuer_keypair, target_keypair.did)
    event = HandshakeReceived(
        session_id=hs.session_id,
        timestamp=datetime.now(UTC),
        request=hs,
    )
    await orch.handle_event(event)

    attestation = captured[0]
    assert verify_attestation(attestation, airlock_keypair.verify_key)


# ===========================================================================
# 3. test_tampered_attestation_rejected
# ===========================================================================


@pytest.mark.asyncio
async def test_tampered_attestation_rejected(
    reputation_store, airlock_keypair, agent_keypair, issuer_keypair, target_keypair
):
    """Modifying a field after signing causes verification to fail."""
    _seed_high_score(reputation_store, agent_keypair.did)

    captured: list[AirlockAttestation] = []

    async def on_verdict(sid: str, verdict: TrustVerdict, att: AirlockAttestation) -> None:
        captured.append(att)

    orch = _make_orchestrator(reputation_store, airlock_keypair, on_verdict=on_verdict)

    hs = _make_handshake(agent_keypair, issuer_keypair, target_keypair.did)
    event = HandshakeReceived(
        session_id=hs.session_id,
        timestamp=datetime.now(UTC),
        request=hs,
    )
    await orch.handle_event(event)

    attestation = captured[0]
    # Tamper with the trust_score
    tampered = attestation.model_copy(update={"trust_score": 0.0})
    assert not verify_attestation(tampered, airlock_keypair.verify_key)


# ===========================================================================
# 4. test_attestation_json_roundtrip_preserves_signature
# ===========================================================================


@pytest.mark.asyncio
async def test_attestation_json_roundtrip_preserves_signature(
    reputation_store, airlock_keypair, agent_keypair, issuer_keypair, target_keypair
):
    """Serialize to JSON and back -- signature still verifies."""
    _seed_high_score(reputation_store, agent_keypair.did)

    captured: list[AirlockAttestation] = []

    async def on_verdict(sid: str, verdict: TrustVerdict, att: AirlockAttestation) -> None:
        captured.append(att)

    orch = _make_orchestrator(reputation_store, airlock_keypair, on_verdict=on_verdict)

    hs = _make_handshake(agent_keypair, issuer_keypair, target_keypair.did)
    event = HandshakeReceived(
        session_id=hs.session_id,
        timestamp=datetime.now(UTC),
        request=hs,
    )
    await orch.handle_event(event)

    attestation = captured[0]
    json_str = attestation.model_dump_json()
    restored = AirlockAttestation.model_validate_json(json_str)
    assert restored.airlock_signature == attestation.airlock_signature
    assert verify_attestation(restored, airlock_keypair.verify_key)


# ===========================================================================
# 5. test_attestation_without_signature_backward_compat
# ===========================================================================


def test_attestation_without_signature_backward_compat():
    """Old attestations without airlock_signature still parse and default to None."""
    attestation = AirlockAttestation(
        session_id="legacy-session",
        verified_did="did:key:z6Mklegacy",
        checks_passed=[
            CheckResult(check=VerificationCheck.SCHEMA, passed=True, detail="ok"),
        ],
        trust_score=0.75,
        verdict=TrustVerdict.VERIFIED,
        issued_at=datetime.now(UTC),
    )
    assert attestation.airlock_signature is None
    # verify_attestation returns False for unsigned attestations (not an error)
    assert not verify_attestation(attestation, KeyPair.generate().verify_key)


# ===========================================================================
# 6. test_verify_attestation_wrong_key_fails
# ===========================================================================


def test_verify_attestation_wrong_key_fails():
    """Signature produced by one gateway key is rejected by a different key."""
    gateway_kp = KeyPair.from_seed(b"gw__attsig_wrong_key_00000000000")
    wrong_kp = KeyPair.from_seed(b"bad_attsig_wrong_key_00000000000")

    attestation = AirlockAttestation(
        session_id="wrong-key-session",
        verified_did="did:key:z6Mkwrong",
        checks_passed=[
            CheckResult(check=VerificationCheck.SCHEMA, passed=True, detail="ok"),
        ],
        trust_score=0.5,
        verdict=TrustVerdict.REJECTED,
        issued_at=datetime.now(UTC),
    )
    sig = sign_attestation(attestation, gateway_kp.signing_key)
    signed = attestation.model_copy(update={"airlock_signature": sig})

    # Correct key verifies
    assert verify_attestation(signed, gateway_kp.verify_key)
    # Wrong key fails
    assert not verify_attestation(signed, wrong_kp.verify_key)


# ===========================================================================
# 7. test_verify_attestation_raw_bytes_key (bonus: raw bytes API)
# ===========================================================================


def test_verify_attestation_raw_bytes_key():
    """verify_attestation accepts raw 32-byte public key in addition to VerifyKey."""
    kp = KeyPair.from_seed(b"raw__attsig_bytes_key_0000000000")

    attestation = AirlockAttestation(
        session_id="bytes-key-session",
        verified_did="did:key:z6Mkbytes",
        checks_passed=[],
        trust_score=0.6,
        verdict=TrustVerdict.VERIFIED,
        issued_at=datetime.now(UTC),
    )
    sig = sign_attestation(attestation, kp.signing_key)
    signed = attestation.model_copy(update={"airlock_signature": sig})

    raw_bytes = bytes(kp.verify_key)
    assert verify_attestation(signed, raw_bytes)
