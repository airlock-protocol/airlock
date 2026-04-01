from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from airlock.schemas import (
    AgentCapability,
    AgentDID,
    AgentProfile,
    ChallengeIssued,
    ChallengeRequest,
    ChallengeResponse,
    ChallengeResponseReceived,
    CheckResult,
    CredentialValidated,
    HandshakeIntent,
    HandshakeReceived,
    HandshakeRequest,
    ResolveRequested,
    SessionSeal,
    SessionSealed,
    SignatureVerified,
    TransportAck,
    TransportNack,
    TrustScore,
    TrustVerdict,
    VerdictReady,
    VerifiableCredential,
    VerificationCheck,
    VerificationFailed,
    VerificationSession,
    VerificationState,
    create_envelope,
    generate_nonce,
)


def _make_vc(expiration_date: datetime) -> VerifiableCredential:
    return VerifiableCredential(
        id="urn:uuid:test",
        type=["Credential", "AgentAuthorization"],
        issuer="did:key:z6MkIssuer",
        issuance_date=datetime.now(UTC) - timedelta(days=1),
        expiration_date=expiration_date,
        credential_subject={},
    )


def _make_handshake_request() -> HandshakeRequest:
    envelope = create_envelope("did:key:z6MkTest123")
    initiator = AgentDID(did="did:key:z6MkTest123", public_key_multibase="z6MkTest123")
    intent = HandshakeIntent(action="connect", description="test", target_did="did:key:z6MkOther")
    credential = _make_vc(datetime.now(UTC) + timedelta(days=1))
    return HandshakeRequest(
        envelope=envelope,
        session_id="s1",
        initiator=initiator,
        intent=intent,
        credential=credential,
    )


def _make_challenge_request() -> ChallengeRequest:
    envelope = create_envelope("did:key:z6MkTest123")
    return ChallengeRequest(
        envelope=envelope,
        session_id="s1",
        challenge_id="c1",
        challenge_type="semantic",
        question="What is 2+2?",
        context="math",
        expires_at=datetime.now(UTC) + timedelta(minutes=5),
    )


def _make_challenge_response() -> ChallengeResponse:
    envelope = create_envelope("did:key:z6MkTest123")
    return ChallengeResponse(
        envelope=envelope, session_id="s1", challenge_id="c1", answer="4", confidence=0.9
    )


def test_message_envelope_creation() -> None:
    env = create_envelope("did:key:z6MkTest123")
    assert env.sender_did == "did:key:z6MkTest123"
    assert env.protocol_version == "0.1.0"
    assert len(env.nonce) == 32
    assert env.timestamp.tzinfo is not None


def test_generate_nonce_uniqueness() -> None:
    assert generate_nonce() != generate_nonce()


def test_generate_nonce_length() -> None:
    nonce = generate_nonce()
    assert len(nonce) == 32
    assert all(c in "0123456789abcdef" for c in nonce)


def test_transport_ack_creation() -> None:
    envelope = create_envelope("did:key:z6MkTest123")
    ack = TransportAck(
        status="ACCEPTED", session_id="s1", timestamp=datetime.now(UTC), envelope=envelope
    )
    assert ack.status == "ACCEPTED"
    assert ack.session_id == "s1"


def test_transport_nack_creation() -> None:
    envelope = create_envelope("did:key:z6MkTest123")
    nack = TransportNack(
        status="REJECTED",
        reason="Invalid",
        error_code="E001",
        timestamp=datetime.now(UTC),
        envelope=envelope,
    )
    assert nack.reason == "Invalid"
    assert nack.error_code == "E001"


def test_agent_did_valid() -> None:
    did = AgentDID(did="did:key:z6MkTest123", public_key_multibase="z6MkTest123")
    assert did.did == "did:key:z6MkTest123"


def test_agent_did_invalid_method() -> None:
    with pytest.raises(ValidationError):
        AgentDID(did="did:web:example.com", public_key_multibase="z6MkTest123")


def test_agent_profile_creation() -> None:
    did = AgentDID(did="did:key:z6MkTest123", public_key_multibase="z6MkTest123")
    cap = AgentCapability(name="test", version="1.0", description="Test capability")
    profile = AgentProfile(
        did=did,
        display_name="Test Agent",
        capabilities=[cap],
        endpoint_url="https://example.com",
        protocol_versions=["0.1.0"],
        status="active",
        registered_at=datetime.now(UTC),
    )
    assert profile.display_name == "Test Agent"
    assert len(profile.capabilities) == 1


def test_verifiable_credential_not_expired() -> None:
    vc = _make_vc(datetime.now(UTC) + timedelta(days=1))
    assert vc.is_expired() is False


def test_verifiable_credential_expired() -> None:
    vc = _make_vc(datetime.now(UTC) - timedelta(days=1))
    assert vc.is_expired() is True


def test_trust_verdict_values() -> None:
    assert TrustVerdict.VERIFIED.value == "VERIFIED"
    assert TrustVerdict.REJECTED.value == "REJECTED"
    assert TrustVerdict.DEFERRED.value == "DEFERRED"


def test_verification_state_values() -> None:
    states = [
        VerificationState.INITIATED,
        VerificationState.RESOLVING,
        VerificationState.RESOLVED,
        VerificationState.HANDSHAKE_RECEIVED,
        VerificationState.SIGNATURE_VERIFIED,
        VerificationState.CREDENTIAL_VALIDATED,
        VerificationState.CHALLENGE_ISSUED,
        VerificationState.CHALLENGE_RESPONDED,
        VerificationState.VERDICT_ISSUED,
        VerificationState.SEALED,
        VerificationState.FAILED,
    ]
    assert len(states) == 11


def test_verification_session_is_expired() -> None:
    now = datetime.now(UTC)
    expired = VerificationSession(
        session_id="s1",
        state=VerificationState.INITIATED,
        initiator_did="did:key:z6Mk1",
        target_did="did:key:z6Mk2",
        created_at=now - timedelta(seconds=1),
        updated_at=now,
        ttl_seconds=0,
    )
    assert expired.is_expired() is True
    not_expired = VerificationSession(
        session_id="s2",
        state=VerificationState.INITIATED,
        initiator_did="did:key:z6Mk1",
        target_did="did:key:z6Mk2",
        created_at=now,
        updated_at=now,
        ttl_seconds=999999,
    )
    assert not_expired.is_expired() is False


def test_check_result_creation() -> None:
    passed = CheckResult(check=VerificationCheck.SIGNATURE, passed=True)
    failed = CheckResult(check=VerificationCheck.CREDENTIAL, passed=False, detail="Invalid")
    assert passed.passed is True
    assert failed.passed is False


def test_handshake_request_creation() -> None:
    req = _make_handshake_request()
    assert req.session_id == "s1"
    assert req.initiator.did == "did:key:z6MkTest123"
    assert req.intent.action == "connect"


def test_challenge_request_creation() -> None:
    req = _make_challenge_request()
    assert req.question == "What is 2+2?"
    assert req.session_id == "s1"
    assert req.expires_at > datetime.now(UTC)


def test_session_seal_creation() -> None:
    envelope = create_envelope("did:key:z6MkTest123")
    checks = [CheckResult(check=VerificationCheck.SIGNATURE, passed=True)]
    seal = SessionSeal(
        envelope=envelope,
        session_id="s1",
        verdict=TrustVerdict.VERIFIED,
        checks_passed=checks,
        trust_score=0.9,
        sealed_at=datetime.now(UTC),
    )
    assert seal.verdict == TrustVerdict.VERIFIED
    assert seal.trust_score == 0.9
    assert len(seal.checks_passed) == 1


def test_trust_score_defaults() -> None:
    now = datetime.now(UTC)
    ts = TrustScore(agent_did="did:key:z6MkTest123", created_at=now, updated_at=now)
    assert ts.score == 0.5
    assert ts.decay_rate == 0.02


def test_trust_score_bounds() -> None:
    now = datetime.now(UTC)
    with pytest.raises(ValidationError):
        TrustScore(agent_did="did:key:z6MkTest123", score=-0.1, created_at=now, updated_at=now)
    with pytest.raises(ValidationError):
        TrustScore(agent_did="did:key:z6MkTest123", score=1.1, created_at=now, updated_at=now)


def test_event_types() -> None:
    now = datetime.now(UTC)
    assert (
        ResolveRequested(session_id="s", timestamp=now, target_did="did:key:z6Mk1").event_type
        == "resolve_requested"
    )
    assert (
        HandshakeReceived(
            session_id="s", timestamp=now, request=_make_handshake_request()
        ).event_type
        == "handshake_received"
    )
    assert SignatureVerified(session_id="s", timestamp=now).event_type == "signature_verified"
    assert CredentialValidated(session_id="s", timestamp=now).event_type == "credential_validated"
    assert (
        ChallengeIssued(
            session_id="s", timestamp=now, challenge=_make_challenge_request()
        ).event_type
        == "challenge_issued"
    )
    assert (
        ChallengeResponseReceived(
            session_id="s", timestamp=now, response=_make_challenge_response()
        ).event_type
        == "challenge_response_received"
    )
    assert (
        VerdictReady(
            session_id="s", timestamp=now, verdict=TrustVerdict.VERIFIED, trust_score=0.9
        ).event_type
        == "verdict_ready"
    )
    assert SessionSealed(session_id="s", timestamp=now).event_type == "session_sealed"
    assert (
        VerificationFailed(
            session_id="s", timestamp=now, error="err", failed_at="initiated"
        ).event_type
        == "verification_failed"
    )
