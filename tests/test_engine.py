"""Phase 2 integration tests: VerificationOrchestrator + EventBus + SessionManager + Reputation.

Test matrix:
  1. Full VERIFIED path  (valid sig + valid VC + high reputation -> fast-path)
  2. REJECTED at verify_signature  (tampered / missing signature)
  3. REJECTED at validate_vc  (expired VC)
  4. DEFERRED path  (unknown reputation -> semantic challenge -> ambiguous answer)
  5. Reputation updates after VERIFIED and REJECTED outcomes
  6. EventBus publish/consume roundtrip
  7. SessionManager TTL expiry
  8. Scoring: half-life decay + diminishing returns
"""

from __future__ import annotations

import asyncio
import os
import shutil
import uuid
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, patch

import pytest

from airlock.crypto import KeyPair, issue_credential, sign_model
from airlock.engine.event_bus import EventBus
from airlock.engine.orchestrator import VerificationOrchestrator
from airlock.engine.state import SessionManager
from airlock.reputation.scoring import (
    INITIAL_SCORE,
    THRESHOLD_HIGH,
    apply_half_life_decay,
    compute_delta,
    routing_decision,
    update_score,
)
from airlock.reputation.store import ReputationStore
from airlock.schemas import (
    AgentDID,
    ChallengeResponse,
    ChallengeResponseReceived,
    HandshakeIntent,
    HandshakeReceived,
    HandshakeRequest,
    TrustScore,
    TrustVerdict,
    VerificationState,
    create_envelope,
)
from airlock.semantic.challenge import ChallengeOutcome

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def tmp_db(tmp_path):
    """Temporary LanceDB path, cleaned up after each test."""
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
    validity_days: int = 365,
    sign: bool = True,
) -> HandshakeRequest:
    """Build a signed HandshakeRequest with a valid VC."""
    vc = issue_credential(
        issuer_key=issuer_kp,
        subject_did=agent_kp.did,
        credential_type="AgentAuthorization",
        claims={"role": "agent", "scope": "test"},
        validity_days=validity_days,
    )
    envelope = create_envelope(sender_did=agent_kp.did)
    request = HandshakeRequest(
        envelope=envelope,
        session_id=session_id or str(uuid.uuid4()),
        initiator=AgentDID(did=agent_kp.did, public_key_multibase=agent_kp.public_key_multibase),
        intent=HandshakeIntent(
            action="connect",
            description="Integration test handshake",
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
    registry: dict | None = None,
    on_challenge=None,
    on_verdict=None,
    on_seal=None,
    vc_allowed_issuers: frozenset[str] | None = None,
) -> VerificationOrchestrator:
    return VerificationOrchestrator(
        reputation_store=reputation_store,
        agent_registry=registry or {},
        airlock_did=airlock_kp.did,
        litellm_model="ollama/llama3",
        litellm_api_base=None,
        on_challenge=on_challenge,
        on_verdict=on_verdict,
        on_seal=on_seal,
        vc_allowed_issuers=vc_allowed_issuers,
    )


# ===========================================================================
# 1. Full VERIFIED path (high reputation -> fast-path, no challenge)
# ===========================================================================


@pytest.mark.asyncio
async def test_verified_fast_path(
    reputation_store, airlock_keypair, agent_keypair, issuer_keypair, target_keypair
):
    """An agent with high trust score is verified without a semantic challenge."""
    # Seed a high trust score
    now = datetime.now(UTC)
    high_score = TrustScore(
        agent_did=agent_keypair.did,
        score=THRESHOLD_HIGH + 0.05,
        interaction_count=10,
        successful_verifications=10,
        failed_verifications=0,
        last_interaction=now,
        decay_rate=0.02,
        created_at=now,
        updated_at=now,
    )
    reputation_store.upsert(high_score)

    verdicts: list[TrustVerdict] = []
    seals = []

    async def on_verdict(sid, verdict, attestation):
        verdicts.append(verdict)

    async def on_seal(sid, seal):
        seals.append(seal)

    orchestrator = _make_orchestrator(
        reputation_store, airlock_keypair, on_verdict=on_verdict, on_seal=on_seal
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

    assert len(verdicts) == 1
    assert verdicts[0] == TrustVerdict.VERIFIED
    assert len(seals) == 1
    assert seals[0].verdict == TrustVerdict.VERIFIED


# ===========================================================================
# 1b. VC issuer allowlist
# ===========================================================================


@pytest.mark.asyncio
async def test_vc_issuer_allowlist_rejects_unlisted_issuer(
    reputation_store, airlock_keypair, agent_keypair, issuer_keypair, target_keypair
):
    """When allowlist is set, VC from an unlisted issuer fails credential check."""
    now = datetime.now(UTC)
    reputation_store.upsert(
        TrustScore(
            agent_did=agent_keypair.did,
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

    verdicts: list[TrustVerdict] = []

    async def on_verdict(sid, verdict, attestation):
        verdicts.append(verdict)

    orchestrator = _make_orchestrator(
        reputation_store,
        airlock_keypair,
        on_verdict=on_verdict,
        vc_allowed_issuers=frozenset({"did:key:other_issuer_not_in_vc"}),
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

    assert len(verdicts) == 1
    assert verdicts[0] == TrustVerdict.REJECTED


@pytest.mark.asyncio
async def test_vc_issuer_allowlist_allows_listed_issuer(
    reputation_store, airlock_keypair, agent_keypair, issuer_keypair, target_keypair
):
    """Allowlist containing the real issuer still fast-path verifies."""
    now = datetime.now(UTC)
    reputation_store.upsert(
        TrustScore(
            agent_did=agent_keypair.did,
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

    verdicts: list[TrustVerdict] = []

    async def on_verdict(sid, verdict, attestation):
        verdicts.append(verdict)

    orchestrator = _make_orchestrator(
        reputation_store,
        airlock_keypair,
        on_verdict=on_verdict,
        vc_allowed_issuers=frozenset({issuer_keypair.did}),
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

    assert verdicts == [TrustVerdict.VERIFIED]


# ===========================================================================
# 2. REJECTED at verify_signature (no signature on request)
# ===========================================================================


@pytest.mark.asyncio
async def test_rejected_bad_signature(
    reputation_store, airlock_keypair, agent_keypair, issuer_keypair, target_keypair
):
    """A request with no signature is rejected at the signature verification node."""
    verdicts: list[TrustVerdict] = []

    async def on_verdict(sid, verdict, attestation):
        verdicts.append(verdict)

    orchestrator = _make_orchestrator(reputation_store, airlock_keypair, on_verdict=on_verdict)

    session_id = str(uuid.uuid4())
    # sign=False -> no signature attached
    request = _make_handshake(
        agent_keypair, issuer_keypair, target_keypair.did, session_id, sign=False
    )
    event = HandshakeReceived(
        session_id=session_id,
        timestamp=datetime.now(UTC),
        request=request,
    )

    await orchestrator.handle_event(event)

    assert len(verdicts) == 1
    assert verdicts[0] == TrustVerdict.REJECTED


# ===========================================================================
# 3. REJECTED at validate_vc (expired credential)
# ===========================================================================


@pytest.mark.asyncio
async def test_rejected_expired_vc(
    reputation_store, airlock_keypair, agent_keypair, issuer_keypair, target_keypair
):
    """A request with an expired VC is rejected at the credential validation node."""
    verdicts: list[TrustVerdict] = []

    async def on_verdict(sid, verdict, attestation):
        verdicts.append(verdict)

    orchestrator = _make_orchestrator(reputation_store, airlock_keypair, on_verdict=on_verdict)

    session_id = str(uuid.uuid4())
    # validity_days=-1 -> already expired
    request = _make_handshake(
        agent_keypair, issuer_keypair, target_keypair.did, session_id, validity_days=-1
    )
    event = HandshakeReceived(
        session_id=session_id,
        timestamp=datetime.now(UTC),
        request=request,
    )

    await orchestrator.handle_event(event)

    assert len(verdicts) == 1
    assert verdicts[0] == TrustVerdict.REJECTED


# ===========================================================================
# 4. DEFERRED path: unknown reputation -> challenge -> ambiguous answer
# ===========================================================================


@pytest.mark.asyncio
async def test_deferred_via_semantic_challenge(
    reputation_store, airlock_keypair, agent_keypair, issuer_keypair, target_keypair
):
    """Unknown-reputation agent is routed to semantic challenge; ambiguous answer -> DEFERRED."""
    challenges_issued: list = []
    verdicts: list[TrustVerdict] = []

    async def on_challenge(sid, challenge):
        challenges_issued.append(challenge)

    async def on_verdict(sid, verdict, attestation):
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
    )

    # Patch LLM calls to avoid real network calls
    with patch(
        "airlock.semantic.challenge._generate_question",
        new=AsyncMock(return_value="What is a nonce?"),
    ):
        await orchestrator.handle_event(event)

        # A challenge should have been issued (graph paused)
        assert len(challenges_issued) == 1
        challenge = challenges_issued[0]
        assert challenge.session_id == session_id

        # Simulate agent sending a response; patch evaluation to return AMBIGUOUS
        response_envelope = create_envelope(sender_did=agent_keypair.did)
        response = ChallengeResponse(
            envelope=response_envelope,
            session_id=session_id,
            challenge_id=challenge.challenge_id,
            answer="I think it is some kind of random value maybe.",
            confidence=0.3,
        )
        response_event = ChallengeResponseReceived(
            session_id=session_id,
            timestamp=datetime.now(UTC),
            response=response,
        )
        with patch(
            "airlock.semantic.challenge._evaluate_with_llm",
            new=AsyncMock(return_value=(ChallengeOutcome.AMBIGUOUS, "Answer was unclear")),
        ):
            await orchestrator.handle_event(response_event)

    assert len(verdicts) == 1
    assert verdicts[0] == TrustVerdict.DEFERRED


@pytest.mark.asyncio
async def test_concurrent_challenge_responses_only_one_seals(
    reputation_store, airlock_keypair, agent_keypair, issuer_keypair, target_keypair
):
    """Two simultaneous responses for the same session — only one wins the pending challenge."""
    verdicts: list[TrustVerdict] = []
    challenges_issued: list = []

    async def on_challenge(sid, challenge):
        challenges_issued.append(challenge)

    async def on_verdict(sid, verdict, attestation):
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
    )

    with patch(
        "airlock.semantic.challenge._generate_question",
        new=AsyncMock(return_value="What is a nonce?"),
    ):
        await orchestrator.handle_event(event)

    assert len(challenges_issued) == 1
    challenge = challenges_issued[0]

    response_envelope = create_envelope(sender_did=agent_keypair.did)
    resp = ChallengeResponse(
        envelope=response_envelope,
        session_id=session_id,
        challenge_id=challenge.challenge_id,
        answer="A unique number used once.",
        confidence=0.95,
    )
    ev1 = ChallengeResponseReceived(
        session_id=session_id,
        timestamp=datetime.now(UTC),
        response=resp,
    )
    ev2 = ChallengeResponseReceived(
        session_id=session_id,
        timestamp=datetime.now(UTC),
        response=resp.model_copy(deep=True),
    )

    eval_mock = AsyncMock(return_value=(ChallengeOutcome.PASS, "clear"))
    with patch("airlock.engine.orchestrator.evaluate_response", new=eval_mock):
        await asyncio.gather(
            orchestrator.handle_event(ev1),
            orchestrator.handle_event(ev2),
        )

    assert eval_mock.await_count == 1
    assert len(verdicts) == 1
    assert verdicts[0] == TrustVerdict.VERIFIED


@pytest.mark.asyncio
async def test_stress_many_concurrent_challenge_responses_single_winner(
    reputation_store, airlock_keypair, agent_keypair, issuer_keypair, target_keypair
):
    """Many simultaneous responses for one session — still exactly one evaluation and verdict.

    Target: ~50 concurrent ``handle_event`` calls. That is enough interleaving on a single
    event loop to stress the pending-challenge lock without meaningfully slowing CI; going
    to hundreds adds little for asyncio (no true parallel CPU) and just burns time.
    """
    verdicts: list[TrustVerdict] = []
    challenges_issued: list = []

    async def on_challenge(sid, challenge):
        challenges_issued.append(challenge)

    async def on_verdict(sid, verdict, attestation):
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
    )

    with patch(
        "airlock.semantic.challenge._generate_question",
        new=AsyncMock(return_value="What is a nonce?"),
    ):
        await orchestrator.handle_event(event)

    assert len(challenges_issued) == 1
    challenge = challenges_issued[0]

    response_envelope = create_envelope(sender_did=agent_keypair.did)
    resp = ChallengeResponse(
        envelope=response_envelope,
        session_id=session_id,
        challenge_id=challenge.challenge_id,
        answer="Concurrent stress answer.",
        confidence=0.9,
    )

    n_racers = 50
    events = [
        ChallengeResponseReceived(
            session_id=session_id,
            timestamp=datetime.now(UTC),
            response=resp.model_copy(deep=True),
        )
        for _ in range(n_racers)
    ]

    eval_mock = AsyncMock(return_value=(ChallengeOutcome.PASS, "ok"))
    with patch("airlock.engine.orchestrator.evaluate_response", new=eval_mock):
        await asyncio.gather(*(orchestrator.handle_event(ev) for ev in events))

    assert eval_mock.await_count == 1
    assert len(verdicts) == 1
    assert verdicts[0] == TrustVerdict.VERIFIED


# ===========================================================================
# 5. Reputation updates after VERIFIED and REJECTED
# ===========================================================================


def test_reputation_update_after_verified(reputation_store, agent_keypair):
    """A VERIFIED outcome increases the agent's trust score."""
    initial = reputation_store.get_or_default(agent_keypair.did)
    assert initial.score == INITIAL_SCORE

    updated = reputation_store.apply_verdict(agent_keypair.did, TrustVerdict.VERIFIED)
    assert updated.score > INITIAL_SCORE
    assert updated.interaction_count == 1
    assert updated.successful_verifications == 1

    # Persisted
    persisted = reputation_store.get(agent_keypair.did)
    assert persisted is not None
    assert abs(persisted.score - updated.score) < 1e-6


def test_reputation_update_after_rejected(reputation_store, agent_keypair):
    """A REJECTED outcome decreases the agent's trust score."""
    updated = reputation_store.apply_verdict(agent_keypair.did, TrustVerdict.REJECTED)
    assert updated.score < INITIAL_SCORE
    assert updated.failed_verifications == 1


def test_reputation_multiple_updates(reputation_store, agent_keypair):
    """Repeated VERIFIED outcomes show diminishing returns."""
    scores = []
    for _ in range(5):
        ts = reputation_store.apply_verdict(agent_keypair.did, TrustVerdict.VERIFIED)
        scores.append(ts.score)

    # Each increment should be smaller than the previous
    deltas = [scores[i + 1] - scores[i] for i in range(len(scores) - 1)]
    for i in range(len(deltas) - 1):
        assert deltas[i] >= deltas[i + 1], "Expected diminishing returns"


# ===========================================================================
# 6. EventBus publish/consume roundtrip
# ===========================================================================


@pytest.mark.asyncio
async def test_event_bus_publish_consume():
    """Events published to the bus are delivered to registered handlers."""
    from airlock.schemas import ResolveRequested

    received: list = []

    async def handler(event):
        received.append(event)

    bus = EventBus(maxsize=10)
    bus.register(handler)
    await bus.start()

    event = ResolveRequested(
        session_id=str(uuid.uuid4()),
        timestamp=datetime.now(UTC),
        target_did="did:key:ztarget",
    )
    bus.publish(event)

    # Give the consumer loop a moment to process
    await asyncio.sleep(0.1)
    await bus.stop()

    assert len(received) == 1
    assert received[0].event_type == "resolve_requested"


@pytest.mark.asyncio
async def test_event_bus_queue_full_raises():
    """publish() raises QueueFull when the buffer is at capacity."""
    from airlock.schemas import ResolveRequested

    bus = EventBus(maxsize=1)
    event = ResolveRequested(
        session_id=str(uuid.uuid4()),
        timestamp=datetime.now(UTC),
        target_did="did:key:ztarget",
    )
    bus.publish(event)  # fills the queue
    with pytest.raises(asyncio.QueueFull):
        bus.publish(event)  # should raise


# ===========================================================================
# 7. SessionManager TTL expiry
# ===========================================================================


@pytest.mark.asyncio
async def test_session_manager_create_and_get():
    """Sessions can be created and retrieved."""
    mgr = SessionManager(default_ttl=180)
    session = await mgr.create("did:key:A", "did:key:B")
    assert session.session_id is not None
    assert session.state == VerificationState.INITIATED

    fetched = await mgr.get(session.session_id)
    assert fetched is not None
    assert fetched.session_id == session.session_id


@pytest.mark.asyncio
async def test_session_manager_expired_returns_none():
    """A session past its TTL is evicted and returns None."""
    mgr = SessionManager(default_ttl=0)  # expires immediately
    session = await mgr.create("did:key:A", "did:key:B", ttl=0)

    # Wait a tick so is_expired() returns True
    await asyncio.sleep(0.01)
    fetched = await mgr.get(session.session_id)
    assert fetched is None


@pytest.mark.asyncio
async def test_session_manager_transition():
    """State transitions are persisted."""
    mgr = SessionManager()
    session = await mgr.create("did:key:A", "did:key:B")
    updated = await mgr.transition(session.session_id, VerificationState.SIGNATURE_VERIFIED)
    assert updated is not None
    assert updated.state == VerificationState.SIGNATURE_VERIFIED


# ===========================================================================
# 8. Scoring unit tests: half-life decay + diminishing returns
# ===========================================================================


def test_scoring_initial_score():
    assert INITIAL_SCORE == 0.5


def test_scoring_verified_increases_score():
    now = datetime.now(UTC)
    score = TrustScore(
        agent_did="did:key:test",
        score=0.5,
        interaction_count=0,
        successful_verifications=0,
        failed_verifications=0,
        last_interaction=now,
        decay_rate=0.02,
        created_at=now,
        updated_at=now,
    )
    updated = update_score(score, TrustVerdict.VERIFIED)
    assert updated.score > 0.5


def test_scoring_rejected_decreases_score():
    now = datetime.now(UTC)
    score = TrustScore(
        agent_did="did:key:test",
        score=0.5,
        interaction_count=0,
        successful_verifications=0,
        failed_verifications=0,
        last_interaction=now,
        decay_rate=0.02,
        created_at=now,
        updated_at=now,
    )
    updated = update_score(score, TrustVerdict.REJECTED)
    assert updated.score < 0.5


def test_scoring_half_life_decay_toward_neutral():
    """A high score decays toward 0.5 after 30 days of inactivity."""
    past = datetime.now(UTC) - timedelta(days=30)
    score = TrustScore(
        agent_did="did:key:test",
        score=0.9,
        interaction_count=5,
        successful_verifications=5,
        failed_verifications=0,
        last_interaction=past,
        decay_rate=0.02,
        created_at=past,
        updated_at=past,
    )
    decayed = apply_half_life_decay(score)
    # After one half-life, should be halfway between 0.9 and 0.5 = 0.7
    assert abs(decayed - 0.7) < 0.01


def test_scoring_routing_decision():
    assert routing_decision(0.8) == "fast_path"
    assert routing_decision(0.5) == "challenge"
    assert routing_decision(0.1) == "blacklist"


def test_scoring_diminishing_returns():
    delta_0 = compute_delta(TrustVerdict.VERIFIED, 0)
    delta_10 = compute_delta(TrustVerdict.VERIFIED, 10)
    delta_100 = compute_delta(TrustVerdict.VERIFIED, 100)
    assert delta_0 > delta_10 > delta_100


def test_scoring_score_clamped():
    """Score never exceeds 1.0 or goes below 0.0."""
    now = datetime.now(UTC)
    score = TrustScore(
        agent_did="did:key:test",
        score=0.99,
        interaction_count=0,
        successful_verifications=0,
        failed_verifications=0,
        last_interaction=now,
        decay_rate=0.02,
        created_at=now,
        updated_at=now,
    )
    for _ in range(20):
        score = update_score(score, TrustVerdict.VERIFIED)
    assert score.score <= 1.0

    score2 = TrustScore(
        agent_did="did:key:test2",
        score=0.01,
        interaction_count=0,
        successful_verifications=0,
        failed_verifications=0,
        last_interaction=now,
        decay_rate=0.02,
        created_at=now,
        updated_at=now,
    )
    for _ in range(20):
        score2 = update_score(score2, TrustVerdict.REJECTED)
    assert score2.score >= 0.0
