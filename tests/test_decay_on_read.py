"""Reputation decay-on-read affects orchestrator routing (challenge vs fast-path)."""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, patch

import pytest

from airlock.crypto import KeyPair, issue_credential, sign_model
from airlock.engine.orchestrator import VerificationOrchestrator
from airlock.engine.state import SessionManager
from airlock.reputation.scoring import THRESHOLD_HIGH
from airlock.reputation.store import ReputationStore
from airlock.schemas import (
    AgentDID,
    HandshakeIntent,
    HandshakeReceived,
    HandshakeRequest,
    TrustScore,
    create_envelope,
)
from airlock.schemas.challenge import ChallengeRequest
from airlock.schemas.envelope import MessageEnvelope, generate_nonce
from airlock.schemas.verdict import TrustVerdict


def _make_hs(session_id: str, agent: KeyPair, issuer: KeyPair, target: str) -> HandshakeRequest:
    vc = issue_credential(issuer, agent.did, "AgentAuthorization", {"role": "agent"})
    env = create_envelope(sender_did=agent.did)
    req = HandshakeRequest(
        envelope=env,
        session_id=session_id,
        initiator=AgentDID(did=agent.did, public_key_multibase=agent.public_key_multibase),
        intent=HandshakeIntent(action="connect", description="d", target_did=target),
        credential=vc,
        signature=None,
    )
    req.signature = sign_model(req, agent.signing_key)
    return req


@pytest.mark.asyncio
async def test_decayed_high_score_routes_to_challenge(tmp_path):
    """Score stored as 0.80 with old last_interaction decays below fast-path threshold."""
    agent = KeyPair.from_seed(b"a" * 32)
    issuer = KeyPair.from_seed(b"i" * 32)
    target = KeyPair.from_seed(b"t" * 32)

    db = str(tmp_path / "decay.lance")
    rep = ReputationStore(db_path=db)
    rep.open()
    past = datetime.now(timezone.utc) - timedelta(days=60)
    seed = TrustScore(
        agent_did=agent.did,
        score=0.80,
        interaction_count=3,
        successful_verifications=3,
        failed_verifications=0,
        last_interaction=past,
        decay_rate=0.02,
        created_at=past,
        updated_at=past,
    )
    rep.upsert(seed)
    loaded = rep.get(agent.did)
    assert loaded is not None
    assert loaded.score < THRESHOLD_HIGH

    sm = SessionManager(default_ttl=300)
    await sm.start()
    gw = KeyPair.from_seed(b"g" * 32)
    challenges: list[str] = []

    async def on_challenge(sid: str, _ch: ChallengeRequest) -> None:
        challenges.append(sid)

    orch = VerificationOrchestrator(
        reputation_store=rep,
        agent_registry={},
        airlock_did=gw.did,
        session_mgr=sm,
        on_challenge=on_challenge,
    )

    now = datetime.now(timezone.utc)
    sid = str(uuid.uuid4())
    fake_ch = ChallengeRequest(
        envelope=MessageEnvelope(
            protocol_version="0.1.0",
            timestamp=now,
            sender_did=orch._airlock_did,
            nonce=generate_nonce(),
        ),
        session_id=sid,
        challenge_id="c1",
        challenge_type="semantic",
        question="q",
        context="",
        expires_at=now + timedelta(minutes=2),
    )

    with patch(
        "airlock.engine.orchestrator.generate_challenge",
        new=AsyncMock(return_value=fake_ch),
    ):
        hs = _make_hs(sid, agent, issuer, target.did)
        await orch.handle_event(
            HandshakeReceived(session_id=sid, timestamp=now, request=hs, callback_url=None)
        )

    assert len(challenges) == 1
    await sm.stop()
    rep.close()


@pytest.mark.asyncio
async def test_concurrent_apply_verdict_serializes(tmp_path):
    import asyncio

    rep = ReputationStore(db_path=str(tmp_path / "conc.lance"))
    rep.open()

    async def apply(v):
        await asyncio.to_thread(rep.apply_verdict, "did:key:x", v)

    await asyncio.gather(
        apply(TrustVerdict.VERIFIED),
        apply(TrustVerdict.VERIFIED),
    )
    final = rep.get("did:key:x")
    assert final is not None
    assert final.interaction_count == 2
    rep.close()
