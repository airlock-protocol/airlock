from __future__ import annotations

"""Tests for the delegation model: DelegationIntent, orchestrator validation,
and RevocationStore cascade."""

import asyncio
import os
import shutil
import uuid
from datetime import UTC, datetime, timedelta, timezone
from unittest.mock import AsyncMock, patch

import pytest

from airlock.crypto import KeyPair, issue_credential, sign_model
from airlock.engine.orchestrator import VerificationOrchestrator
from airlock.engine.state import SessionManager
from airlock.gateway.revocation import RevocationStore
from airlock.reputation.store import ReputationStore
from airlock.schemas import (
    AgentCapability,
    AgentDID,
    AgentProfile,
    HandshakeIntent,
    HandshakeReceived,
    HandshakeRequest,
    create_envelope,
)
from airlock.schemas.handshake import DelegationIntent
from airlock.schemas.reputation import TrustScore
from airlock.schemas.verdict import TrustVerdict, VerificationCheck


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def reputation_store(tmp_path):
    store = ReputationStore(db_path=str(tmp_path / "deleg_rep.lance"))
    store.open()
    yield store
    store.close()


@pytest.fixture
def revocation_store():
    return RevocationStore()


@pytest.fixture
def airlock_kp():
    return KeyPair.from_seed(b"airlock_deleg0000000000000000000")


@pytest.fixture
def agent_kp():
    return KeyPair.from_seed(b"agent___deleg0000000000000000000")


@pytest.fixture
def delegator_kp():
    return KeyPair.from_seed(b"delegator_dlg0000000000000000000")


@pytest.fixture
def issuer_kp():
    return KeyPair.from_seed(b"issuer__deleg0000000000000000000")


@pytest.fixture
def target_kp():
    return KeyPair.from_seed(b"target__deleg0000000000000000000")


def _make_handshake(
    agent_kp: KeyPair,
    issuer_kp: KeyPair,
    target_did: str,
    *,
    delegator_did: str | None = None,
    delegation: DelegationIntent | None = None,
    credential_chain: list | None = None,
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
            description="Delegation test handshake",
            target_did=target_did,
        ),
        credential=vc,
        signature=None,
        delegator_did=delegator_did,
        delegation=delegation,
        credential_chain=credential_chain or None,
    )
    if sign:
        request.signature = sign_model(request, agent_kp.signing_key)
    return request


def _set_trust_score(reputation_store: ReputationStore, did: str, score: float) -> None:
    """Set a specific trust score for a DID."""
    now = datetime.now(UTC)
    ts = TrustScore(
        agent_did=did,
        score=score,
        interaction_count=10,
        successful_verifications=8,
        failed_verifications=2,
        last_interaction=now,
        decay_rate=0.02,
        created_at=now,
        updated_at=now,
    )
    reputation_store.upsert(ts)


def _make_orchestrator(
    reputation_store: ReputationStore,
    revocation_store: RevocationStore,
    airlock_kp: KeyPair,
    agent_registry: dict | None = None,
) -> VerificationOrchestrator:
    return VerificationOrchestrator(
        reputation_store=reputation_store,
        agent_registry=agent_registry or {},
        airlock_did=airlock_kp.did,
        revocation_store=revocation_store,
    )


# ---------------------------------------------------------------------------
# DelegationIntent model tests
# ---------------------------------------------------------------------------


def test_delegation_intent_defaults():
    d = DelegationIntent(scope="read")
    assert d.scope == "read"
    assert d.max_depth == 1
    assert d.expires_at is None


def test_delegation_intent_with_expiry():
    exp = datetime(2030, 1, 1, tzinfo=timezone.utc)
    d = DelegationIntent(scope="write", max_depth=3, expires_at=exp)
    assert d.max_depth == 3
    assert d.expires_at == exp


# ---------------------------------------------------------------------------
# HandshakeRequest backward compat
# ---------------------------------------------------------------------------


def test_handshake_request_no_delegation_fields(agent_kp, issuer_kp, target_kp):
    """HandshakeRequest without delegation fields works (backward compat)."""
    hs = _make_handshake(agent_kp, issuer_kp, target_kp.did, sign=False)
    assert hs.delegator_did is None
    assert hs.credential_chain is None
    assert hs.delegation is None


def test_handshake_request_with_delegation_fields(agent_kp, issuer_kp, target_kp, delegator_kp):
    """HandshakeRequest with delegation fields serialises correctly."""
    deleg = DelegationIntent(scope="admin", max_depth=2)
    hs = _make_handshake(
        agent_kp, issuer_kp, target_kp.did,
        delegator_did=delegator_kp.did,
        delegation=deleg,
        sign=False,
    )
    assert hs.delegator_did == delegator_kp.did
    assert hs.delegation.scope == "admin"


# ---------------------------------------------------------------------------
# VerificationCheck.DELEGATION
# ---------------------------------------------------------------------------


def test_delegation_enum_value():
    assert VerificationCheck.DELEGATION == "delegation"
    assert VerificationCheck.DELEGATION.value == "delegation"


# ---------------------------------------------------------------------------
# Orchestrator delegation validation (via graph run)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_delegation_passthrough_no_delegator(
    reputation_store, revocation_store, airlock_kp, agent_kp, issuer_kp, target_kp
):
    """Non-delegated handshake should pass delegation check as no-op."""
    _set_trust_score(reputation_store, agent_kp.did, 0.9)
    orch = _make_orchestrator(reputation_store, revocation_store, airlock_kp)
    hs = _make_handshake(agent_kp, issuer_kp, target_kp.did)

    with patch("airlock.engine.orchestrator.generate_challenge", new_callable=AsyncMock):
        event = HandshakeReceived(
            session_id=hs.session_id,
            timestamp=datetime.now(UTC),
            request=hs,
        )
        await orch.handle_event(event)

    # Should not fail at delegation
    # (may fail at other steps, but delegation check should pass)


@pytest.mark.asyncio
async def test_delegation_rejected_delegator_revoked(
    reputation_store, revocation_store, airlock_kp, agent_kp, issuer_kp, target_kp, delegator_kp
):
    """Delegation fails if delegator is revoked."""
    _set_trust_score(reputation_store, agent_kp.did, 0.9)
    _set_trust_score(reputation_store, delegator_kp.did, 0.9)
    await revocation_store.revoke(delegator_kp.did)

    orch = _make_orchestrator(reputation_store, revocation_store, airlock_kp)

    deleg = DelegationIntent(scope="test")
    hs = _make_handshake(
        agent_kp, issuer_kp, target_kp.did,
        delegator_did=delegator_kp.did,
        delegation=deleg,
    )

    # Run the graph directly via internal method
    from airlock.engine.orchestrator import OrchestrationState
    from airlock.schemas.session import VerificationSession, VerificationState

    now = datetime.now(UTC)
    session = VerificationSession(
        session_id=hs.session_id,
        state=VerificationState.HANDSHAKE_RECEIVED,
        initiator_did=agent_kp.did,
        target_did=target_kp.did,
        created_at=now,
        updated_at=now,
        handshake_request=hs,
    )
    initial: OrchestrationState = {
        "session": session,
        "handshake": hs,
        "challenge": None,
        "challenge_response": None,
        "check_results": [],
        "trust_score": 0.5,
        "verdict": None,
        "error": None,
        "failed_at": None,
        "_sig_valid": False,
        "_vc_valid": False,
        "_routing": "challenge",
        "_challenge_outcome": None,
    }
    final = await orch._run_graph(initial)
    assert final.get("verdict") == TrustVerdict.REJECTED
    assert final.get("failed_at") == "validate_delegation"


@pytest.mark.asyncio
async def test_delegation_rejected_low_trust_score(
    reputation_store, revocation_store, airlock_kp, agent_kp, issuer_kp, target_kp, delegator_kp
):
    """Delegation fails if delegator trust score < 0.75."""
    _set_trust_score(reputation_store, agent_kp.did, 0.9)
    _set_trust_score(reputation_store, delegator_kp.did, 0.5)  # Too low

    orch = _make_orchestrator(reputation_store, revocation_store, airlock_kp)

    deleg = DelegationIntent(scope="test")
    hs = _make_handshake(
        agent_kp, issuer_kp, target_kp.did,
        delegator_did=delegator_kp.did,
        delegation=deleg,
    )

    from airlock.engine.orchestrator import OrchestrationState
    from airlock.schemas.session import VerificationSession, VerificationState

    now = datetime.now(UTC)
    session = VerificationSession(
        session_id=hs.session_id,
        state=VerificationState.HANDSHAKE_RECEIVED,
        initiator_did=agent_kp.did,
        target_did=target_kp.did,
        created_at=now,
        updated_at=now,
        handshake_request=hs,
    )
    initial: OrchestrationState = {
        "session": session,
        "handshake": hs,
        "challenge": None,
        "challenge_response": None,
        "check_results": [],
        "trust_score": 0.5,
        "verdict": None,
        "error": None,
        "failed_at": None,
        "_sig_valid": False,
        "_vc_valid": False,
        "_routing": "challenge",
        "_challenge_outcome": None,
    }
    final = await orch._run_graph(initial)
    assert final.get("verdict") == TrustVerdict.REJECTED
    assert final.get("failed_at") == "validate_delegation"


@pytest.mark.asyncio
async def test_delegation_chain_too_deep(
    reputation_store, revocation_store, airlock_kp, agent_kp, issuer_kp, target_kp, delegator_kp
):
    """Delegation fails if credential chain exceeds max_depth."""
    _set_trust_score(reputation_store, agent_kp.did, 0.9)
    _set_trust_score(reputation_store, delegator_kp.did, 0.9)

    orch = _make_orchestrator(reputation_store, revocation_store, airlock_kp)

    # Create chain of 3 VCs but max_depth=1
    vc1 = issue_credential(issuer_kp, agent_kp.did, "AgentAuthorization", {"a": 1})
    vc2 = issue_credential(issuer_kp, agent_kp.did, "AgentAuthorization", {"b": 2})
    vc3 = issue_credential(issuer_kp, agent_kp.did, "AgentAuthorization", {"c": 3})

    deleg = DelegationIntent(scope="test", max_depth=1)
    hs = _make_handshake(
        agent_kp, issuer_kp, target_kp.did,
        delegator_did=delegator_kp.did,
        delegation=deleg,
        credential_chain=[vc1, vc2, vc3],
    )

    from airlock.engine.orchestrator import OrchestrationState
    from airlock.schemas.session import VerificationSession, VerificationState

    now = datetime.now(UTC)
    session = VerificationSession(
        session_id=hs.session_id,
        state=VerificationState.HANDSHAKE_RECEIVED,
        initiator_did=agent_kp.did,
        target_did=target_kp.did,
        created_at=now,
        updated_at=now,
        handshake_request=hs,
    )
    initial: OrchestrationState = {
        "session": session,
        "handshake": hs,
        "challenge": None,
        "challenge_response": None,
        "check_results": [],
        "trust_score": 0.5,
        "verdict": None,
        "error": None,
        "failed_at": None,
        "_sig_valid": False,
        "_vc_valid": False,
        "_routing": "challenge",
        "_challenge_outcome": None,
    }
    final = await orch._run_graph(initial)
    assert final.get("verdict") == TrustVerdict.REJECTED
    assert final.get("failed_at") == "validate_delegation"


@pytest.mark.asyncio
async def test_delegation_expired(
    reputation_store, revocation_store, airlock_kp, agent_kp, issuer_kp, target_kp, delegator_kp
):
    """Delegation fails if it has expired."""
    _set_trust_score(reputation_store, agent_kp.did, 0.9)
    _set_trust_score(reputation_store, delegator_kp.did, 0.9)

    orch = _make_orchestrator(reputation_store, revocation_store, airlock_kp)

    deleg = DelegationIntent(
        scope="test",
        expires_at=datetime(2020, 1, 1, tzinfo=timezone.utc),  # already expired
    )
    hs = _make_handshake(
        agent_kp, issuer_kp, target_kp.did,
        delegator_did=delegator_kp.did,
        delegation=deleg,
    )

    from airlock.engine.orchestrator import OrchestrationState
    from airlock.schemas.session import VerificationSession, VerificationState

    now = datetime.now(UTC)
    session = VerificationSession(
        session_id=hs.session_id,
        state=VerificationState.HANDSHAKE_RECEIVED,
        initiator_did=agent_kp.did,
        target_did=target_kp.did,
        created_at=now,
        updated_at=now,
        handshake_request=hs,
    )
    initial: OrchestrationState = {
        "session": session,
        "handshake": hs,
        "challenge": None,
        "challenge_response": None,
        "check_results": [],
        "trust_score": 0.5,
        "verdict": None,
        "error": None,
        "failed_at": None,
        "_sig_valid": False,
        "_vc_valid": False,
        "_routing": "challenge",
        "_challenge_outcome": None,
    }
    final = await orch._run_graph(initial)
    assert final.get("verdict") == TrustVerdict.REJECTED
    assert final.get("failed_at") == "validate_delegation"


# ---------------------------------------------------------------------------
# RevocationStore delegation + cascade tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_register_delegation():
    store = RevocationStore()
    store.register_delegation("did:key:zDelegator", "did:key:zDelegate1")
    store.register_delegation("did:key:zDelegator", "did:key:zDelegate2")
    assert "did:key:zDelegate1" in store._delegations["did:key:zDelegator"]
    assert "did:key:zDelegate2" in store._delegations["did:key:zDelegator"]


@pytest.mark.asyncio
async def test_revocation_cascade_to_delegates():
    """Revoking a delegator also revokes its delegates."""
    store = RevocationStore()
    store.register_delegation("did:key:zDelegator", "did:key:zDelegate1")
    store.register_delegation("did:key:zDelegator", "did:key:zDelegate2")

    result = await store.revoke("did:key:zDelegator")
    assert result is True

    assert await store.is_revoked("did:key:zDelegator")
    assert await store.is_revoked("did:key:zDelegate1")
    assert await store.is_revoked("did:key:zDelegate2")


@pytest.mark.asyncio
async def test_revocation_no_cascade_without_delegation():
    """Revoking a DID without delegates only revokes that DID."""
    store = RevocationStore()
    await store.revoke("did:key:zSolo")
    assert await store.is_revoked("did:key:zSolo")
    # No crash, no side effects


@pytest.mark.asyncio
async def test_cascade_does_not_double_revoke():
    """Already-revoked delegates are not double-counted."""
    store = RevocationStore()
    store.register_delegation("did:key:zDelegator", "did:key:zDelegate1")
    await store.revoke("did:key:zDelegate1")  # Pre-revoked
    result = await store.revoke("did:key:zDelegator")
    assert result is True
    assert await store.is_revoked("did:key:zDelegate1")


@pytest.mark.asyncio
async def test_unrevoke_does_not_unrevoke_delegates():
    """Unrevoking a delegator does NOT automatically unrevoke delegates."""
    store = RevocationStore()
    store.register_delegation("did:key:zDelegator", "did:key:zDelegate1")
    await store.revoke("did:key:zDelegator")

    await store.unrevoke("did:key:zDelegator")
    assert not await store.is_revoked("did:key:zDelegator")
    # Delegate stays revoked (cascaded revocations are not automatically undone)
    assert await store.is_revoked("did:key:zDelegate1")
