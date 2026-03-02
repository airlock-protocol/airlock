from __future__ import annotations

"""Demo scenario 1: Legitimate agent with high trust score.

This agent has:
- A valid Ed25519 keypair (deterministic seed)
- A valid VC issued by a trusted issuer keypair
- A pre-seeded high trust score (> 0.75 threshold → fast-path VERIFIED)
- A registered AgentProfile in the gateway registry

Expected outcome: VERIFIED via fast-path (no semantic challenge needed).
"""

import uuid
from datetime import datetime, timezone

from airlock.crypto.keys import KeyPair
from airlock.crypto.signing import sign_model
from airlock.crypto.vc import issue_credential
from airlock.engine.orchestrator import VerificationOrchestrator
from airlock.reputation.store import ReputationStore
from airlock.schemas.envelope import create_envelope
from airlock.schemas.events import HandshakeReceived
from airlock.schemas.handshake import HandshakeIntent, HandshakeRequest
from airlock.schemas.identity import (
    AgentCapability,
    AgentProfile,
    VerifiableCredential,
)
from airlock.schemas.reputation import TrustScore
from airlock.schemas.verdict import TrustVerdict

# Deterministic seed for the legitimate agent (32 bytes exactly)
_AGENT_SEED = b"legitimate_agent_demo_seed_00000"
# Deterministic seed for the trusted issuer keypair
_ISSUER_SEED = b"trusted_issuer_keypair_seed_0000"


def build_legitimate_profile(kp: KeyPair) -> AgentProfile:
    """Build a rich AgentProfile for the legitimate agent."""
    return AgentProfile(
        did=kp.to_agent_did(),
        display_name="Legitimate Research Agent",
        capabilities=[
            AgentCapability(
                name="data_retrieval",
                version="1.0.0",
                description="Fetches and summarises research papers",
            ),
            AgentCapability(
                name="report_generation",
                version="1.0.0",
                description="Generates structured markdown reports",
            ),
        ],
        endpoint_url="https://agents.example.com/legitimate",
        protocol_versions=["0.1.0"],
        status="active",
        registered_at=datetime.now(timezone.utc),
    )


def build_legitimate_vc(issuer_kp: KeyPair, agent_did: str) -> VerifiableCredential:
    """Issue a valid VerifiableCredential from the trusted issuer to the agent."""
    return issue_credential(
        issuer_key=issuer_kp,
        subject_did=agent_did,
        credential_type="AgentAuthorization",
        claims={
            "role": "research_agent",
            "authorization_level": "standard",
            "domain": "academic_research",
        },
        validity_days=365,
    )


def seed_high_trust_score(reputation_store: ReputationStore, agent_did: str) -> float:
    """Directly seed a high trust score (0.80) for the agent.

    A score of 0.80 is above the THRESHOLD_HIGH (0.75), which routes the
    handshake to the fast-path (VERIFIED) without a semantic challenge.
    """
    now = datetime.now(timezone.utc)
    score = TrustScore(
        agent_did=agent_did,
        score=0.80,
        interaction_count=20,
        successful_verifications=18,
        failed_verifications=1,
        last_interaction=now,
        decay_rate=0.02,
        created_at=now,
        updated_at=now,
    )
    reputation_store.upsert(score)
    return score.score


def build_handshake_request(
    agent_kp: KeyPair,
    vc: VerifiableCredential,
    airlock_did: str,
) -> HandshakeRequest:
    """Build and sign a HandshakeRequest."""
    session_id = str(uuid.uuid4())
    envelope = create_envelope(sender_did=agent_kp.did)

    req = HandshakeRequest(
        envelope=envelope,
        session_id=session_id,
        initiator=agent_kp.to_agent_did(),
        intent=HandshakeIntent(
            action="request_data_access",
            description="Requesting access to the shared research dataset",
            target_did=airlock_did,
        ),
        credential=vc,
        signature=None,
    )

    # Sign the request (exclude 'signature' field from canonical form)
    req.signature = sign_model(req, agent_kp.signing_key)
    return req


async def run_legitimate_scenario(
    orchestrator: VerificationOrchestrator,
    reputation_store: ReputationStore,
    airlock_did: str,
) -> dict:
    """Run the legitimate agent scenario end-to-end.

    Steps:
    1. Create deterministic keypair + issuer keypair
    2. Issue a valid VC
    3. Seed high trust score directly in the reputation store
    4. Build and sign a HandshakeRequest
    5. Dispatch HandshakeReceived event directly to the orchestrator
    6. Capture verdict via on_verdict callback
    7. Return trace dict

    Returns:
        dict with keys: scenario, verdict, session_id, trust_score, trace
    """
    agent_kp = KeyPair.from_seed(_AGENT_SEED)
    issuer_kp = KeyPair.from_seed(_ISSUER_SEED)

    vc = build_legitimate_vc(issuer_kp, agent_kp.did)
    trust_score = seed_high_trust_score(reputation_store, agent_kp.did)
    handshake = build_handshake_request(agent_kp, vc, airlock_did)

    # Wire a one-shot verdict capture callback
    result: dict = {
        "scenario": "legitimate",
        "agent_did": agent_kp.did,
        "verdict": None,
        "session_id": handshake.session_id,
        "trust_score": trust_score,
        "trace": [],
    }

    captured: list[dict] = []

    async def _on_verdict(session_id: str, verdict: TrustVerdict, attestation) -> None:
        captured.append(
            {
                "event": "verdict",
                "session_id": session_id,
                "verdict": verdict.value,
                "trust_score": attestation.trust_score,
                "checks": [
                    {"check": c.check.value, "passed": c.passed, "detail": c.detail}
                    for c in attestation.checks_passed
                ],
            }
        )

    # Temporarily install our callback
    original_on_verdict = orchestrator._on_verdict
    orchestrator._on_verdict = _on_verdict

    event = HandshakeReceived(
        session_id=handshake.session_id,
        timestamp=datetime.now(timezone.utc),
        request=handshake,
        callback_url=None,
    )

    await orchestrator.handle_event(event)

    # Restore original callback
    orchestrator._on_verdict = original_on_verdict

    result["trace"] = captured
    if captured:
        result["verdict"] = captured[-1]["verdict"]

    return result
