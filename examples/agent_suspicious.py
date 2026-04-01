from __future__ import annotations

"""Demo scenario 3: Suspicious agent — valid creds, zero reputation.

This agent has:
- A valid Ed25519 keypair (deterministic seed)
- A valid VC issued by a trusted issuer keypair
- NO pre-seeded reputation (defaults to 0.50 → routes to semantic challenge)
- Semantic challenge module patched to return AMBIGUOUS (simulates LLM unavailable fallback)

Expected outcome: DEFERRED — valid identity, but LLM challenge returns ambiguous answer.
The session is left open (DEFERRED state) — no VERIFIED or REJECTED verdict is issued yet.
"""

import uuid
from datetime import UTC, datetime
from unittest.mock import patch

from airlock.crypto.keys import KeyPair
from airlock.crypto.signing import sign_model
from airlock.crypto.vc import issue_credential
from airlock.engine.orchestrator import VerificationOrchestrator
from airlock.reputation.store import ReputationStore
from airlock.schemas.challenge import ChallengeRequest
from airlock.schemas.envelope import create_envelope
from airlock.schemas.events import HandshakeReceived
from airlock.schemas.handshake import HandshakeIntent, HandshakeRequest
from airlock.schemas.identity import VerifiableCredential

# Deterministic seeds (different from the legitimate agent)
_SUSPICIOUS_SEED = b"suspicious_agent_demo_seed_00000"
_ISSUER_SEED = b"trusted_issuer_keypair_seed_0000"  # same issuer — valid VC

# Fixed challenge question returned by the patched generate_challenge
_FIXED_CHALLENGE_QUESTION = (
    "Describe in detail the specific data you need access to and explain "
    "why your current authorization level is insufficient for this request."
)


def build_suspicious_vc(issuer_kp: KeyPair, agent_did: str) -> VerifiableCredential:
    """Issue a valid VC — the suspicious agent has legitimate-looking credentials."""
    return issue_credential(
        issuer_key=issuer_kp,
        subject_did=agent_did,
        credential_type="AgentAuthorization",
        claims={
            "role": "data_aggregator",
            "authorization_level": "restricted",
            "domain": "market_intelligence",
        },
        validity_days=365,
    )


def build_suspicious_handshake(
    agent_kp: KeyPair,
    vc: VerifiableCredential,
    airlock_did: str,
) -> HandshakeRequest:
    """Build and sign the HandshakeRequest for the suspicious agent."""
    envelope = create_envelope(sender_did=agent_kp.did)
    session_id = str(uuid.uuid4())

    req = HandshakeRequest(
        envelope=envelope,
        session_id=session_id,
        initiator=agent_kp.to_agent_did(),
        intent=HandshakeIntent(
            action="bulk_data_export",
            description="Requesting bulk export of all user interaction logs",
            target_did=airlock_did,
        ),
        credential=vc,
        signature=None,
    )
    req.signature = sign_model(req, agent_kp.signing_key)
    return req


async def _patched_generate_challenge(
    session_id: str,
    capabilities: list,
    airlock_did: str,
    litellm_model: str,
    litellm_api_base: str | None = None,
) -> ChallengeRequest:
    """Replacement for generate_challenge — returns a fixed challenge without LLM."""
    from datetime import timedelta

    from airlock.schemas.challenge import ChallengeRequest
    from airlock.schemas.envelope import create_envelope

    challenge_id = str(uuid.uuid4())
    envelope = create_envelope(sender_did=airlock_did)
    return ChallengeRequest(
        envelope=envelope,
        session_id=session_id,
        challenge_id=challenge_id,
        challenge_type="semantic",
        question=_FIXED_CHALLENGE_QUESTION,
        context="The agent has requested bulk data export. Verify intent and authorization.",
        expires_at=datetime.now(UTC) + timedelta(minutes=5),
    )


async def run_suspicious_scenario(
    orchestrator: VerificationOrchestrator,
    reputation_store: ReputationStore,
    airlock_did: str,
) -> dict:
    """Run the suspicious agent scenario end-to-end.

    The agent passes signature and VC checks but has default 0.5 trust score,
    which routes it to semantic challenge. The challenge module is patched to
    return a fixed question and AMBIGUOUS outcome (simulating LLM unavailable).
    The orchestrator receives the challenge but no response arrives — the session
    ends with DEFERRED status (challenge issued, awaiting response).

    Returns:
        dict with keys: scenario, verdict, session_id, trust_score, challenge, trace
    """
    agent_kp = KeyPair.from_seed(_SUSPICIOUS_SEED)
    issuer_kp = KeyPair.from_seed(_ISSUER_SEED)

    vc = build_suspicious_vc(issuer_kp, agent_kp.did)
    handshake = build_suspicious_handshake(agent_kp, vc, airlock_did)

    # No reputation seeding — agent starts at default 0.50 → routes to challenge
    score_record = reputation_store.get_or_default(agent_kp.did)
    initial_trust_score = score_record.score

    result: dict = {
        "scenario": "suspicious",
        "agent_did": agent_kp.did,
        "verdict": "DEFERRED",
        "session_id": handshake.session_id,
        "trust_score": initial_trust_score,
        "challenge_issued": None,
        "trace": [],
    }

    challenge_captured: list[ChallengeRequest] = []

    async def _on_challenge(session_id: str, challenge: ChallengeRequest) -> None:
        challenge_captured.append(challenge)
        result["trace"].append(
            {
                "event": "challenge_issued",
                "session_id": session_id,
                "challenge_id": challenge.challenge_id,
                "challenge_type": challenge.challenge_type,
                "question": challenge.question,
            }
        )

    # Temporarily install challenge callback and patch the generate_challenge function
    original_on_challenge = orchestrator._on_challenge
    orchestrator._on_challenge = _on_challenge

    event = HandshakeReceived(
        session_id=handshake.session_id,
        timestamp=datetime.now(UTC),
        request=handshake,
        callback_url=None,
    )

    # Patch generate_challenge in the orchestrator module so no LLM call is made
    with patch(
        "airlock.engine.orchestrator.generate_challenge",
        side_effect=_patched_generate_challenge,
    ):
        await orchestrator.handle_event(event)

    # Restore original callback
    orchestrator._on_challenge = original_on_challenge

    if challenge_captured:
        result["challenge_issued"] = {
            "challenge_id": challenge_captured[0].challenge_id,
            "question": challenge_captured[0].question,
            "expires_at": challenge_captured[0].expires_at.isoformat(),
        }
        result["trace"].append(
            {
                "event": "session_deferred",
                "reason": (
                    "Challenge issued — no response received in demo. "
                    "LLM evaluation skipped (no LLM configured). "
                    "In production, the agent would answer and receive VERIFIED or REJECTED."
                ),
            }
        )
    else:
        result["trace"].append(
            {
                "event": "no_challenge_issued",
                "reason": "Unexpected: challenge path was taken but no challenge was generated.",
            }
        )

    return result
