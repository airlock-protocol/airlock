from __future__ import annotations

"""A2A-native gateway routes.

These endpoints allow agents that speak the Google A2A protocol to interact
with Airlock's trust verification layer without needing the Airlock SDK.

Route overview:
  POST /a2a/verify         Accept an A2A Message, run Airlock trust verification,
                           return the original message enriched with trust metadata.
  GET  /a2a/agent-card     Return the Airlock gateway's own AirlockAgentCard.
  POST /a2a/register       Register an agent via A2A Agent Card format.

All routes sit under the /a2a prefix and don't interfere with the existing
Airlock-native routes.
"""

import logging
import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from airlock.a2a.adapter import (
    AirlockAgentCard,
    a2a_card_to_agent_profile,
    a2a_message_to_handshake_request,
    agent_profile_to_a2a_card,
    airlock_attestation_to_a2a_metadata,
)
from airlock.crypto.keys import resolve_public_key
from airlock.crypto.signing import verify_model
from airlock.schemas.envelope import create_envelope
from airlock.schemas.identity import (
    AgentCapability,
    AgentDID,
    AgentProfile,
    VerifiableCredential,
)
from airlock.schemas.verdict import TrustVerdict

logger = logging.getLogger(__name__)

a2a_router = APIRouter(prefix="/a2a", tags=["A2A"])


class A2AVerifyRequest(BaseModel):
    """Request body for POST /a2a/verify.

    Combines the minimal identity fields needed for Airlock verification
    with the A2A message payload.  An agent sends its DID, public key,
    credential, and the A2A-format message it wants to relay.
    """

    sender_did: str
    sender_public_key_multibase: str
    target_did: str
    credential: VerifiableCredential
    message_parts: list[dict[str, Any]]
    message_metadata: dict[str, Any] | None = None


class A2AVerifyResponse(BaseModel):
    """Response from POST /a2a/verify."""

    session_id: str
    verdict: str
    trust_score: float
    checks: list[dict[str, Any]]
    a2a_metadata: dict[str, Any]


class A2ARegisterRequest(BaseModel):
    """Register an agent using A2A-style fields."""

    did: str
    public_key_multibase: str
    display_name: str
    endpoint_url: str
    skills: list[dict[str, str]] = Field(default_factory=list)
    protocol_versions: list[str] = Field(default_factory=lambda: ["0.1.0"])


# ---------------------------------------------------------------------------
# GET /a2a/agent-card
# ---------------------------------------------------------------------------


@a2a_router.get("/agent-card")
async def get_agent_card(request: Request) -> dict:
    """Return the Airlock gateway's own agent card in AirlockAgentCard format.

    This enables A2A-compatible discovery: any A2A agent can fetch this
    card to learn about the Airlock gateway's capabilities and DID.
    """
    kp = request.app.state.airlock_kp
    cfg = request.app.state.config

    gateway_profile = AgentProfile(
        did=AgentDID(did=kp.did, public_key_multibase=kp.public_key_multibase),
        display_name="Airlock Trust Gateway",
        capabilities=[
            AgentCapability(
                name="trust-verification",
                version=cfg.protocol_version,
                description="Agent identity and trust verification via 5-phase Airlock protocol",
            ),
            AgentCapability(
                name="reputation-scoring",
                version="1.0",
                description="Trust score with half-life decay based on interaction history",
            ),
            AgentCapability(
                name="semantic-challenge",
                version="1.0",
                description="LLM-based behavioral verification for unknown agents",
            ),
        ],
        endpoint_url=f"http://{cfg.host}:{cfg.port}",
        protocol_versions=[cfg.protocol_version],
        status="active",
        registered_at=datetime.now(timezone.utc),
    )

    airlock_card = agent_profile_to_a2a_card(
        gateway_profile,
        provider_name="Airlock Protocol",
        provider_url="https://airlock-protocol.dev",
    )

    return {
        "airlock_did": airlock_card.airlock_did,
        "airlock_public_key_multibase": airlock_card.airlock_public_key_multibase,
        "trust_score": airlock_card.trust_score,
        "supports_semantic_challenge": airlock_card.supports_semantic_challenge,
        "a2a_card": {
            "name": airlock_card.a2a_card.name,
            "description": airlock_card.a2a_card.description,
            "url": airlock_card.a2a_card.url,
            "version": airlock_card.a2a_card.version,
            "skills": [
                {"name": s.name, "description": s.description, "tags": s.tags}
                for s in airlock_card.a2a_card.skills
            ],
            "provider": {
                "organization": airlock_card.a2a_card.provider.organization,
                "url": airlock_card.a2a_card.provider.url,
            } if airlock_card.a2a_card.provider else None,
        },
    }


# ---------------------------------------------------------------------------
# POST /a2a/register
# ---------------------------------------------------------------------------


@a2a_router.post("/register")
async def a2a_register(body: A2ARegisterRequest, request: Request) -> dict:
    """Register an agent using A2A-style fields.

    Converts the A2A-style registration into an Airlock AgentProfile and
    stores it in the in-memory registry.
    """
    registry: dict = request.app.state.agent_registry

    capabilities = [
        AgentCapability(
            name=skill.get("name", "unknown"),
            version=skill.get("version", "1.0"),
            description=skill.get("description", ""),
        )
        for skill in body.skills
    ]

    profile = AgentProfile(
        did=AgentDID(did=body.did, public_key_multibase=body.public_key_multibase),
        display_name=body.display_name,
        capabilities=capabilities,
        endpoint_url=body.endpoint_url,
        protocol_versions=body.protocol_versions,
        status="active",
        registered_at=datetime.now(timezone.utc),
    )

    registry[body.did] = profile
    logger.info("A2A-registered agent: %s (%s)", body.display_name, body.did)

    return {
        "registered": True,
        "did": body.did,
        "display_name": body.display_name,
        "format": "a2a",
    }


# ---------------------------------------------------------------------------
# POST /a2a/verify
# ---------------------------------------------------------------------------


@a2a_router.post("/verify")
async def a2a_verify(body: A2AVerifyRequest, request: Request) -> A2AVerifyResponse:
    """Verify an A2A agent through the Airlock trust pipeline.

    This is the main entry point for A2A-native agents. It accepts a
    verification request with A2A-style message parts and runs the full
    Airlock 5-phase protocol (schema, signature, credential, reputation,
    optional semantic challenge).

    The response includes the A2A-compatible metadata dict that the agent
    can embed in subsequent A2A messages to prove its trust status.
    """
    orchestrator = request.app.state.orchestrator
    reputation = request.app.state.reputation

    session_id = str(uuid.uuid4())

    text_parts = []
    for part in body.message_parts:
        if part.get("type") == "text" or "text" in part:
            text_parts.append(part.get("text", str(part)))

    description = " ".join(text_parts) if text_parts else "A2A agent verification"

    from airlock.schemas.handshake import HandshakeIntent, HandshakeRequest
    from airlock.schemas.envelope import create_envelope

    envelope = create_envelope(sender_did=body.sender_did)

    handshake_request = HandshakeRequest(
        envelope=envelope,
        session_id=session_id,
        initiator=AgentDID(
            did=body.sender_did,
            public_key_multibase=body.sender_public_key_multibase,
        ),
        intent=HandshakeIntent(
            action=body.message_metadata.get("airlock_action", "connect") if body.message_metadata else "connect",
            description=description,
            target_did=body.target_did,
        ),
        credential=body.credential,
    )

    from airlock.schemas.events import HandshakeReceived
    event = HandshakeReceived(
        session_id=session_id,
        timestamp=datetime.now(timezone.utc),
        request=handshake_request,
    )

    sig_valid = False
    try:
        verify_key = resolve_public_key(body.sender_did)
        sig_valid = verify_model(handshake_request, verify_key)
    except Exception:
        sig_valid = False

    from airlock.crypto.vc import validate_credential
    vc_valid = False
    vc_reason = "no proof"
    try:
        issuer_verify_key = resolve_public_key(body.credential.issuer)
        vc_valid, vc_reason = validate_credential(body.credential, issuer_verify_key)
    except Exception as exc:
        vc_valid = False
        vc_reason = str(exc)

    from airlock.reputation.scoring import routing_decision
    score_record = reputation.get_or_default(body.sender_did)
    routing = routing_decision(score_record.score)

    checks = [
        {"check": "schema", "passed": True, "detail": "Pydantic validation passed"},
        {"check": "signature", "passed": sig_valid, "detail": "Ed25519 valid" if sig_valid else "Signature verification failed"},
        {"check": "credential", "passed": vc_valid, "detail": vc_reason},
        {"check": "reputation", "passed": routing != "blacklist", "detail": f"score={score_record.score:.4f} routing={routing}"},
    ]

    if routing == "blacklist":
        verdict = TrustVerdict.REJECTED
    elif not sig_valid:
        verdict = TrustVerdict.REJECTED
    elif not vc_valid:
        verdict = TrustVerdict.REJECTED
    elif routing == "fast_path":
        verdict = TrustVerdict.VERIFIED
    else:
        verdict = TrustVerdict.DEFERRED

    if verdict in (TrustVerdict.VERIFIED, TrustVerdict.REJECTED):
        reputation.apply_verdict(body.sender_did, verdict)

    from airlock.schemas.verdict import AirlockAttestation, CheckResult, VerificationCheck
    attestation = AirlockAttestation(
        session_id=session_id,
        verified_did=body.sender_did,
        checks_passed=[
            CheckResult(
                check=VerificationCheck(c["check"]),
                passed=c["passed"],
                detail=c["detail"],
            )
            for c in checks
        ],
        trust_score=score_record.score,
        verdict=verdict,
        issued_at=datetime.now(timezone.utc),
    )

    a2a_meta = airlock_attestation_to_a2a_metadata(attestation)

    logger.info(
        "A2A verify: session=%s did=%s verdict=%s score=%.4f",
        session_id, body.sender_did, verdict.value, score_record.score,
    )

    return A2AVerifyResponse(
        session_id=session_id,
        verdict=verdict.value,
        trust_score=score_record.score,
        checks=checks,
        a2a_metadata=a2a_meta,
    )


def register_a2a_routes(app: Any) -> None:
    """Register A2A routes on the FastAPI app."""
    app.include_router(a2a_router)
