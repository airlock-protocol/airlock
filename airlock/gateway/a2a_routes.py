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

from __future__ import annotations

import logging
import uuid
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from airlock.a2a.adapter import (
    agent_profile_to_a2a_card,
    airlock_attestation_to_a2a_metadata,
)
from airlock.gateway.handshake_precheck import _client_ip, handshake_transport_precheck
from airlock.schemas.envelope import MessageEnvelope
from airlock.schemas.handshake import HandshakeIntent, HandshakeRequest, SignatureEnvelope
from airlock.schemas.identity import (
    AgentCapability,
    AgentDID,
    AgentProfile,
    VerifiableCredential,
)
from airlock.schemas.verdict import (
    AirlockAttestation,
    CheckResult,
    TrustVerdict,
    VerificationCheck,
)

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
    session_id: str | None = None
    envelope: MessageEnvelope | None = None
    signature: SignatureEnvelope | None = None


class A2AVerifyResponse(BaseModel):
    """Response from POST /a2a/verify."""

    session_id: str
    verdict: str
    trust_score: float
    checks: list[dict[str, Any]]
    a2a_metadata: dict[str, Any]
    challenge: dict[str, Any] | None = None
    trust_token: str | None = None


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
async def get_agent_card(request: Request) -> dict[str, Any]:
    """Return the Airlock gateway's own agent card in AirlockAgentCard format.

    This enables A2A-compatible discovery: any A2A agent can fetch this
    card to learn about the Airlock gateway's capabilities and DID.
    """
    kp = request.app.state.airlock_kp
    cfg = request.app.state.config

    public = (cfg.public_base_url or cfg.default_gateway_url or "").strip().rstrip("/")
    if not public:
        public = f"http://{cfg.host}:{cfg.port}"

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
        endpoint_url=public,
        protocol_versions=[cfg.protocol_version],
        status="active",
        registered_at=datetime.now(UTC),
    )

    airlock_card = agent_profile_to_a2a_card(
        gateway_profile,
        provider_name="Airlock Protocol",
        provider_url="https://airlock.ing",
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
            }
            if airlock_card.a2a_card.provider
            else None,
        },
    }


# ---------------------------------------------------------------------------
# POST /a2a/register
# ---------------------------------------------------------------------------


@a2a_router.post("/register")
async def a2a_register(body: A2ARegisterRequest, request: Request) -> dict[str, Any]:
    """Register an agent using A2A-style fields.

    Converts the A2A-style registration into an Airlock AgentProfile and
    stores it in the in-memory registry and LanceDB (same as POST /register).
    """
    ip = _client_ip(request)
    if not await request.app.state.rate_limit_ip.allow(f"ip:{ip}:register"):
        raise HTTPException(status_code=429, detail="Rate limit exceeded")
    rl_hour = getattr(request.app.state, "rate_limit_register_hour", None)
    if rl_hour is not None and not await rl_hour.allow(f"ip:{ip}:register:hour"):
        raise HTTPException(
            status_code=429,
            detail="Registration rate limit exceeded for this IP (hourly cap)",
        )

    registry: dict[str, AgentProfile] = request.app.state.agent_registry

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
        registered_at=datetime.now(UTC),
    )

    registry[body.did] = profile
    request.app.state.agent_store.upsert(profile)
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
    optional semantic challenge), matching POST /handshake + orchestrator.

    The client must sign the same :class:`HandshakeRequest` the gateway
    builds: include ``session_id``, ``envelope`` (nonce/timestamp the client
    used when signing), and ``signature``.
    """
    orchestrator = request.app.state.orchestrator
    reputation = request.app.state.reputation

    session_id = body.session_id or str(uuid.uuid4())

    text_parts = []
    for part in body.message_parts:
        if part.get("type") == "text" or "text" in part:
            text_parts.append(part.get("text", str(part)))

    description = " ".join(text_parts) if text_parts else "A2A agent verification"

    score = reputation.get_or_default(body.sender_did).score

    if body.signature is None:
        attestation = AirlockAttestation(
            session_id=session_id,
            verified_did=body.sender_did,
            checks_passed=[
                CheckResult(
                    check=VerificationCheck.SIGNATURE,
                    passed=False,
                    detail="Missing signature on handshake",
                ),
            ],
            trust_score=score,
            verdict=TrustVerdict.REJECTED,
            issued_at=datetime.now(UTC),
        )
        return A2AVerifyResponse(
            session_id=session_id,
            verdict=TrustVerdict.REJECTED.value,
            trust_score=score,
            checks=[
                {
                    "check": VerificationCheck.SIGNATURE.value,
                    "passed": False,
                    "detail": "Missing signature on handshake",
                },
            ],
            a2a_metadata=airlock_attestation_to_a2a_metadata(attestation),
        )

    if body.envelope is None:
        attestation = AirlockAttestation(
            session_id=session_id,
            verified_did=body.sender_did,
            checks_passed=[
                CheckResult(
                    check=VerificationCheck.SIGNATURE,
                    passed=False,
                    detail="Signed verify requires envelope (client nonce) in request body",
                ),
            ],
            trust_score=score,
            verdict=TrustVerdict.REJECTED,
            issued_at=datetime.now(UTC),
        )
        return A2AVerifyResponse(
            session_id=session_id,
            verdict=TrustVerdict.REJECTED.value,
            trust_score=score,
            checks=[
                {
                    "check": VerificationCheck.SIGNATURE.value,
                    "passed": False,
                    "detail": "Signed verify requires envelope in request body",
                },
            ],
            a2a_metadata=airlock_attestation_to_a2a_metadata(attestation),
        )

    envelope = body.envelope

    handshake_request = HandshakeRequest(
        envelope=envelope,
        session_id=session_id,
        initiator=AgentDID(
            did=body.sender_did,
            public_key_multibase=body.sender_public_key_multibase,
        ),
        intent=HandshakeIntent(
            action=body.message_metadata.get("airlock_action", "connect")
            if body.message_metadata
            else "connect",
            description=description,
            target_did=body.target_did,
        ),
        credential=body.credential,
        signature=body.signature,
    )

    nack = await handshake_transport_precheck(handshake_request, request)
    if nack is not None:
        attestation = AirlockAttestation(
            session_id=nack.session_id or session_id,
            verified_did=body.sender_did,
            checks_passed=[
                CheckResult(
                    check=VerificationCheck.SIGNATURE,
                    passed=False,
                    detail=f"{nack.error_code}: {nack.reason}",
                ),
            ],
            trust_score=score,
            verdict=TrustVerdict.REJECTED,
            issued_at=datetime.now(UTC),
        )
        return A2AVerifyResponse(
            session_id=nack.session_id or session_id,
            verdict=TrustVerdict.REJECTED.value,
            trust_score=score,
            checks=[
                {
                    "check": VerificationCheck.SIGNATURE.value,
                    "passed": False,
                    "detail": f"{nack.error_code}: {nack.reason}",
                },
            ],
            a2a_metadata=airlock_attestation_to_a2a_metadata(attestation),
        )

    try:
        outcome = await orchestrator.run_handshake_and_wait(
            session_id=session_id,
            handshake=handshake_request,
            callback_url=None,
        )
    except TimeoutError:
        raise HTTPException(status_code=504, detail="Verification timed out") from None

    if outcome[0] == "verdict":
        verdict, attestation = outcome[1], outcome[2]
        checks = [
            {"check": c.check.value, "passed": c.passed, "detail": c.detail}
            for c in attestation.checks_passed
        ]
        logger.info(
            "A2A verify: session=%s did=%s verdict=%s score=%.4f",
            session_id,
            body.sender_did,
            verdict.value,
            attestation.trust_score,
        )
        return A2AVerifyResponse(
            session_id=session_id,
            verdict=verdict.value,
            trust_score=attestation.trust_score,
            checks=checks,
            a2a_metadata=airlock_attestation_to_a2a_metadata(attestation),
            trust_token=attestation.trust_token,
        )

    challenge, challenge_checks = outcome[1], outcome[2]
    score_deferred = reputation.get_or_default(body.sender_did).score
    semantic_checks: list[CheckResult] = list(challenge_checks)
    semantic_checks.append(
        CheckResult(
            check=VerificationCheck.SEMANTIC,
            passed=False,
            detail="Semantic challenge issued — complete POST /challenge-response",
        )
    )
    deferred_attestation = AirlockAttestation(
        session_id=session_id,
        verified_did=body.sender_did,
        checks_passed=semantic_checks,
        trust_score=score_deferred,
        verdict=TrustVerdict.DEFERRED,
        issued_at=datetime.now(UTC),
    )
    checks_out = [
        {"check": c.check.value, "passed": c.passed, "detail": c.detail} for c in semantic_checks
    ]

    logger.info(
        "A2A verify (deferred): session=%s did=%s challenge=%s",
        session_id,
        body.sender_did,
        challenge.challenge_id,
    )

    return A2AVerifyResponse(
        session_id=session_id,
        verdict=TrustVerdict.DEFERRED.value,
        trust_score=score_deferred,
        checks=checks_out,
        a2a_metadata=airlock_attestation_to_a2a_metadata(deferred_attestation),
        challenge=challenge.model_dump(mode="json"),
    )


def register_a2a_routes(app: Any) -> None:
    """Register A2A routes on the FastAPI app."""
    app.include_router(a2a_router)
