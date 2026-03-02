from __future__ import annotations

"""Request handlers for the Airlock gateway.

Every handler follows the same validation pipeline:
  1. Parse body (Pydantic — already done by FastAPI)
  2. Verify Ed25519 signature
  3. Publish VerificationEvent to EventBus
  4. Return TransportAck or TransportNack

Handlers are pure functions that receive the parsed body + app.state.
They do NOT perform async I/O themselves beyond publishing to the event bus.
"""

import logging
import uuid
from datetime import datetime, timezone

from fastapi import HTTPException, Request

from airlock.crypto.keys import resolve_public_key
from airlock.crypto.signing import verify_model
from airlock.schemas.challenge import ChallengeResponse
from airlock.schemas.envelope import (
    MessageEnvelope,
    TransportAck,
    TransportNack,
    create_envelope,
    generate_nonce,
)
from airlock.schemas.events import (
    ChallengeResponseReceived,
    HandshakeReceived,
    ResolveRequested,
)
from airlock.schemas.handshake import HandshakeRequest
from airlock.schemas.identity import AgentProfile

logger = logging.getLogger(__name__)

_AIRLOCK_DID_PLACEHOLDER = "did:key:z_airlock"


def _airlock_envelope(request: Request) -> MessageEnvelope:
    kp = request.app.state.airlock_kp
    return create_envelope(sender_did=kp.did)


def _ack(request: Request, session_id: str) -> TransportAck:
    return TransportAck(
        status="ACCEPTED",
        session_id=session_id,
        timestamp=datetime.now(timezone.utc),
        envelope=_airlock_envelope(request),
    )


def _nack(request: Request, reason: str, error_code: str, session_id: str | None = None) -> TransportNack:
    return TransportNack(
        status="REJECTED",
        session_id=session_id,
        reason=reason,
        error_code=error_code,
        timestamp=datetime.now(timezone.utc),
        envelope=_airlock_envelope(request),
    )


# ---------------------------------------------------------------------------
# POST /resolve
# ---------------------------------------------------------------------------

async def handle_resolve(target_did: str, request: Request) -> dict:
    """Look up an agent by DID and return its profile."""
    registry: dict = request.app.state.agent_registry
    profile: AgentProfile | None = registry.get(target_did)

    session_id = str(uuid.uuid4())
    event_bus = request.app.state.event_bus
    event_bus.publish(
        ResolveRequested(
            session_id=session_id,
            timestamp=datetime.now(timezone.utc),
            target_did=target_did,
        )
    )

    if profile is None:
        return {"found": False, "did": target_did}
    return {"found": True, "profile": profile.model_dump(mode="json")}


# ---------------------------------------------------------------------------
# POST /handshake
# ---------------------------------------------------------------------------

async def handle_handshake(
    body: HandshakeRequest,
    request: Request,
    callback_url: str | None = None,
) -> TransportAck | TransportNack:
    """Verify the initiator's signature then publish HandshakeReceived."""
    session_id = body.session_id or str(uuid.uuid4())

    # Signature check — this is the gateway's synchronous gate
    try:
        verify_key = resolve_public_key(body.initiator.did)
        valid = verify_model(body, verify_key)
    except Exception as exc:
        logger.debug("Signature resolution error for %s: %s", body.initiator.did, exc)
        valid = False

    if not valid:
        logger.info("Handshake NACK: invalid signature from %s", body.initiator.did)
        return _nack(request, "Invalid or missing signature", "INVALID_SIGNATURE", session_id)

    # Publish to event bus — orchestrator handles the rest asynchronously
    event_bus = request.app.state.event_bus
    event_bus.publish(
        HandshakeReceived(
            session_id=session_id,
            timestamp=datetime.now(timezone.utc),
            request=body,
            callback_url=callback_url,
        )
    )

    logger.info("Handshake ACK: session %s from %s", session_id, body.initiator.did)
    return _ack(request, session_id)


# ---------------------------------------------------------------------------
# POST /challenge-response
# ---------------------------------------------------------------------------

async def handle_challenge_response(
    body: ChallengeResponse,
    request: Request,
) -> TransportAck | TransportNack:
    """Verify the response signature then publish ChallengeResponseReceived."""
    session_id = body.session_id

    # Verify signature on the response
    try:
        verify_key = resolve_public_key(body.envelope.sender_did)
        valid = verify_model(body, verify_key)
    except Exception as exc:
        logger.debug("Challenge response sig error: %s", exc)
        valid = False

    if not valid:
        return _nack(request, "Invalid signature on challenge response", "INVALID_SIGNATURE", session_id)

    event_bus = request.app.state.event_bus
    event_bus.publish(
        ChallengeResponseReceived(
            session_id=session_id,
            timestamp=datetime.now(timezone.utc),
            response=body,
        )
    )

    return _ack(request, session_id)


# ---------------------------------------------------------------------------
# POST /register
# ---------------------------------------------------------------------------

async def handle_register(profile: AgentProfile, request: Request) -> dict:
    """Register an agent DID + profile in the in-memory registry."""
    registry: dict = request.app.state.agent_registry
    registry[profile.did.did] = profile
    logger.info("Registered agent: %s", profile.did.did)
    return {"registered": True, "did": profile.did.did}


# ---------------------------------------------------------------------------
# POST /heartbeat
# ---------------------------------------------------------------------------

async def handle_heartbeat(agent_did: str, endpoint_url: str, request: Request) -> dict:
    """Record a liveness ping with a TTL timestamp."""
    heartbeat_store: dict = request.app.state.heartbeat_store
    heartbeat_store[agent_did] = {
        "endpoint_url": endpoint_url,
        "last_seen": datetime.now(timezone.utc).isoformat(),
    }
    return {"acknowledged": True, "agent_did": agent_did}


# ---------------------------------------------------------------------------
# GET /reputation/{did}
# ---------------------------------------------------------------------------

async def handle_get_reputation(did: str, request: Request) -> dict:
    """Return the trust score for an agent DID."""
    reputation = request.app.state.reputation
    score = reputation.get(did)
    if score is None:
        return {"found": False, "did": did, "score": 0.5}
    return {"found": True, "did": did, "score": score.score, "interaction_count": score.interaction_count}


# ---------------------------------------------------------------------------
# GET /session/{session_id}
# ---------------------------------------------------------------------------

async def handle_get_session(session_id: str, request: Request) -> dict:
    """Return the current state of a verification session."""
    session_mgr = request.app.state.session_mgr
    session = await session_mgr.get(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Session not found or expired")
    return {
        "session_id": session.session_id,
        "state": session.state.value,
        "initiator_did": session.initiator_did,
        "target_did": session.target_did,
        "verdict": session.verdict.value if session.verdict else None,
    }


# ---------------------------------------------------------------------------
# GET /health
# ---------------------------------------------------------------------------

async def handle_health(request: Request) -> dict:
    """Gateway health check."""
    return {
        "status": "ok",
        "protocol_version": request.app.state.config.protocol_version,
        "airlock_did": request.app.state.airlock_kp.did,
    }
