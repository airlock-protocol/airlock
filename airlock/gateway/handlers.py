"""Request handlers for the Airlock gateway.

Every handler follows the same validation pipeline:
  1. Parse body (Pydantic — already done by FastAPI)
  2. Verify Ed25519 signature
  3. Publish VerificationEvent to EventBus
  4. Return TransportAck or TransportNack

Handlers receive the parsed body + app.state. Most avoid extra I/O beyond the
event bus; ``handle_resolve`` may call a configured upstream registry via HTTP.
"""

from __future__ import annotations

import asyncio
import logging
import re
import time
import uuid
from datetime import UTC, datetime
from typing import Any

from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse

_DID_PATTERN = re.compile(r"^did:key:z[a-km-zA-HJ-NP-Z1-9]+$")


def _is_valid_did(did: str) -> bool:
    """Validate DID format (did:key with base58btc multibase)."""
    return bool(_DID_PATTERN.match(did))


from airlock.crypto.keys import resolve_public_key
from airlock.crypto.signing import verify_model
from airlock.gateway.auth import (
    build_session_payload,
    gate_rp_routes,
    require_session_access,
    session_access_allows_full_payload,
)
from airlock.gateway.error_handlers import RateLimitExceeded, _rate_limit_headers
from airlock.gateway.handshake_precheck import handshake_transport_precheck
from airlock.registry.remote import resolve_remote_profile
from airlock.schemas.challenge import ChallengeResponse
from airlock.schemas.envelope import (
    MessageEnvelope,
    TransportAck,
    TransportNack,
    create_envelope,
)
from airlock.schemas.events import (
    ChallengeResponseReceived,
    HandshakeReceived,
    ResolveRequested,
)
from airlock.schemas.handshake import HandshakeRequest
from airlock.schemas.identity import AgentProfile
from airlock.schemas.reputation import SignedFeedbackReport
from airlock.schemas.requests import HeartbeatRequest
from airlock.schemas.session import VerificationSession, VerificationState
from airlock.schemas.verdict import TrustVerdict

logger = logging.getLogger(__name__)


def _audit_bg(request: Request, **kwargs: object) -> None:
    """Fire-and-forget audit trail append (non-blocking)."""
    trail = getattr(request.app.state, "audit_trail", None)
    if trail is not None:
        asyncio.ensure_future(trail.append(**kwargs))


def _client_ip(request: Request) -> str:
    if request.client and request.client.host:
        return request.client.host
    return "unknown"


def _airlock_envelope(request: Request) -> MessageEnvelope:
    kp = request.app.state.airlock_kp
    return create_envelope(sender_did=kp.did)


def _ack(
    request: Request,
    session_id: str,
    *,
    session_view_token: str | None = None,
) -> TransportAck:
    return TransportAck(
        status="ACCEPTED",
        session_id=session_id,
        timestamp=datetime.now(UTC),
        envelope=_airlock_envelope(request),
        session_view_token=session_view_token,
    )


def _nack(
    request: Request,
    reason: str,
    error_code: str,
    session_id: str | None = None,
) -> TransportNack:
    return TransportNack(
        status="REJECTED",
        session_id=session_id,
        reason=reason,
        error_code=error_code,
        timestamp=datetime.now(UTC),
        envelope=_airlock_envelope(request),
    )


# ---------------------------------------------------------------------------
# POST /resolve
# ---------------------------------------------------------------------------


async def handle_resolve(target_did: str, request: Request) -> dict[str, Any]:
    """Look up an agent by DID and return its profile."""
    registry: dict[str, AgentProfile] = request.app.state.agent_registry
    profile: AgentProfile | None = registry.get(target_did)
    registry_source: str | None = "local" if profile is not None else None

    session_id = str(uuid.uuid4())
    event_bus = request.app.state.event_bus
    event_bus.try_publish(
        ResolveRequested(
            session_id=session_id,
            timestamp=datetime.now(UTC),
            target_did=target_did,
        )
    )

    if profile is None:
        http_client = getattr(request.app.state, "registry_http_client", None)
        if http_client is not None:
            profile = await resolve_remote_profile(http_client, target_did)
            if profile is not None:
                registry_source = "remote"

    _audit_bg(
        request,
        event_type="agent_resolved",
        actor_did=target_did,
        detail={"found": profile is not None, "source": registry_source},
    )

    if profile is None:
        return {"found": False, "did": target_did}
    out: dict[str, Any] = {"found": True, "profile": profile.model_dump(mode="json")}
    if registry_source:
        out["registry_source"] = registry_source
    return out


# ---------------------------------------------------------------------------
# POST /handshake
# ---------------------------------------------------------------------------


async def handle_handshake(
    body: HandshakeRequest,
    request: Request,
    callback_url: str | None = None,
) -> TransportAck | TransportNack | JSONResponse:
    """Verify the initiator's signature then publish HandshakeReceived."""
    session_id = body.session_id or str(uuid.uuid4())

    nack = await handshake_transport_precheck(body, request)
    if nack is not None:
        return nack

    session_mgr = request.app.state.session_mgr
    now = datetime.now(UTC)
    await session_mgr.put(
        VerificationSession(
            session_id=session_id,
            state=VerificationState.HANDSHAKE_RECEIVED,
            initiator_did=body.initiator.did,
            target_did=body.intent.target_did,
            callback_url=callback_url,
            created_at=now,
            updated_at=now,
            ttl_seconds=request.app.state.config.session_ttl,
            handshake_request=body,
        )
    )

    # Publish to event bus — orchestrator handles the rest asynchronously
    event_bus = request.app.state.event_bus
    if not event_bus.try_publish(
        HandshakeReceived(
            session_id=session_id,
            timestamp=datetime.now(UTC),
            request=body,
            callback_url=callback_url,
        )
    ):
        return _nack(request, "Event queue saturated", "SERVICE_BUSY", session_id)

    session_view_token: str | None = None
    sv_secret = (request.app.state.config.session_view_secret or "").strip()
    if sv_secret:
        from airlock.trust_jwt import mint_session_view_token  # noqa: PLC0415

        session_view_token = mint_session_view_token(
            session_id=session_id,
            initiator_did=body.initiator.did,
            issuer_did=request.app.state.airlock_kp.did,
            secret=sv_secret,
            ttl_seconds=request.app.state.config.session_ttl,
        )

    _audit_bg(
        request,
        event_type="handshake_initiated",
        actor_did=body.initiator.did,
        subject_did=body.intent.target_did,
        session_id=session_id,
        detail={"action": body.intent.action},
    )
    logger.info("Handshake ACK: session %s from %s", session_id, body.initiator.did)
    return _ack(request, session_id, session_view_token=session_view_token)


# ---------------------------------------------------------------------------
# POST /challenge-response
# ---------------------------------------------------------------------------


async def handle_challenge_response(
    body: ChallengeResponse,
    request: Request,
) -> TransportAck | TransportNack | JSONResponse:
    """Verify the response signature then publish ChallengeResponseReceived."""
    session_id = body.session_id

    ip = _client_ip(request)
    rl_result = await request.app.state.rate_limit_ip.check(f"ip:{ip}:challenge")
    if not rl_result.allowed:
        nack = _nack(request, "Rate limit exceeded", "RATE_LIMIT", session_id)
        return JSONResponse(
            status_code=429,
            content=nack.model_dump(mode="json"),
            headers=_rate_limit_headers(rl_result),
        )

    # Verify signature on the response
    try:
        verify_key = resolve_public_key(body.envelope.sender_did)
        valid = verify_model(body, verify_key)
    except Exception as exc:
        logger.debug("Challenge response sig error: %s", exc)
        valid = False

    if not valid:
        return _nack(
            request,
            "Invalid signature on challenge response",
            "INVALID_SIGNATURE",
            session_id,
        )

    if not await request.app.state.nonce_guard.check_and_remember(
        body.envelope.sender_did, body.envelope.nonce
    ):
        return _nack(request, "Nonce replay detected", "REPLAY", session_id)

    event_bus = request.app.state.event_bus
    if not event_bus.try_publish(
        ChallengeResponseReceived(
            session_id=session_id,
            timestamp=datetime.now(UTC),
            response=body,
        )
    ):
        return _nack(request, "Event queue saturated", "SERVICE_BUSY", session_id)

    return _ack(request, session_id)


# ---------------------------------------------------------------------------
# POST /register
# ---------------------------------------------------------------------------


async def handle_register(profile: AgentProfile, request: Request) -> dict[str, Any]:
    """Register an agent DID + profile in LanceDB and the in-memory cache."""
    # Input validation
    if not _is_valid_did(profile.did.did):
        raise HTTPException(status_code=422, detail="Invalid DID format (expected did:key:z...)")
    if profile.endpoint_url and not profile.endpoint_url.startswith(("http://", "https://")):
        raise HTTPException(status_code=422, detail="endpoint_url must use http:// or https://")

    ip = _client_ip(request)
    rl_result = await request.app.state.rate_limit_ip.check(f"ip:{ip}:register")
    if not rl_result.allowed:
        raise RateLimitExceeded("Rate limit exceeded", rl_result)
    rl_hour = getattr(request.app.state, "rate_limit_register_hour", None)
    if rl_hour is not None:
        rl_hour_result = await rl_hour.check(f"ip:{ip}:register:hour")
        if not rl_hour_result.allowed:
            raise RateLimitExceeded(
                "Registration rate limit exceeded for this IP (hourly cap)",
                rl_hour_result,
            )

    registry: dict[str, AgentProfile] = request.app.state.agent_registry
    registry[profile.did.did] = profile
    request.app.state.agent_store.upsert(profile)
    _audit_bg(
        request,
        event_type="agent_registered",
        actor_did=profile.did.did,
        detail={"display_name": profile.display_name},
    )
    logger.info("Registered agent: %s", profile.did.did)
    return {"registered": True, "did": profile.did.did}


# ---------------------------------------------------------------------------
# POST /feedback
# ---------------------------------------------------------------------------


async def handle_feedback(body: SignedFeedbackReport, request: Request) -> dict[str, Any]:
    """Post-verification reputation signal (Ed25519 signed by reporter DID)."""
    if body.signature is None:
        raise HTTPException(status_code=401, detail="Missing signature on feedback")

    ip = _client_ip(request)
    rl_result = await request.app.state.rate_limit_ip.check(f"ip:{ip}:feedback")
    if not rl_result.allowed:
        raise RateLimitExceeded("Rate limit exceeded", rl_result)

    if body.envelope.sender_did != body.reporter_did:
        raise HTTPException(status_code=400, detail="Envelope sender_did must match reporter_did")
    try:
        verify_key = resolve_public_key(body.reporter_did)
        valid = verify_model(body, verify_key)
    except Exception as exc:
        logger.debug("Feedback sig error: %s", exc)
        valid = False
    if not valid:
        raise HTTPException(status_code=401, detail="Invalid signature on feedback")

    if not await request.app.state.nonce_guard.check_and_remember(
        body.envelope.sender_did, body.envelope.nonce
    ):
        raise HTTPException(status_code=400, detail="Nonce replay detected")

    reputation = request.app.state.reputation
    if body.rating == "negative":
        reputation.apply_verdict(body.subject_did, TrustVerdict.REJECTED)
    elif body.rating == "positive":
        reputation.apply_verdict(body.subject_did, TrustVerdict.VERIFIED)
    return {
        "ok": True,
        "subject_did": body.subject_did,
        "rating": body.rating,
    }


# ---------------------------------------------------------------------------
# POST /heartbeat
# ---------------------------------------------------------------------------


async def handle_heartbeat(body: HeartbeatRequest, request: Request) -> dict[str, Any]:
    """Record a signed liveness ping (Ed25519) bound to ``agent_did``."""
    if body.signature is None:
        raise HTTPException(status_code=401, detail="Missing signature on heartbeat")

    ip = _client_ip(request)
    rl_result = await request.app.state.rate_limit_ip.check(f"ip:{ip}:heartbeat")
    if not rl_result.allowed:
        raise RateLimitExceeded("Rate limit exceeded", rl_result)

    if body.envelope.sender_did != body.agent_did:
        raise HTTPException(status_code=400, detail="Envelope sender_did must match agent_did")
    try:
        verify_key = resolve_public_key(body.agent_did)
        valid = verify_model(body, verify_key)
    except Exception as exc:
        logger.debug("Heartbeat sig error: %s", exc)
        valid = False
    if not valid:
        raise HTTPException(status_code=401, detail="Invalid signature on heartbeat")

    if not await request.app.state.nonce_guard.check_and_remember(
        body.envelope.sender_did, body.envelope.nonce
    ):
        raise HTTPException(status_code=400, detail="Nonce replay detected")

    endpoint_s = str(body.endpoint_url)
    heartbeat_store: dict[str, Any] = request.app.state.heartbeat_store
    heartbeat_store[body.agent_did] = {
        "endpoint_url": endpoint_s,
        "last_seen": datetime.now(UTC).isoformat(),
    }
    return {"acknowledged": True, "agent_did": body.agent_did}


# ---------------------------------------------------------------------------
# GET /revocation/{did}
# ---------------------------------------------------------------------------


async def handle_check_revocation(did: str, request: Request) -> dict[str, Any]:
    """Return whether an agent DID is currently revoked."""
    store = request.app.state.revocation_store
    revoked = await store.is_revoked(did)
    return {"did": did, "revoked": revoked}


# ---------------------------------------------------------------------------
# GET /reputation/{did}
# ---------------------------------------------------------------------------


async def handle_get_reputation(did: str, request: Request) -> dict[str, Any]:
    """Return the trust score for an agent DID."""
    reputation = request.app.state.reputation
    score = reputation.get(did)
    if score is None:
        return {"found": False, "did": did, "score": 0.5}
    return {
        "found": True,
        "did": did,
        "score": score.score,
        "interaction_count": score.interaction_count,
    }


# ---------------------------------------------------------------------------
# GET /session/{session_id}
# ---------------------------------------------------------------------------


async def handle_get_session(session_id: str, request: Request) -> dict[str, Any]:
    """Return the current state of a verification session."""
    session_mgr = request.app.state.session_mgr
    session = await session_mgr.get(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Session not found or expired")
    require_session_access(request, session_id)
    include_token = session_access_allows_full_payload(request, session_id)
    return build_session_payload(session, include_trust_token=include_token)


# ---------------------------------------------------------------------------
# POST /token/introspect
# ---------------------------------------------------------------------------


async def handle_introspect_trust_token(token: str, request: Request) -> dict[str, Any]:
    """Decode and validate a trust JWT using the gateway secret (debug / Relying Party)."""
    from jwt import PyJWTError

    from airlock.trust_jwt import decode_trust_token

    gate_rp_routes(request)

    secret = (request.app.state.config.trust_token_secret or "").strip()
    if not secret:
        raise HTTPException(
            status_code=503,
            detail="Trust tokens are not configured (set AIRLOCK_TRUST_TOKEN_SECRET)",
        )
    try:
        claims = decode_trust_token(token, secret)
    except PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    return {"active": True, "claims": claims}


# ---------------------------------------------------------------------------
# GET /live  (liveness — process up)
# ---------------------------------------------------------------------------


def handle_live(request: Request) -> dict[str, str]:
    return {"status": "live"}


# ---------------------------------------------------------------------------
# GET /ready  (readiness — dependencies)
# ---------------------------------------------------------------------------


async def handle_ready(request: Request) -> dict[str, str]:
    if getattr(request.app.state, "shutting_down", False):
        raise HTTPException(status_code=503, detail="Shutting down")

    rep_ok = ag_ok = bus_ok = redis_ok = True
    try:
        request.app.state.reputation.count()
    except Exception:
        rep_ok = False
    try:
        request.app.state.agent_store.count_rows()
    except Exception:
        ag_ok = False
    try:
        bus_ok = request.app.state.event_bus.is_running
    except Exception:
        bus_ok = False

    redis_client = getattr(request.app.state, "redis_client", None)
    if redis_client is not None:
        try:
            await redis_client.ping()
        except Exception:
            redis_ok = False

    if not (rep_ok and ag_ok and bus_ok and ((redis_client is None) or redis_ok)):
        raise HTTPException(status_code=503, detail="Service not ready")
    return {"status": "ready"}


# ---------------------------------------------------------------------------
# GET /health
# ---------------------------------------------------------------------------


async def handle_health(request: Request) -> dict[str, Any]:
    """Gateway health check (subsystems)."""
    rep_ok = ag_ok = bus_ok = redis_ok = True
    try:
        request.app.state.reputation.count()
    except Exception:
        rep_ok = False
    try:
        request.app.state.agent_store.count_rows()
    except Exception:
        ag_ok = False
    try:
        bus_ok = request.app.state.event_bus.is_running
    except Exception:
        bus_ok = False

    redis_client = getattr(request.app.state, "redis_client", None)
    if redis_client is not None:
        try:
            await redis_client.ping()
        except Exception:
            redis_ok = False

    event_bus = request.app.state.event_bus
    sessions_active = 0
    try:
        sessions_active = len(await request.app.state.session_mgr.active_sessions())
    except Exception:
        pass

    started = getattr(request.app.state, "started_at_monotonic", None)
    uptime_seconds: float | None = None
    if started is not None:
        uptime_seconds = round(time.monotonic() - started, 3)

    status = "ok" if rep_ok and ag_ok and bus_ok and redis_ok else "degraded"
    subsystems: dict[str, Any] = {
        "reputation": rep_ok,
        "agent_registry": ag_ok,
        "event_bus": bus_ok,
        "trust_tokens": bool((request.app.state.config.trust_token_secret or "").strip()),
    }
    if redis_client is not None:
        subsystems["redis"] = redis_ok
    return {
        "status": status,
        "protocol_version": request.app.state.config.protocol_version,
        "airlock_did": request.app.state.airlock_kp.did,
        "subsystems": subsystems,
        "sessions_active": sessions_active,
        "event_bus_queue_depth": event_bus.qsize,
        "event_bus_dead_letters": event_bus.dead_letter_count,
        "uptime_seconds": uptime_seconds,
    }
