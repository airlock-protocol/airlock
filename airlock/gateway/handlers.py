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
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from airlock.pow import Argon2idPowChallenge, PowChallenge

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
from airlock.schemas.reputation import SignedFeedbackReport, TrustScore
from airlock.schemas.requests import HeartbeatRequest
from airlock.schemas.session import VerificationSession, VerificationState
from airlock.schemas.verdict import TrustVerdict

logger = logging.getLogger(__name__)


def _extract_bearer_token(request: Request) -> str | None:
    """Extract an OAuth bearer token from the Authorization header, if present."""
    auth_header = request.headers.get("authorization", "")
    if auth_header.lower().startswith("bearer "):
        return auth_header[7:].strip()
    return None


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
# GET /pow-challenge
# ---------------------------------------------------------------------------


async def handle_pow_challenge(request: Request) -> JSONResponse:
    """Issue a PoW challenge for handshake anti-Sybil protection.

    When ``pow_algorithm`` is ``"argon2id"``, issues a memory-hard Argon2id
    challenge; otherwise falls back to SHA-256 Hashcash.
    """
    from airlock.config import get_config
    from airlock.pow import issue_argon2id_challenge, issue_pow_challenge

    cfg = get_config()

    challenge: PowChallenge | Argon2idPowChallenge
    if cfg.pow_algorithm == "argon2id":
        challenge = issue_argon2id_challenge(
            preset=cfg.pow_argon2id_preset,
            difficulty=cfg.pow_difficulty,
            ttl=cfg.pow_ttl_seconds,
            pre_filter_bits=cfg.pow_argon2id_pre_filter_bits,
        )
    else:
        challenge = issue_pow_challenge(
            difficulty=cfg.pow_difficulty,
            ttl=cfg.pow_ttl_seconds,
        )

    # Store challenge for later verification
    pow_store = getattr(request.app.state, "pow_challenges", None)
    if pow_store is not None:
        pow_store[challenge.challenge_id] = challenge

    return JSONResponse(challenge.model_dump())


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

    resolve_chain_id: str | None = None
    resolve_chain_registry = getattr(request.app.state, "chain_registry", None)
    if resolve_chain_registry is not None:
        resolve_chain_id = resolve_chain_registry.get_chain_id_for_did(target_did)

    _audit_bg(
        request,
        event_type="agent_resolved",
        actor_did=target_did,
        detail={"found": profile is not None, "source": registry_source},
        rotation_chain_id=resolve_chain_id,
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

    # Ensure rotation chain exists for this initiator (idempotent)
    chain_registry = getattr(request.app.state, "chain_registry", None)
    if chain_registry is not None:
        try:
            verify_key = resolve_public_key(body.initiator.did)
            chain_registry.register_chain(body.initiator.did, bytes(verify_key))
        except Exception:
            pass  # Best-effort; chain registration may already exist

    # --- Proof-of-Work verification (anti-Sybil, v0.2) ---
    from airlock.config import get_config

    cfg = get_config()
    if cfg.pow_required and body.pow is None:
        return JSONResponse(
            {"error": "proof_of_work_required", "detail": "PoW solution required for handshake"},
            status_code=400,
        )
    if body.pow is not None:
        from airlock.pow import verify_pow_with_store

        pow_store = getattr(request.app.state, "pow_challenges", None)
        if pow_store is not None:
            # Use bounded semaphore for Argon2id verification
            semaphore = getattr(request.app.state, "argon2id_semaphore", None)
            if semaphore is not None and body.pow.algorithm == "argon2id":
                timeout = cfg.pow_argon2id_verify_timeout_seconds
                try:
                    async with asyncio.timeout(timeout):
                        async with semaphore:
                            ok, reason = verify_pow_with_store(body.pow, pow_store)
                except TimeoutError:
                    return JSONResponse(
                        {
                            "error": "pow_verification_timeout",
                            "detail": "PoW verification timed out",
                            "status_code": 503,
                        },
                        status_code=503,
                    )
            else:
                ok, reason = verify_pow_with_store(body.pow, pow_store)
            if not ok:
                error_map: dict[str, tuple[str, int]] = {
                    "unknown_challenge": ("Challenge ID not recognised or already used", 400),
                    "expired_challenge": ("PoW challenge has expired", 400),
                    "invalid_proof": ("Proof-of-work verification failed", 400),
                    "pre_filter_failed": ("Proof-of-work pre-filter check failed", 400),
                    "bound_did_mismatch": ("PoW bound to a different DID", 400),
                    "algorithm_mismatch": ("PoW algorithm does not match challenge", 400),
                }
                detail, status = error_map.get(reason or "", ("PoW verification failed", 400))
                return JSONResponse(
                    {"error": f"pow_{reason}", "detail": detail, "status_code": status},
                    status_code=status,
                )
        else:
            # Fallback: no challenge store available — hash-only check
            from airlock.pow import verify_pow

            if not verify_pow(body.pow):
                return JSONResponse(
                    {"error": "pow_invalid", "detail": "Proof-of-work verification failed"},
                    status_code=400,
                )

    # Resolve rotation chain_id for this initiator DID (no-op when registry absent)
    chain_id: str | None = None
    chain_registry = getattr(request.app.state, "chain_registry", None)
    if chain_registry is not None:
        chain_id = chain_registry.get_chain_id_for_did(body.initiator.did)

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
            rotation_chain_id=chain_id,
        )
    )

    # Publish to event bus — orchestrator handles the rest asynchronously
    bearer_token = _extract_bearer_token(request)
    event_bus = request.app.state.event_bus
    if not event_bus.try_publish(
        HandshakeReceived(
            session_id=session_id,
            timestamp=datetime.now(UTC),
            request=body,
            callback_url=callback_url,
            bearer_token=bearer_token,
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
        rotation_chain_id=chain_id,
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

    # Auto-register rotation chain so key rotation works for this DID
    chain_registry = getattr(request.app.state, "chain_registry", None)
    if chain_registry is not None:
        try:
            verify_key = resolve_public_key(profile.did.did)
            chain_registry.register_chain(profile.did.did, bytes(verify_key))
        except Exception as exc:
            logger.debug("Chain registration skipped for %s: %s", profile.did.did, exc)

    register_chain_id: str | None = None
    if chain_registry is not None:
        register_chain_id = chain_registry.get_chain_id_for_did(profile.did.did)

    _audit_bg(
        request,
        event_type="agent_registered",
        actor_did=profile.did.did,
        detail={"display_name": profile.display_name},
        rotation_chain_id=register_chain_id,
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
    """Return the trust score for an agent DID.

    When a rotation chain registry is available, resolves the DID through
    the chain so that reputation lookups work for both current and
    historical DIDs in the same rotation chain.
    """
    reputation = request.app.state.reputation
    rep_did = did
    chain_registry = getattr(request.app.state, "chain_registry", None)
    if chain_registry is not None:
        chain = chain_registry.get_chain_by_did(did)
        if chain is not None:
            rep_did = chain.current_did

    score = reputation.get(rep_did)
    if score is None:
        return {"found": False, "did": did, "score": 0.5}
    return {
        "found": True,
        "did": did,
        "score": score.score,
        "interaction_count": score.interaction_count,
    }


# ---------------------------------------------------------------------------
# GET /audit/entries  (chain-filtered audit queries)
# ---------------------------------------------------------------------------


async def handle_audit_entries(request: Request) -> dict[str, Any]:
    """Return audit entries filtered by chain_id and/or actor DID.

    Query parameters:
        chain_id: filter by rotation_chain_id (hex)
        did: filter by actor_did
        limit: max entries to return (default 100, max 1000)
        offset: pagination offset (default 0)
    """
    chain_id_filter = request.query_params.get("chain_id")
    did_filter = request.query_params.get("did")

    try:
        limit = min(int(request.query_params.get("limit", "100")), 1000)
    except (ValueError, TypeError):
        limit = 100
    try:
        offset = max(int(request.query_params.get("offset", "0")), 0)
    except (ValueError, TypeError):
        offset = 0

    trail = getattr(request.app.state, "audit_trail", None)
    if trail is None:
        raise HTTPException(status_code=503, detail="Audit trail not available")

    entries = await trail.get_entries_filtered(
        chain_id=chain_id_filter,
        actor_did=did_filter,
        limit=limit,
        offset=offset,
    )
    return {
        "entries": [e.model_dump(mode="json") for e in entries],
        "limit": limit,
        "offset": offset,
        "filters": {
            "chain_id": chain_id_filter,
            "did": did_filter,
        },
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
    """Decode and validate a trust JWT using the gateway secret (debug / Relying Party).

    When the gateway's revocation store is available, an additional check
    ensures the token's subject DID has not been revoked or suspended.
    """
    from jwt import PyJWTError

    from airlock.trust_jwt import TokenRevokedError, decode_trust_token

    gate_rp_routes(request)

    secret = (request.app.state.config.trust_token_secret or "").strip()
    if not secret:
        raise HTTPException(
            status_code=503,
            detail="Trust tokens are not configured (set AIRLOCK_TRUST_TOKEN_SECRET)",
        )

    revocation_store = getattr(request.app.state, "revocation_store", None)

    try:
        claims = decode_trust_token(
            token,
            secret,
            revocation_store=revocation_store,
        )
    except TokenRevokedError:
        return {"active": False, "reason": "did_revoked"}
    except PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    return {"active": True, "claims": claims}


# ---------------------------------------------------------------------------
# GET /crl  (public CRL endpoint)
# ---------------------------------------------------------------------------


async def handle_crl(request: Request) -> JSONResponse:
    """Return the current signed CRL with caching headers.

    Public, unauthenticated endpoint. Supports ETag / If-None-Match
    for efficient polling.
    """
    crl_gen = getattr(request.app.state, "crl_generator", None)
    if crl_gen is None:
        return JSONResponse(
            {
                "error": "crl_unavailable",
                "detail": "CRL service not configured",
                "status_code": 503,
            },
            status_code=503,
        )

    crl = await crl_gen.get_or_generate()

    etag = f'"{crl.crl_number}"'

    # Support conditional GET: If-None-Match
    if_none_match = request.headers.get("if-none-match")
    if if_none_match and if_none_match.strip() == etag:
        return JSONResponse(content=None, status_code=304, headers={"ETag": etag})

    cfg = request.app.state.config
    cache_control = f"max-age={cfg.crl_update_interval_seconds}, must-revalidate"

    return JSONResponse(
        content=crl.model_dump(mode="json"),
        headers={
            "Cache-Control": cache_control,
            "ETag": etag,
        },
    )


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


# ---------------------------------------------------------------------------
# POST /rotate-key
# ---------------------------------------------------------------------------


async def handle_rotate_key(
    body: dict[str, Any],
    request: Request,
) -> dict[str, Any]:
    """Process a signed key rotation request.

    Validates the old-key signature, checks pre-rotation commitment (if
    any), performs first-write-wins rotation, and transfers trust state
    via the rotation chain.
    """
    from airlock.config import get_config
    from airlock.rotation.chain import RotationChainRegistry
    from airlock.rotation.precommit import PreRotationCommitment, verify_commitment
    from airlock.schemas.rotation import KeyRotationRequest

    cfg = get_config()
    if not cfg.key_rotation_enabled:
        raise HTTPException(status_code=503, detail="Key rotation is not enabled")

    # Parse the request
    try:
        rotation_req = KeyRotationRequest(**body)
    except Exception as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    if not _is_valid_did(rotation_req.old_did):
        raise HTTPException(status_code=422, detail="Invalid old_did format")
    if not _is_valid_did(rotation_req.new_did):
        raise HTTPException(status_code=422, detail="Invalid new_did format")
    if rotation_req.old_did == rotation_req.new_did:
        raise HTTPException(status_code=422, detail="old_did and new_did must differ")

    # Verify old-key signature
    try:
        verify_key = resolve_public_key(rotation_req.old_did)
        sig_payload = rotation_req.model_dump(mode="json")
        sig_payload.pop("signature", None)
        from airlock.crypto.signing import verify_signature

        valid = verify_signature(sig_payload, rotation_req.signature, verify_key)
    except Exception as exc:
        logger.debug("Rotation signature error: %s", exc)
        valid = False

    if not valid:
        raise HTTPException(status_code=401, detail="Invalid signature (old key)")

    # Replay check
    if not await request.app.state.nonce_guard.check_and_remember(
        rotation_req.old_did, rotation_req.nonce
    ):
        raise HTTPException(status_code=400, detail="Nonce replay detected")

    chain_registry: RotationChainRegistry | None = getattr(
        request.app.state, "chain_registry", None
    )
    if chain_registry is None:
        raise HTTPException(status_code=503, detail="Chain registry not available")

    # Verify chain_id matches
    chain_record = chain_registry.get_chain(rotation_req.rotation_chain_id)
    if chain_record is None:
        raise HTTPException(status_code=404, detail="Unknown rotation chain")
    if chain_record.current_did != rotation_req.old_did:
        raise HTTPException(
            status_code=409,
            detail="old_did does not match chain's current DID",
        )

    # Extract new public key bytes from new_did
    new_verify_key = resolve_public_key(rotation_req.new_did)
    new_public_key_bytes = bytes(new_verify_key)

    # Check pre-rotation commitment BEFORE first-write-wins
    from airlock.rotation.precommit_store import PreCommitmentStore

    commitment_store: PreCommitmentStore = request.app.state.precommit_store
    existing_commitment = commitment_store.get(rotation_req.rotation_chain_id)

    # Mandatory pre-commitment check for higher tiers
    reputation = request.app.state.reputation
    trust_score = reputation.get(rotation_req.old_did)
    current_tier = trust_score.tier if trust_score else 0

    if current_tier >= cfg.pre_rotation_required_tier and existing_commitment is None:
        raise HTTPException(
            status_code=403,
            detail="Pre-rotation commitment required for this trust tier",
        )

    if existing_commitment is not None:
        if not verify_commitment(existing_commitment, new_public_key_bytes):
            raise HTTPException(
                status_code=403,
                detail="New public key does not match pre-rotation commitment",
            )

    # Rotation rate check
    if chain_registry.check_rotation_rate(
        rotation_req.rotation_chain_id,
        max_per_24h=cfg.key_rotation_max_per_24h,
    ):
        raise HTTPException(
            status_code=429,
            detail="Rotation rate limit exceeded (max per 24h)",
        )

    # First-write-wins rotation
    try:
        updated_record = chain_registry.rotate(
            old_did=rotation_req.old_did,
            new_did=rotation_req.new_did,
            chain_id=rotation_req.rotation_chain_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc

    # Rotate out old DID in revocation store (no cascade)
    revocation_store = request.app.state.revocation_store
    reason = rotation_req.reason
    if reason == "compromise":
        grace_seconds = 0
    else:
        grace_seconds = cfg.key_rotation_grace_seconds
    await revocation_store.rotate_out(rotation_req.old_did, grace_seconds=grace_seconds)

    # On compromise: force immediate CRL regeneration so relying parties see it
    if reason == "compromise":
        crl_gen = getattr(request.app.state, "crl_generator", None)
        if crl_gen is not None:
            try:
                await crl_gen.force_regenerate()
                logger.info("CRL force-regenerated after key compromise: %s", rotation_req.old_did)
            except Exception as exc:
                logger.error("CRL force-regeneration failed: %s", exc)

    # Transfer trust score via chain_id with penalty
    if trust_score is not None:
        penalty = cfg.key_rotation_trust_penalty
        new_score_val = max(0.0, trust_score.score - penalty)
        now = datetime.now(UTC)
        new_trust = trust_score.model_copy(
            update={
                "agent_did": rotation_req.new_did,
                "score": new_score_val,
                "rotation_chain_id": rotation_req.rotation_chain_id,
                "updated_at": now,
            }
        )
        reputation.upsert(new_trust)
    else:
        # Create a default score for the new DID with chain_id
        now = datetime.now(UTC)
        from airlock.reputation.scoring import INITIAL_SCORE

        new_trust = TrustScore(
            agent_did=rotation_req.new_did,
            score=INITIAL_SCORE,
            rotation_chain_id=rotation_req.rotation_chain_id,
            created_at=now,
            updated_at=now,
        )
        reputation.upsert(new_trust)

    # Handle chained commitment (N+2)
    if rotation_req.next_key_commitment:
        commitment_store.put(
            rotation_req.rotation_chain_id,
            PreRotationCommitment(
                alg="sha256",
                digest=rotation_req.next_key_commitment,
                committed_at=datetime.now(UTC),
                committed_by_did=rotation_req.new_did,
                signature="",  # Commitment is embedded in the signed rotation request
            ),
        )
    else:
        # Clear the used commitment
        commitment_store.delete(rotation_req.rotation_chain_id)

    _audit_bg(
        request,
        event_type="key_rotated",
        actor_did=rotation_req.old_did,
        subject_did=rotation_req.new_did,
        detail={
            "chain_id": rotation_req.rotation_chain_id,
            "reason": reason,
            "rotation_count": updated_record.rotation_count,
        },
        rotation_chain_id=rotation_req.rotation_chain_id,
    )

    grace_until_dt = datetime.fromtimestamp(
        time.time() + grace_seconds, tz=UTC
    ) if grace_seconds > 0 else None

    from airlock.schemas.rotation import KeyRotationResponse

    resp = KeyRotationResponse(
        rotated=True,
        chain_id=rotation_req.rotation_chain_id,
        old_did=rotation_req.old_did,
        new_did=rotation_req.new_did,
        rotation_count=updated_record.rotation_count,
        grace_until=grace_until_dt,
    )
    return resp.model_dump(mode="json")


# ---------------------------------------------------------------------------
# POST /pre-commit-key
# ---------------------------------------------------------------------------


async def handle_pre_commit_key(
    body: dict[str, Any],
    request: Request,
) -> dict[str, Any]:
    """Store a pre-rotation commitment for future key rotation.

    The commitment is a SHA-256 hash of the agent's next public key. Once
    stored, it cannot be updated for a configurable lockout period
    (default 72 hours).
    """
    from airlock.config import get_config
    from airlock.rotation.precommit import (
        PreRotationCommitment,
        can_update_commitment,
    )
    from airlock.schemas.rotation import PreCommitKeyRequest

    cfg = get_config()
    if not cfg.key_rotation_enabled:
        raise HTTPException(status_code=503, detail="Key rotation is not enabled")

    try:
        commit_req = PreCommitKeyRequest(**body)
    except Exception as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    if not _is_valid_did(commit_req.did):
        raise HTTPException(status_code=422, detail="Invalid DID format")

    # Verify signature
    try:
        verify_key = resolve_public_key(commit_req.did)
        sig_payload = commit_req.model_dump(mode="json")
        sig_payload.pop("signature", None)
        from airlock.crypto.signing import verify_signature

        valid = verify_signature(sig_payload, commit_req.signature, verify_key)
    except Exception as exc:
        logger.debug("Pre-commit signature error: %s", exc)
        valid = False

    if not valid:
        raise HTTPException(status_code=401, detail="Invalid signature")

    # Replay check
    if not await request.app.state.nonce_guard.check_and_remember(
        commit_req.did, commit_req.nonce
    ):
        raise HTTPException(status_code=400, detail="Nonce replay detected")

    # Resolve chain_id for this DID
    chain_registry = getattr(request.app.state, "chain_registry", None)
    if chain_registry is None:
        raise HTTPException(status_code=503, detail="Chain registry not available")

    chain_id = chain_registry.get_chain_id_for_did(commit_req.did)
    if chain_id is None:
        raise HTTPException(status_code=404, detail="DID not registered in any chain")

    # Check existing commitment and lockout
    from airlock.rotation.precommit_store import PreCommitmentStore

    commitment_store: PreCommitmentStore = request.app.state.precommit_store
    existing = commitment_store.get(chain_id)
    if existing is not None:
        if not can_update_commitment(existing, lockout_hours=cfg.pre_rotation_update_lockout_hours):
            raise HTTPException(
                status_code=429,
                detail="Commitment update locked (waiting period not elapsed)",
            )

    now = datetime.now(UTC)
    commitment = PreRotationCommitment(
        alg=commit_req.alg,
        digest=commit_req.digest,
        committed_at=now,
        committed_by_did=commit_req.did,
        signature=commit_req.signature,
    )
    commitment_store.put(chain_id, commitment)

    _audit_bg(
        request,
        event_type="pre_rotation_committed",
        actor_did=commit_req.did,
        detail={"chain_id": chain_id, "alg": commit_req.alg},
        rotation_chain_id=chain_id,
    )

    from airlock.schemas.rotation import PreCommitKeyResponse

    resp = PreCommitKeyResponse(
        committed=True,
        did=commit_req.did,
        alg=commit_req.alg,
        digest=commit_req.digest,
        committed_at=now,
    )
    return resp.model_dump(mode="json")
