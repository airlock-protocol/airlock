"""Gateway gates for a signed handshake (rate limits, signature, envelope, nonce)."""

from __future__ import annotations

import logging
from datetime import UTC, datetime

from fastapi import Request

from airlock.crypto.keys import resolve_public_key
from airlock.crypto.signing import verify_model
from airlock.schemas.envelope import TransportNack, create_envelope
from airlock.schemas.handshake import HandshakeRequest

logger = logging.getLogger(__name__)


def _client_ip(req: Request) -> str:
    if req.client and req.client.host:
        return req.client.host
    return "unknown"


def _handshake_nack(
    request: Request,
    reason: str,
    error_code: str,
    session_id: str | None,
) -> TransportNack:
    kp = request.app.state.airlock_kp
    return TransportNack(
        status="REJECTED",
        session_id=session_id,
        reason=reason,
        error_code=error_code,
        timestamp=datetime.now(UTC),
        envelope=create_envelope(sender_did=kp.did),
    )


async def handshake_transport_precheck(
    body: HandshakeRequest,
    request: Request,
) -> TransportNack | None:
    """Apply the same pre-orchestrator checks as POST /handshake.

    Returns a TransportNack when the request must be rejected; otherwise None.
    """
    session_id = body.session_id or None

    ip = _client_ip(request)
    if not await request.app.state.rate_limit_ip.allow(f"ip:{ip}:any"):
        logger.info("Handshake NACK: IP rate limit %s", ip)
        return _handshake_nack(request, "Rate limit exceeded", "RATE_LIMIT", session_id)

    did_key = f"did:{body.initiator.did}:handshake"
    if not await request.app.state.rate_limit_handshake_did.allow(did_key):
        logger.info("Handshake NACK: DID rate limit %s", body.initiator.did)
        return _handshake_nack(request, "Rate limit exceeded", "RATE_LIMIT", session_id)

    try:
        verify_key = resolve_public_key(body.initiator.did)
        valid = verify_model(body, verify_key)
    except Exception as exc:
        logger.debug("Signature resolution error for %s: %s", body.initiator.did, exc)
        valid = False

    if not valid:
        logger.info("Handshake NACK: invalid signature from %s", body.initiator.did)
        return _handshake_nack(
            request, "Invalid or missing signature", "INVALID_SIGNATURE", session_id
        )

    if body.envelope.sender_did != body.initiator.did:
        return _handshake_nack(
            request,
            "Envelope sender must match initiator DID",
            "INVALID_ENVELOPE",
            session_id,
        )

    nonce_ok = await request.app.state.nonce_guard.check_and_remember(
        body.initiator.did,
        body.envelope.nonce,
    )
    if not nonce_ok:
        logger.info("Handshake NACK: replay %s", body.initiator.did)
        return _handshake_nack(request, "Nonce replay detected", "REPLAY", session_id)

    return None
