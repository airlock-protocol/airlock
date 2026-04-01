from __future__ import annotations

from fastapi import APIRouter, FastAPI, Header, Request
from fastapi.responses import PlainTextResponse

from airlock.gateway.auth import gate_rp_routes
from airlock.gateway.handlers import (
    handle_challenge_response,
    handle_check_revocation,
    handle_feedback,
    handle_get_reputation,
    handle_get_session,
    handle_handshake,
    handle_health,
    handle_heartbeat,
    handle_introspect_trust_token,
    handle_live,
    handle_ready,
    handle_register,
    handle_resolve,
)
from airlock.gateway.metrics import saturation_prometheus_text
from airlock.schemas.challenge import ChallengeResponse
from airlock.schemas.handshake import HandshakeRequest
from airlock.schemas.identity import AgentProfile
from airlock.schemas.reputation import SignedFeedbackReport
from airlock.schemas.requests import HeartbeatRequest, IntrospectRequest, ResolveRequest

router = APIRouter()


@router.post("/resolve")
async def resolve(body: ResolveRequest, request: Request) -> dict:
    return await handle_resolve(body.target_did, request)


@router.post("/handshake")
async def handshake(
    body: HandshakeRequest,
    request: Request,
    x_callback_url: str | None = Header(default=None),
):
    return await handle_handshake(body, request, callback_url=x_callback_url)


@router.post("/challenge-response")
async def challenge_response(body: ChallengeResponse, request: Request):
    return await handle_challenge_response(body, request)


@router.post("/register")
async def register(body: AgentProfile, request: Request) -> dict:
    return await handle_register(body, request)


@router.post("/feedback")
async def feedback(body: SignedFeedbackReport, request: Request) -> dict:
    return await handle_feedback(body, request)


@router.post("/heartbeat")
async def heartbeat(body: HeartbeatRequest, request: Request) -> dict:
    return await handle_heartbeat(body, request)


@router.get("/revocation/{did:path}")
async def check_revocation(did: str, request: Request) -> dict:
    return await handle_check_revocation(did, request)


@router.get("/reputation/{did:path}")
async def get_reputation(did: str, request: Request) -> dict:
    return await handle_get_reputation(did, request)


@router.get("/session/{session_id}")
async def get_session(session_id: str, request: Request) -> dict:
    return await handle_get_session(session_id, request)


@router.get("/audit/latest")
async def audit_latest(request: Request) -> dict:
    trail = request.app.state.audit_trail
    length = trail.length
    if length == 0:
        return {"chain_length": 0, "latest_hash": None}
    entries = await trail.get_entries(limit=1, offset=0)
    return {"chain_length": length, "latest_hash": entries[0].entry_hash}


@router.get("/health")
async def health(request: Request) -> dict:
    return await handle_health(request)


@router.get("/live")
async def live(request: Request) -> dict:
    return handle_live(request)


@router.get("/ready")
async def ready(request: Request) -> dict:
    return await handle_ready(request)


@router.get("/metrics")
async def prometheus_metrics(request: Request) -> PlainTextResponse:
    gate_rp_routes(request)
    metrics = getattr(request.app.state, "http_metrics", None)
    if metrics is None:
        return PlainTextResponse("", status_code=503)
    body = metrics.prometheus_text() + saturation_prometheus_text(request.app)
    return PlainTextResponse(
        body,
        media_type="text/plain; version=0.0.4; charset=utf-8",
    )


@router.post("/token/introspect")
async def introspect_trust_token(body: IntrospectRequest, request: Request) -> dict:
    return await handle_introspect_trust_token(body.token, request)


def register_routes(app: FastAPI) -> None:
    app.include_router(router)
    from airlock.gateway.ws import router as ws_router

    app.include_router(ws_router)
