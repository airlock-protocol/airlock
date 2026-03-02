from __future__ import annotations

from fastapi import APIRouter, FastAPI, Header, Request

from airlock.gateway.handlers import (
    handle_challenge_response,
    handle_get_reputation,
    handle_get_session,
    handle_handshake,
    handle_health,
    handle_heartbeat,
    handle_register,
    handle_resolve,
)
from airlock.schemas.challenge import ChallengeResponse
from airlock.schemas.handshake import HandshakeRequest
from airlock.schemas.identity import AgentProfile

router = APIRouter()


@router.post("/resolve")
async def resolve(body: dict, request: Request) -> dict:
    return await handle_resolve(body["target_did"], request)


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


@router.post("/heartbeat")
async def heartbeat(body: dict, request: Request) -> dict:
    return await handle_heartbeat(body["agent_did"], body["endpoint_url"], request)


@router.get("/reputation/{did:path}")
async def get_reputation(did: str, request: Request) -> dict:
    return await handle_get_reputation(did, request)


@router.get("/session/{session_id}")
async def get_session(session_id: str, request: Request) -> dict:
    return await handle_get_session(session_id, request)


@router.get("/health")
async def health(request: Request) -> dict:
    return await handle_health(request)


def register_routes(app: FastAPI) -> None:
    app.include_router(router)
