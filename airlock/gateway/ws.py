"""WebSocket push for verification session updates (alternative to polling GET /session)."""

from __future__ import annotations

import asyncio
import logging

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from airlock.gateway.auth import (
    build_session_payload,
    parse_session_view_token_raw,
    session_view_secret_configured,
    verify_service_bearer_token,
    ws_session_bearer_token,
)
from airlock.schemas.session import VerificationState

logger = logging.getLogger(__name__)

router = APIRouter()


def _ws_allow_and_full(websocket: WebSocket, session_id: str) -> tuple[bool, bool]:
    """Return (allowed, include_trust_token)."""
    cfg = websocket.app.state.config
    bearer = ws_session_bearer_token(
        websocket.headers.get("authorization"),
        websocket.query_params.get("token")
        or websocket.query_params.get("session_view_token"),
    )
    if verify_service_bearer_token(cfg, bearer):
        return True, True
    if parse_session_view_token_raw(cfg, bearer, session_id):
        return True, True
    if session_view_secret_configured(cfg) or cfg.is_production:
        return False, False
    return True, False


@router.websocket("/ws/session/{session_id}")
async def watch_session(websocket: WebSocket, session_id: str) -> None:
    await websocket.accept()
    allowed, include_full = _ws_allow_and_full(websocket, session_id)
    if not allowed:
        await websocket.send_json({"error": "unauthorized", "session_id": session_id})
        await websocket.close(code=4401)
        return

    session_mgr = websocket.app.state.session_mgr
    queue = await session_mgr.subscribe(session_id)
    try:
        cur = await session_mgr.get(session_id)
        if cur is None:
            await websocket.send_json({"error": "session_not_found", "session_id": session_id})
            await websocket.close(code=4404)
            return
        await websocket.send_json(
            {
                "type": "session",
                "payload": build_session_payload(cur, include_trust_token=include_full),
            }
        )
        terminal = {
            VerificationState.SEALED,
            VerificationState.FAILED,
        }
        while True:
            try:
                session = await asyncio.wait_for(queue.get(), timeout=30.0)
            except asyncio.TimeoutError:
                cur2 = await session_mgr.get(session_id)
                if cur2 is None:
                    await websocket.send_json({"type": "closed", "reason": "expired"})
                    await websocket.close()
                    return
                continue
            await websocket.send_json(
                {
                    "type": "session",
                    "payload": build_session_payload(
                        session, include_trust_token=include_full
                    ),
                }
            )
            if session.state in terminal:
                await websocket.close()
                return
    except WebSocketDisconnect:
        logger.debug("WS client disconnected session %s", session_id)
    finally:
        await session_mgr.unsubscribe(session_id, queue)
