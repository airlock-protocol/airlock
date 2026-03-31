"""Admin API gated by ``AIRLOCK_ADMIN_TOKEN`` (Bearer)."""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field

from airlock.reputation.scoring import INITIAL_SCORE
from airlock.schemas.identity import AgentProfile
from airlock.schemas.reputation import TrustScore

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/admin", tags=["admin"])
_bearer = HTTPBearer(auto_error=False)


class AdminSessionSample(BaseModel):
    session_id: str
    state: str
    initiator_did: str
    target_did: str


class SessionsListResponse(BaseModel):
    active_count: int
    sample: list[AdminSessionSample] = Field(default_factory=list)


async def require_admin_token(
    request: Request,
    creds: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
) -> None:
    expected = (request.app.state.config.admin_token or "").strip()
    if not expected:
        raise HTTPException(status_code=403, detail="Admin API is disabled")
    if creds is None or creds.scheme.lower() != "bearer":
        raise HTTPException(status_code=401, detail="Missing or invalid Authorization header")
    if creds.credentials != expected:
        raise HTTPException(status_code=403, detail="Invalid admin token")


@router.get("/sessions", response_model=SessionsListResponse)
async def list_sessions(
    request: Request,
    _: Annotated[None, Depends(require_admin_token)],
    limit: int = 20,
) -> SessionsListResponse:
    mgr = request.app.state.session_mgr
    active = await mgr.active_sessions()
    sample = [
        AdminSessionSample(
            session_id=s.session_id,
            state=s.state.value,
            initiator_did=s.initiator_did,
            target_did=s.target_did,
        )
        for s in active[: max(1, min(limit, 100))]
    ]
    return SessionsListResponse(active_count=len(active), sample=sample)


@router.delete("/sessions/{session_id}", response_model=dict[str, Any])
async def delete_session(
    session_id: str,
    request: Request,
    _: Annotated[None, Depends(require_admin_token)],
) -> dict[str, Any]:
    await request.app.state.session_mgr.delete(session_id)
    return {"deleted": True, "session_id": session_id}


@router.get("/agents", response_model=dict[str, Any])
async def list_agents(
    request: Request,
    _: Annotated[None, Depends(require_admin_token)],
    offset: int = 0,
    limit: int = 50,
) -> dict[str, Any]:
    registry: dict[str, AgentProfile] = request.app.state.agent_registry
    items = list(registry.items())
    total = len(items)
    slice_ = items[offset : offset + max(1, min(limit, 500))]
    return {
        "total": total,
        "offset": offset,
        "limit": limit,
        "agents": [
            {"did": did, "profile": prof.model_dump(mode="json")}
            for did, prof in slice_
        ],
    }


@router.delete("/agents/{did:path}", response_model=dict[str, Any])
async def delete_agent(
    did: str,
    request: Request,
    _: Annotated[None, Depends(require_admin_token)],
) -> dict[str, Any]:
    registry: dict[str, AgentProfile] = request.app.state.agent_registry
    registry.pop(did, None)
    request.app.state.agent_store.delete(did)
    logger.info("Admin removed agent from registry: %s", did)
    return {"deleted": True, "did": did}


@router.post("/revoke/{did:path}", response_model=dict[str, Any])
async def revoke_agent(
    did: str,
    request: Request,
    _: Annotated[None, Depends(require_admin_token)],
) -> dict[str, Any]:
    store = request.app.state.revocation_store
    changed = await store.revoke(did)
    return {"revoked": True, "did": did, "changed": changed}


@router.post("/unrevoke/{did:path}", response_model=dict[str, Any])
async def unrevoke_agent(
    did: str,
    request: Request,
    _: Annotated[None, Depends(require_admin_token)],
) -> dict[str, Any]:
    store = request.app.state.revocation_store
    changed = await store.unrevoke(did)
    return {"unrevoked": True, "did": did, "changed": changed}


@router.get("/revoked", response_model=dict[str, Any])
async def list_revoked(
    request: Request,
    _: Annotated[None, Depends(require_admin_token)],
) -> dict[str, Any]:
    store = request.app.state.revocation_store
    revoked = await store.list_revoked()
    return {"count": len(revoked), "revoked": revoked}


@router.post("/reputation/{did:path}/reset", response_model=dict[str, Any])
async def reset_reputation(
    did: str,
    request: Request,
    _: Annotated[None, Depends(require_admin_token)],
) -> dict[str, Any]:
    now = datetime.now(UTC)
    score = TrustScore(
        agent_did=did,
        score=INITIAL_SCORE,
        interaction_count=0,
        successful_verifications=0,
        failed_verifications=0,
        last_interaction=None,
        decay_rate=0.02,
        created_at=now,
        updated_at=now,
    )
    request.app.state.reputation.upsert(score)
    return {"reset": True, "did": did, "score": INITIAL_SCORE}
