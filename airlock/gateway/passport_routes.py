"""Passport (Web Bot Auth) gateway routes.

Serves the hosted key directory and passport status endpoint defined by
draft-meunier-webbotauth-httpsig-directory-00:

- ``GET /.well-known/http-message-signatures-directory`` — JWKS of all
  active (registered, non-revoked) agents in the registry.
- ``GET /.well-known/http-message-signatures-directory-assertions`` —
  tenant-signed possession proofs for those keys
  (draft-singh-webbotauth-hosted-directories-00 section 5).
- ``GET /passport/{did}/status`` — registration, revocation and
  standing summary for one agent DID.

All return 404 while ``passport_enabled`` is off.

Deviation from the directory draft: the draft RECOMMENDS one HTTP message
signature per key over the directory response (tag
``http-message-signatures-directory``) as proof of key possession. A
hosted registry cannot produce those signatures — agents keep their own
private keys — so the directory is served unsigned and possession is
proved by the tenant-signed assertions document instead.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, FastAPI, HTTPException, Request, Response
from nacl.signing import VerifyKey

from airlock.crypto.keys import resolve_public_key
from airlock.gateway.handlers import (
    _is_valid_did,
    handle_check_revocation,
    handle_get_reputation,
)
from airlock.passport.assertions import WELL_KNOWN_ASSERTIONS_PATH
from airlock.passport.base import DIRECTORY_MEDIA_TYPE, WELL_KNOWN_DIRECTORY_PATH
from airlock.passport.directory import build_directory, jwk_thumbprint, key_to_jwk
from airlock.schemas.identity import AgentProfile
from airlock.schemas.passport import (
    AssertionsDocument,
    PassportStatus,
    ReputationSummary,
)

logger = logging.getLogger(__name__)

router = APIRouter()


def _require_passport_enabled(request: Request) -> None:
    config = request.app.state.config
    if not getattr(config, "passport_enabled", False):
        raise HTTPException(status_code=404, detail="Passport feature is not enabled")


async def _active_profiles(request: Request) -> list[AgentProfile]:
    """Registered, active, non-revoked profiles in deterministic order."""
    registry: dict[str, AgentProfile] = request.app.state.agent_registry
    revocation_store = request.app.state.revocation_store
    profiles: list[AgentProfile] = []
    for did in sorted(registry):
        profile = registry[did]
        if profile.status != "active":
            continue
        if await revocation_store.is_revoked(did):
            continue
        profiles.append(profile)
    return profiles


def _cache_headers(request: Request) -> dict[str, str]:
    max_age = request.app.state.config.passport_directory_max_age_seconds
    return {"Cache-Control": f"max-age={max_age}"}


@router.get(WELL_KNOWN_DIRECTORY_PATH)
async def signatures_directory(request: Request) -> Response:
    """JWKS key directory of active registered agents (Web Bot Auth)."""
    _require_passport_enabled(request)

    keys: list[VerifyKey] = []
    for profile in await _active_profiles(request):
        try:
            keys.append(resolve_public_key(profile.did.did))
        except ValueError:
            logger.debug("Skipping non-Ed25519 DID in directory: %s", profile.did.did)
            continue

    directory = build_directory(keys)
    return Response(
        content=directory.model_dump_json(exclude_none=True),
        media_type=DIRECTORY_MEDIA_TYPE,
        headers=_cache_headers(request),
    )


@router.get(WELL_KNOWN_ASSERTIONS_PATH)
async def signatures_directory_assertions(request: Request) -> Response:
    """Tenant-signed directory assertions for the keys in the directory.

    Possession proofs signed by the agents themselves — the registry
    publishes them verbatim and cannot mint them (it holds no agent
    private keys). Served with the same cache policy as the directory.
    """
    _require_passport_enabled(request)

    assertions = [
        profile.passport_assertion
        for profile in await _active_profiles(request)
        if profile.passport_assertion is not None
    ]
    document = AssertionsDocument(assertions=assertions)
    return Response(
        content=document.model_dump_json(),
        media_type="application/json",
        headers=_cache_headers(request),
    )


@router.get("/passport/{did:path}/status")
async def passport_status(did: str, request: Request) -> PassportStatus:
    """Registration + revocation + reputation summary for an agent DID."""
    _require_passport_enabled(request)

    if not _is_valid_did(did):
        raise HTTPException(
            status_code=422, detail="Invalid DID format (expected did:key:z...)"
        )

    # Compose the existing revocation and reputation handlers.
    revocation = await handle_check_revocation(did, request)
    reputation = await handle_get_reputation(did, request)

    registry: dict[str, AgentProfile] = request.app.state.agent_registry
    thumbprint: str | None = None
    try:
        thumbprint = jwk_thumbprint(key_to_jwk(resolve_public_key(did)))
    except ValueError:
        thumbprint = None

    return PassportStatus(
        did=did,
        registered=did in registry,
        revoked=bool(revocation.get("revoked", False)),
        reputation=ReputationSummary(
            found=bool(reputation.get("found", False)),
            score=float(reputation.get("score", 0.5)),
            interaction_count=reputation.get("interaction_count"),
        ),
        key_thumbprint=thumbprint,
    )


def register_passport_routes(app: FastAPI) -> None:
    """Attach passport routes (they 404 until ``passport_enabled`` is on)."""
    app.include_router(router)
