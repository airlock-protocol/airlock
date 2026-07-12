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
from airlock.passport.directory import (
    build_directory,
    jwk_thumbprint,
    key_to_jwk,
    tenant_directory_url,
)
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


def _tenant_domain_base(request: Request) -> str | None:
    base = getattr(request.app.state.config, "passport_tenant_domain_base", None) or ""
    cleaned = base.strip().strip(".").lower()
    return cleaned or None


def _tenant_label(request: Request) -> str | None:
    """Tenant label when the request targets a per-tenant authority.

    With ``passport_tenant_domain_base`` set to ``agents.example``, a
    request whose Host is ``alice.agents.example`` yields ``"alice"``.
    The base host itself — and any unrelated host — yields ``None``
    (the flat all-tenants view, preserving back-compat).
    """
    base = _tenant_domain_base(request)
    if base is None:
        return None
    host = (request.headers.get("host") or "").strip().lower()
    host = host.split(":", 1)[0].rstrip(".")
    if not host.endswith("." + base):
        return None
    return host[: -len(base) - 1]


async def _profiles_for_host(request: Request) -> list[AgentProfile]:
    """Profiles to serve for this request's Host header.

    Flat view for the base (or any non-tenant) host; exactly one tenant
    for ``<label>.<base>`` hosts. An unknown label is a structured 404; a
    known label whose agent is revoked or inactive serves an empty
    directory (the key disappears, the authority does not).
    """
    label = _tenant_label(request)
    profiles = await _active_profiles(request)
    if label is None:
        return profiles
    registry: dict[str, AgentProfile] = request.app.state.agent_registry
    if not any(p.passport_label == label for p in registry.values()):
        raise HTTPException(status_code=404, detail=f"Unknown tenant label '{label}'")
    return [p for p in profiles if p.passport_label == label]


def _cache_headers(request: Request) -> dict[str, str]:
    max_age = request.app.state.config.passport_directory_max_age_seconds
    return {"Cache-Control": f"max-age={max_age}"}


@router.get(WELL_KNOWN_DIRECTORY_PATH)
async def signatures_directory(request: Request) -> Response:
    """JWKS key directory of active registered agents (Web Bot Auth)."""
    _require_passport_enabled(request)

    keys: list[VerifyKey] = []
    for profile in await _profiles_for_host(request):
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
        for profile in await _profiles_for_host(request)
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

    profile = registry.get(did)
    label = profile.passport_label if profile is not None else None
    base = _tenant_domain_base(request)
    tenant_url: str | None = None
    if base is not None and label is not None:
        try:
            tenant_url = tenant_directory_url(base, label)
        except ValueError:
            tenant_url = None

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
        passport_label=label,
        tenant_directory_url=tenant_url,
    )


def register_passport_routes(app: FastAPI) -> None:
    """Attach passport routes (they 404 until ``passport_enabled`` is on)."""
    app.include_router(router)
