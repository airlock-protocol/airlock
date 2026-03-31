"""HTTP client for delegating DID resolution to another Airlock-compatible gateway."""

from __future__ import annotations

import logging

import httpx

from airlock.schemas.identity import AgentProfile

logger = logging.getLogger(__name__)


async def resolve_remote_profile(
    client: httpx.AsyncClient,
    target_did: str,
) -> AgentProfile | None:
    """POST ``/resolve`` on the configured base URL; parse ``AgentProfile`` if found.

    Expects the same JSON shape as this gateway's ``POST /resolve``:
    ``{"found": true, "profile": {...}}`` when the agent exists.
    """
    try:
        resp = await client.post("/resolve", json={"target_did": target_did})
        resp.raise_for_status()
        data = resp.json()
    except (httpx.HTTPError, ValueError) as exc:
        logger.debug("Remote registry resolve failed for %s: %s", target_did, exc)
        return None

    if not data.get("found"):
        return None
    raw_profile = data.get("profile")
    if not isinstance(raw_profile, dict):
        return None
    try:
        return AgentProfile.model_validate(raw_profile)
    except Exception as exc:
        logger.info("Remote registry returned invalid profile for %s: %s", target_did, exc)
        return None
