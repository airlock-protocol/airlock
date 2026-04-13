from __future__ import annotations

"""RFC 7662 Token Introspection with live Airlock trust data."""

import logging
from typing import Any

from nacl.signing import VerifyKey

from airlock.oauth.models import IntrospectionResponse
from airlock.oauth.store import OAuthStore
from airlock.oauth.token_validator import OAuthTokenError, validate_access_token

logger = logging.getLogger(__name__)


async def introspect_token(
    token: str,
    oauth_store: OAuthStore,
    reputation_store: Any,
    verify_key: VerifyKey,
) -> IntrospectionResponse:
    """Introspect an OAuth access token and return live trust data.

    Returns an inactive response for expired, revoked, or invalid tokens
    rather than raising an error (per RFC 7662).
    """
    try:
        claims = validate_access_token(
            token,
            verify_key,
            revocation_check=oauth_store.is_token_revoked,
        )
    except OAuthTokenError:
        return IntrospectionResponse(active=False)

    subject_did = claims.get("sub", "")
    client_id = claims.get("client_id", "")

    # Fetch live trust score
    trust_score: float | None = claims.get("airlock:trust_score")
    trust_tier: int | None = claims.get("airlock:trust_tier")

    if reputation_store is not None:
        try:
            score_record = reputation_store.get(subject_did)
            if score_record is not None:
                if isinstance(score_record, dict):
                    trust_score = float(score_record.get("score", trust_score or 0.0))
                    trust_tier = int(score_record.get("tier", trust_tier or 0))
                else:
                    live_score = getattr(score_record, "score", None)
                    live_tier = getattr(score_record, "tier", None)
                    if live_score is not None:
                        trust_score = float(live_score)
                    if live_tier is not None:
                        trust_tier = int(live_tier)
        except Exception:
            logger.debug("Could not fetch live trust data for %s", subject_did, exc_info=True)

    return IntrospectionResponse(
        active=True,
        sub=subject_did,
        client_id=client_id,
        scope=claims.get("scope", ""),
        exp=claims.get("exp"),
        iat=claims.get("iat"),
        iss=claims.get("iss", ""),
        trust_score=trust_score,
        trust_tier=trust_tier,
    )
