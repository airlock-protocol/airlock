from __future__ import annotations

"""RFC 7662 token introspection with live trust data."""

import logging
from typing import Any

from nacl.signing import VerifyKey

from airlock.oauth.models import IntrospectionResponse
from airlock.oauth.store import OAuthStore
from airlock.oauth.token_validator import TokenValidationError, validate_access_token

logger = logging.getLogger(__name__)


def introspect_token(
    token: str,
    *,
    verify_key: VerifyKey,
    issuer_did: str,
    oauth_store: OAuthStore,
    trust_score_lookup: Any | None = None,
) -> IntrospectionResponse:
    """Introspect an access token and return live trust data.

    Parameters
    ----------
    token:
        The encoded JWT to introspect.
    verify_key:
        The gateway's Ed25519 public key.
    issuer_did:
        The expected issuer DID.
    oauth_store:
        The OAuth store for revocation checks.
    trust_score_lookup:
        Callable(did) -> (score, tier) for live trust data.

    Returns
    -------
    IntrospectionResponse with ``active=True`` if valid, or ``active=False``.
    """
    # First validate the token cryptographically
    try:
        payload = validate_access_token(
            token,
            verify_key=verify_key,
            expected_issuer=issuer_did,
        )
    except TokenValidationError:
        return IntrospectionResponse(active=False)

    # Check revocation in store
    jti = payload.get("jti", "")
    if jti:
        token_record = oauth_store.get_token(jti)
        if token_record is not None and token_record.revoked:
            return IntrospectionResponse(active=False)

    subject_did = payload.get("sub", "")

    # Look up live trust score
    score = payload.get("airlock:trust_score")
    tier = payload.get("airlock:trust_tier")
    if trust_score_lookup is not None and subject_did:
        try:
            live_score, live_tier = trust_score_lookup(subject_did)
            score = live_score
            tier = live_tier
        except Exception:
            pass  # Fall back to token-embedded values

    return IntrospectionResponse(
        active=True,
        sub=subject_did,
        client_id=payload.get("client_id"),
        scope=payload.get("scope"),
        exp=payload.get("exp"),
        iat=payload.get("iat"),
        **{
            "airlock:trust_score": score,
            "airlock:trust_tier": tier,
        },
    )
