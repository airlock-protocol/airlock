from __future__ import annotations

"""RFC 8693 Token Exchange for delegation chains with scope narrowing."""

import logging
from datetime import UTC, datetime
from typing import Any

from nacl.signing import SigningKey, VerifyKey

from airlock.oauth.models import OAuthToken, TokenResponse
from airlock.oauth.scopes import is_scope_subset
from airlock.oauth.store import OAuthStore
from airlock.oauth.token_generator import generate_access_token
from airlock.oauth.token_validator import validate_access_token

logger = logging.getLogger(__name__)

SUBJECT_TOKEN_TYPE_JWT = "urn:ietf:params:oauth:token-type:jwt"


class TokenExchangeError(Exception):
    """Raised when token exchange validation fails."""

    def __init__(self, error: str, description: str) -> None:
        self.error = error
        self.description = description
        super().__init__(description)


def handle_token_exchange(
    *,
    subject_token: str,
    subject_token_type: str,
    requested_scope: str | None,
    oauth_store: OAuthStore,
    signing_key: SigningKey,
    verify_key: VerifyKey,
    issuer_did: str,
    actor_did: str,
    actor_client_id: str,
    ttl_seconds: int = 3600,
    max_delegation_depth: int = 5,
    trust_score: float = 0.0,
    trust_tier: int = 0,
) -> TokenResponse:
    """Process an RFC 8693 token exchange request.

    Parameters
    ----------
    subject_token:
        The parent token being exchanged.
    subject_token_type:
        Must be ``urn:ietf:params:oauth:token-type:jwt``.
    requested_scope:
        Space-separated scopes for the child token.
    oauth_store:
        The OAuth store for token lookup and persistence.
    signing_key:
        The gateway's Ed25519 signing key.
    verify_key:
        The gateway's Ed25519 public key for parent token verification.
    issuer_did:
        The gateway's DID.
    actor_did:
        The DID of the agent requesting delegation.
    actor_client_id:
        The client_id of the requesting agent.
    ttl_seconds:
        TTL for the child token.
    max_delegation_depth:
        Maximum allowed depth for delegation chains.
    trust_score:
        The actor's current trust score.
    trust_tier:
        The actor's current trust tier.

    Returns
    -------
    TokenResponse with the delegated child token.

    Raises
    ------
    TokenExchangeError
        On any validation failure.
    """
    if subject_token_type != SUBJECT_TOKEN_TYPE_JWT:
        raise TokenExchangeError(
            "invalid_request",
            f"subject_token_type must be {SUBJECT_TOKEN_TYPE_JWT}",
        )

    # Validate the parent token
    try:
        parent_payload = validate_access_token(
            subject_token,
            verify_key=verify_key,
            expected_issuer=issuer_did,
            max_delegation_depth=max_delegation_depth,
        )
    except Exception as exc:
        raise TokenExchangeError("invalid_grant", f"Subject token invalid: {exc}")

    parent_jti = parent_payload.get("jti", "")

    # Check parent token is still active in store
    if parent_jti and not oauth_store.is_token_active(parent_jti):
        raise TokenExchangeError("invalid_grant", "Subject token has been revoked")

    # Check delegation depth
    current_depth = _count_act_depth(parent_payload)
    if current_depth + 1 > max_delegation_depth:
        raise TokenExchangeError(
            "invalid_grant",
            f"Delegation depth would exceed maximum ({max_delegation_depth})",
        )

    # Scope narrowing: child scope must be subset of parent scope
    parent_scope = parent_payload.get("scope", "")
    child_scope = requested_scope or parent_scope

    if child_scope and not is_scope_subset(child_scope, parent_scope):
        raise TokenExchangeError(
            "invalid_scope",
            "Requested scope is not a subset of parent token scope",
        )

    # Build nested act claim
    act_claim = _build_act_chain(parent_payload, actor_did, actor_client_id)

    # Generate child token
    extra_claims: dict[str, Any] = {"act": act_claim}
    encoded, jti, expires_at = generate_access_token(
        signing_key=signing_key,
        issuer_did=issuer_did,
        subject_did=parent_payload.get("sub", ""),
        client_id=actor_client_id,
        scope=child_scope,
        trust_score=trust_score,
        trust_tier=trust_tier,
        ttl_seconds=ttl_seconds,
        extra_claims=extra_claims,
    )

    # Build actor chain for storage
    actor_chain: list[dict[str, Any]] = []
    parent_token_record = oauth_store.get_token(parent_jti) if parent_jti else None
    if parent_token_record and parent_token_record.actor_chain:
        actor_chain = list(parent_token_record.actor_chain)
    actor_chain.append({"sub": actor_did, "client_id": actor_client_id})

    # Store child token
    token_record = OAuthToken(
        access_token=encoded,
        token_type="Bearer",
        expires_in=ttl_seconds,
        scope=child_scope,
        subject_did=parent_payload.get("sub", ""),
        trust_score=trust_score,
        trust_tier=trust_tier,
        issued_at=datetime.now(UTC),
        expires_at=expires_at,
        jti=jti,
        parent_jti=parent_jti,
        delegation_depth=current_depth + 1,
        actor_chain=actor_chain,
    )
    oauth_store.store_token(token_record)

    return TokenResponse(
        access_token=encoded,
        token_type="Bearer",
        expires_in=ttl_seconds,
        scope=child_scope,
    )


def _count_act_depth(payload: dict[str, Any]) -> int:
    """Count the depth of nested ``act`` claims."""
    depth = 0
    current = payload
    while "act" in current:
        depth += 1
        act = current["act"]
        if not isinstance(act, dict):
            break
        current = act
    return depth


def _build_act_chain(
    parent_payload: dict[str, Any],
    actor_did: str,
    actor_client_id: str,
) -> dict[str, Any]:
    """Build the nested ``act`` claim for the child token.

    The new actor wraps the existing act chain from the parent.
    """
    act: dict[str, Any] = {
        "sub": actor_did,
        "client_id": actor_client_id,
    }

    if "act" in parent_payload:
        act["act"] = parent_payload["act"]

    return act
