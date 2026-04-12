from __future__ import annotations

"""Dynamic client registration (RFC 7591) for Airlock OAuth."""

import logging
import uuid
from datetime import UTC, datetime

from pydantic import BaseModel, Field, field_validator

from airlock.oauth.models import OAuthClient
from airlock.oauth.scopes import AIRLOCK_SCOPES
from airlock.oauth.store import OAuthStore

logger = logging.getLogger(__name__)


class RegistrationRequest(BaseModel):
    """Dynamic client registration request body."""

    client_name: str = ""
    did: str
    public_key_multibase: str
    grant_types: list[str] = Field(default_factory=lambda: ["client_credentials"])
    scope: str = ""

    @field_validator("did")
    @classmethod
    def did_must_be_key_method(cls, v: str) -> str:
        if not v.startswith("did:key:"):
            raise ValueError("DID must use the did:key method")
        return v


class RegistrationResponse(BaseModel):
    """Dynamic client registration response."""

    client_id: str
    client_name: str
    did: str
    grant_types: list[str]
    scope: str
    registered_at: datetime


class RegistrationError(Exception):
    """Raised when client registration fails."""

    def __init__(self, error: str, description: str) -> None:
        self.error = error
        self.description = description
        super().__init__(description)


def register_client(
    request: RegistrationRequest,
    *,
    oauth_store: OAuthStore,
    allowed_scopes: str | None = None,
) -> RegistrationResponse:
    """Register a new OAuth client.

    Parameters
    ----------
    request:
        The registration request.
    oauth_store:
        The OAuth store for persistence.
    allowed_scopes:
        Comma-separated allowed scopes (from config).

    Returns
    -------
    RegistrationResponse with the assigned client_id.

    Raises
    ------
    RegistrationError
        On validation failure or duplicate registration.
    """
    # Check for existing registration by DID
    existing = oauth_store.get_client_by_did(request.did)
    if existing is not None:
        raise RegistrationError(
            "invalid_client_metadata",
            f"DID already registered with client_id: {existing.client_id}",
        )

    # Validate grant types
    allowed_grants = {"client_credentials", "urn:ietf:params:oauth:grant-type:token-exchange"}
    for gt in request.grant_types:
        if gt not in allowed_grants:
            raise RegistrationError(
                "invalid_client_metadata",
                f"Unsupported grant_type: {gt}",
            )

    # Validate scopes
    if request.scope:
        known = set(AIRLOCK_SCOPES.keys())
        if allowed_scopes:
            permitted = {s.strip() for s in allowed_scopes.split(",") if s.strip()}
        else:
            permitted = known

        for scope in request.scope.split():
            if scope not in known:
                raise RegistrationError(
                    "invalid_client_metadata",
                    f"Unknown scope: {scope}",
                )
            if scope not in permitted:
                raise RegistrationError(
                    "invalid_client_metadata",
                    f"Scope not permitted: {scope}",
                )

    # Generate client_id
    client_id = f"airlock_{uuid.uuid4().hex[:16]}"
    now = datetime.now(UTC)

    client = OAuthClient(
        client_id=client_id,
        client_name=request.client_name or request.did,
        did=request.did,
        public_key_multibase=request.public_key_multibase,
        grant_types=request.grant_types,
        scope=request.scope,
        registered_at=now,
    )

    oauth_store.register_client(client)

    logger.info("New OAuth client registered: %s (did=%s)", client_id, request.did)

    return RegistrationResponse(
        client_id=client_id,
        client_name=client.client_name,
        did=client.did,
        grant_types=client.grant_types,
        scope=client.scope,
        registered_at=now,
    )
