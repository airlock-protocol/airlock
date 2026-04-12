from __future__ import annotations

"""RFC 7591 Dynamic Client Registration for Airlock OAuth."""

import logging
import uuid
from datetime import UTC, datetime

from airlock.crypto.keys import resolve_public_key
from airlock.oauth.models import OAuthClient
from airlock.oauth.scopes import AIRLOCK_SCOPES
from airlock.oauth.store import OAuthStore

logger = logging.getLogger(__name__)


class RegistrationError(Exception):
    """Raised when dynamic client registration fails."""

    def __init__(self, error: str, description: str, status_code: int = 400) -> None:
        self.error = error
        self.description = description
        self.status_code = status_code
        super().__init__(description)


def register_client(
    *,
    did: str,
    client_name: str,
    store: OAuthStore,
    grant_types: list[str] | None = None,
    scope: str | None = None,
) -> OAuthClient:
    """Register a new OAuth client via RFC 7591 dynamic registration.

    The client's public key is extracted from the DID for later assertion
    verification.  Only ``did:key`` method is supported.

    Raises
    ------
    RegistrationError
        On invalid DID or duplicate registration.
    """
    if not did.startswith("did:key:"):
        raise RegistrationError("invalid_client_metadata", "DID must use the did:key method")

    # Verify the DID is resolvable (valid public key)
    try:
        resolve_public_key(did)
    except (ValueError, Exception) as exc:
        raise RegistrationError(
            "invalid_client_metadata",
            f"Cannot resolve public key from DID: {exc}",
        ) from exc

    # Check for duplicate
    existing = store.get_client_by_did(did)
    if existing is not None:
        raise RegistrationError(
            "invalid_client_metadata",
            f"A client is already registered for DID {did}",
            status_code=409,
        )

    multibase = did[len("did:key:"):]
    default_scope = " ".join(sorted(AIRLOCK_SCOPES.keys()))
    client = OAuthClient(
        client_id=str(uuid.uuid4()),
        client_name=client_name,
        did=did,
        public_key_multibase=multibase,
        grant_types=grant_types or ["client_credentials"],
        scope=scope or default_scope,
        registered_at=datetime.now(UTC),
    )
    store.register_client(client)
    logger.info("Registered OAuth client %s for DID %s", client.client_id, did)
    return client
