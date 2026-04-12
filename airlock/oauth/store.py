from __future__ import annotations

"""In-memory OAuth client and token store with thread-safe locking."""

import logging
import threading
from datetime import UTC, datetime

from airlock.oauth.models import ClientStatus, OAuthClient, OAuthToken

logger = logging.getLogger(__name__)


class OAuthStore:
    """Thread-safe in-memory store for OAuth clients and tokens.

    Uses ``threading.Lock`` for synchronization, matching the pattern
    used by ReputationStore and other Airlock stores.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._clients: dict[str, OAuthClient] = {}
        self._tokens: dict[str, OAuthToken] = {}
        # Map DID -> client_id for reverse lookup
        self._did_to_client: dict[str, str] = {}

    # ------------------------------------------------------------------
    # Client operations
    # ------------------------------------------------------------------

    def register_client(self, client: OAuthClient) -> None:
        """Register or update an OAuth client."""
        with self._lock:
            self._clients[client.client_id] = client
            self._did_to_client[client.did] = client.client_id
            logger.info("OAuth client registered: %s (did=%s)", client.client_id, client.did)

    def get_client(self, client_id: str) -> OAuthClient | None:
        """Look up a client by client_id."""
        with self._lock:
            return self._clients.get(client_id)

    def get_client_by_did(self, did: str) -> OAuthClient | None:
        """Look up a client by DID."""
        with self._lock:
            cid = self._did_to_client.get(did)
            if cid is None:
                return None
            return self._clients.get(cid)

    def suspend_client(self, client_id: str) -> bool:
        """Suspend a client. Returns True if found and suspended."""
        with self._lock:
            client = self._clients.get(client_id)
            if client is None:
                return False
            client.status = ClientStatus.SUSPENDED
            return True

    # ------------------------------------------------------------------
    # Token operations
    # ------------------------------------------------------------------

    def store_token(self, token: OAuthToken) -> None:
        """Store a token record."""
        with self._lock:
            self._tokens[token.jti] = token

    def get_token(self, jti: str) -> OAuthToken | None:
        """Look up a token by JTI."""
        with self._lock:
            return self._tokens.get(jti)

    def get_token_by_access_token(self, access_token: str) -> OAuthToken | None:
        """Look up a token by its encoded access_token string."""
        with self._lock:
            for token in self._tokens.values():
                if token.access_token == access_token:
                    return token
            return None

    def revoke_token(self, jti: str) -> bool:
        """Revoke a token by JTI. Returns True if found and revoked."""
        with self._lock:
            token = self._tokens.get(jti)
            if token is None:
                return False
            token.revoked = True
            logger.info("OAuth token revoked: jti=%s", jti)
            return True

    def revoke_tokens_by_did(self, did: str) -> int:
        """Revoke all tokens for a DID. Returns count of revoked tokens."""
        with self._lock:
            count = 0
            for token in self._tokens.values():
                if token.subject_did == did and not token.revoked:
                    token.revoked = True
                    count += 1
            if count:
                logger.info("Revoked %d OAuth tokens for did=%s", count, did)
            return count

    def revoke_cascade(self, parent_jti: str) -> int:
        """Revoke a token and all tokens derived from it (delegation cascade).

        Returns total count of revoked tokens (including the parent).
        """
        with self._lock:
            return self._revoke_cascade_unlocked(parent_jti)

    def _revoke_cascade_unlocked(self, jti: str) -> int:
        """Recursively revoke a token and its children. Must hold lock."""
        token = self._tokens.get(jti)
        if token is None:
            return 0

        count = 0
        if not token.revoked:
            token.revoked = True
            count = 1

        # Find children
        for child in self._tokens.values():
            if child.parent_jti == jti and not child.revoked:
                count += self._revoke_cascade_unlocked(child.jti)

        return count

    def is_token_active(self, jti: str) -> bool:
        """Check if a token exists, is not revoked, and has not expired."""
        with self._lock:
            token = self._tokens.get(jti)
            if token is None:
                return False
            if token.revoked:
                return False
            return datetime.now(UTC) < token.expires_at

    def cleanup_expired(self) -> int:
        """Remove expired tokens from the store. Returns count removed."""
        now = datetime.now(UTC)
        with self._lock:
            expired = [jti for jti, t in self._tokens.items() if t.expires_at < now]
            for jti in expired:
                del self._tokens[jti]
            return len(expired)
