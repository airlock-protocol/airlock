from __future__ import annotations

"""In-memory store for OAuth clients and token metadata."""

import logging
import threading
from typing import Any

from airlock.oauth.models import OAuthClient

logger = logging.getLogger(__name__)


class OAuthStore:
    """Thread-safe in-memory store for OAuth clients and revoked tokens.

    Mirrors the ``ReputationStore`` locking pattern used elsewhere in the
    codebase but keeps data in plain dicts (no LanceDB dependency).
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._clients: dict[str, OAuthClient] = {}
        self._did_index: dict[str, str] = {}  # did -> client_id
        self._tokens: dict[str, dict[str, Any]] = {}  # jti -> token metadata
        self._revoked: set[str] = set()  # set of revoked jtis

    # ------------------------------------------------------------------
    # Client management
    # ------------------------------------------------------------------

    def register_client(self, client: OAuthClient) -> None:
        """Register (or replace) a client."""
        with self._lock:
            self._clients[client.client_id] = client
            self._did_index[client.did] = client.client_id
            logger.info("OAuth client registered: %s (did=%s)", client.client_id, client.did)

    def get_client(self, client_id: str) -> OAuthClient | None:
        with self._lock:
            return self._clients.get(client_id)

    def get_client_by_did(self, did: str) -> OAuthClient | None:
        with self._lock:
            cid = self._did_index.get(did)
            if cid is None:
                return None
            return self._clients.get(cid)

    def delete_client(self, client_id: str) -> bool:
        with self._lock:
            client = self._clients.pop(client_id, None)
            if client is None:
                return False
            self._did_index.pop(client.did, None)
            return True

    def list_clients(self) -> list[OAuthClient]:
        with self._lock:
            return list(self._clients.values())

    # ------------------------------------------------------------------
    # Token tracking
    # ------------------------------------------------------------------

    def store_token(self, jti: str, metadata: dict[str, Any]) -> None:
        with self._lock:
            self._tokens[jti] = metadata

    def get_token(self, jti: str) -> dict[str, Any] | None:
        with self._lock:
            return self._tokens.get(jti)

    def revoke_token(self, jti: str) -> None:
        with self._lock:
            self._revoked.add(jti)
            logger.info("OAuth token revoked: jti=%s", jti)

    def is_token_revoked(self, jti: str) -> bool:
        with self._lock:
            return jti in self._revoked
