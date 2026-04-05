"""CRL (Certificate Revocation List) generator for the Airlock gateway.

Builds a signed CRL from the current revocation state, caches it until
the next update interval, and tracks a monotonically increasing crl_number.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

from airlock.crypto.signing import sign_message
from airlock.schemas.crl import CRLEntry, SignedCRL

if TYPE_CHECKING:
    from nacl.signing import SigningKey

    from airlock.gateway.revocation import RedisRevocationStore, RevocationStore

logger = logging.getLogger(__name__)


class CRLGenerator:
    """Generates and caches signed CRLs from the current revocation state.

    Parameters
    ----------
    revocation_store:
        The revocation store to read current revoked/suspended DIDs from.
    signing_key:
        Ed25519 signing key used to sign the CRL.
    issuer_did:
        DID of the gateway that issues the CRL.
    update_interval_seconds:
        Seconds between CRL regenerations (controls ``next_update``).
    max_cache_age_seconds:
        Value published in the CRL's ``max_cache_age_seconds`` field.
    """

    def __init__(
        self,
        revocation_store: RevocationStore | RedisRevocationStore,
        signing_key: SigningKey,
        issuer_did: str,
        update_interval_seconds: int = 60,
        max_cache_age_seconds: int = 300,
    ) -> None:
        self._store = revocation_store
        self._signing_key = signing_key
        self._issuer_did = issuer_did
        self._update_interval = update_interval_seconds
        self._max_cache_age = max_cache_age_seconds
        self._crl_number: int = 0
        self._cached_crl: SignedCRL | None = None

    @property
    def crl_number(self) -> int:
        """Current CRL sequence number."""
        return self._crl_number

    def _is_cache_fresh(self) -> bool:
        """Return True if the cached CRL has not passed its next_update time."""
        if self._cached_crl is None:
            return False
        now = datetime.now(UTC)
        return now < self._cached_crl.next_update

    async def generate(self) -> SignedCRL:
        """Build a new SignedCRL from the current revocation state.

        Increments crl_number, builds entries from all revoked and suspended
        DIDs, signs the CRL, and updates the cache.
        """
        self._crl_number += 1
        now = datetime.now(UTC)
        next_update = now + timedelta(seconds=self._update_interval)

        entries: list[CRLEntry] = []

        # Add permanently revoked DIDs
        revoked_reasons = self._store.get_revoked_with_reasons()
        for did, reason in sorted(revoked_reasons.items()):
            entries.append(
                CRLEntry(
                    did=did,
                    status="revoked",
                    reason=reason.value,
                    revoked_at=now,
                )
            )

        # Add suspended DIDs
        suspended_dids = await self._store.list_suspended()
        for did in suspended_dids:
            entries.append(
                CRLEntry(
                    did=did,
                    status="suspended",
                    reason="investigation",
                    revoked_at=now,
                )
            )

        crl = SignedCRL(
            version=1,
            crl_number=self._crl_number,
            issuer_did=self._issuer_did,
            this_update=now,
            next_update=next_update,
            max_cache_age_seconds=self._max_cache_age,
            entries=entries,
            signature=None,
        )

        # Sign the CRL (signature field is excluded by canonicalize)
        crl_dict = crl.model_dump(mode="json")
        signature = sign_message(crl_dict, self._signing_key)
        crl = crl.model_copy(update={"signature": signature})

        self._cached_crl = crl
        logger.info(
            "CRL #%d generated: %d entries, next_update=%s",
            self._crl_number,
            len(entries),
            next_update.isoformat(),
        )
        return crl

    async def get_or_generate(self) -> SignedCRL:
        """Return the cached CRL if fresh, otherwise regenerate."""
        if self._is_cache_fresh():
            return self._cached_crl  # type: ignore[return-value]
        return await self.generate()
