from __future__ import annotations

from typing import TYPE_CHECKING

import base58
from nacl.signing import SigningKey, VerifyKey

if TYPE_CHECKING:
    from airlock.schemas.identity import AgentDID

MULTICODEC_ED25519_PUB = b"\xed\x01"


class KeyPair:
    """An Ed25519 signing key pair with DID:key identity."""

    def __init__(self, signing_key: SigningKey) -> None:
        self.signing_key = signing_key
        self.verify_key = signing_key.verify_key
        self.public_key_multibase = self._encode_multibase()
        self.did = f"did:key:{self.public_key_multibase}"

    def _encode_multibase(self) -> str:
        raw = self.verify_key.encode()
        payload = MULTICODEC_ED25519_PUB + raw
        encoded = base58.b58encode(payload).decode("ascii")
        return f"z{encoded}"

    @classmethod
    def generate(cls) -> KeyPair:
        """Generate a new random Ed25519 key pair."""
        return cls(SigningKey.generate())

    @classmethod
    def from_seed(cls, seed: bytes) -> KeyPair:
        """Create a key pair from a 32-byte seed (deterministic, for testing)."""
        if len(seed) != 32:
            raise ValueError("Seed must be exactly 32 bytes")
        return cls(SigningKey(seed))

    def to_agent_did(self) -> AgentDID:
        """Create an AgentDID schema instance from this key pair."""
        from airlock.schemas.identity import AgentDID

        return AgentDID(did=self.did, public_key_multibase=self.public_key_multibase)


def resolve_public_key(agent_did: str) -> VerifyKey:
    """Extract the Ed25519 VerifyKey from a did:key string.

    Reverses the did:key encoding: strip 'did:key:z' prefix,
    base58btc decode, strip multicodec prefix, return VerifyKey.
    """
    multibase = did_to_multibase(agent_did)
    if not multibase.startswith("z"):
        raise ValueError("Expected multibase prefix 'z' (base58btc)")
    payload = base58.b58decode(multibase[1:])
    if len(payload) < 34 or payload[:2] != MULTICODEC_ED25519_PUB:
        raise ValueError("Invalid did:key: expected Ed25519 multicodec prefix")
    raw_key = payload[2:]
    return VerifyKey(raw_key)


def did_to_multibase(did: str) -> str:
    """Extract the multibase-encoded public key from a did:key string."""
    prefix = "did:key:"
    if not did.startswith(prefix):
        raise ValueError("DID must use the did:key method")
    return did[len(prefix) :]
