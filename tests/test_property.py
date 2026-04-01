"""Property-based tests using Hypothesis for protocol invariants."""

from __future__ import annotations

import json

from hypothesis import assume, given, settings
from hypothesis import strategies as st

from airlock.crypto.keys import KeyPair
from airlock.crypto.signing import sign_message, verify_signature

# Strategy: random 32-byte seeds for Ed25519 keys
ed25519_seeds = st.binary(min_size=32, max_size=32)

# Strategy: printable text for agent names/answers
safe_text = st.text(
    st.characters(whitelist_categories=("L", "N", "P", "Z")), min_size=1, max_size=200
)

# Strategy: DID-like strings
did_strings = st.builds(
    lambda seed: KeyPair.from_seed(seed).did,
    ed25519_seeds,
)


class TestKeyPairProperties:
    """Property tests for Ed25519 key pair generation."""

    @given(seed=ed25519_seeds)
    def test_deterministic_key_generation(self, seed: bytes) -> None:
        """Same seed always produces same DID."""
        kp1 = KeyPair.from_seed(seed)
        kp2 = KeyPair.from_seed(seed)
        assert kp1.did == kp2.did

    @given(seed1=ed25519_seeds, seed2=ed25519_seeds)
    def test_different_seeds_different_dids(self, seed1: bytes, seed2: bytes) -> None:
        """Different seeds produce different DIDs."""
        assume(seed1 != seed2)
        kp1 = KeyPair.from_seed(seed1)
        kp2 = KeyPair.from_seed(seed2)
        assert kp1.did != kp2.did

    @given(seed=ed25519_seeds)
    def test_did_format_always_valid(self, seed: bytes) -> None:
        """All generated DIDs follow did:key:z... format."""
        kp = KeyPair.from_seed(seed)
        assert kp.did.startswith("did:key:z")
        assert len(kp.did) > 20


class TestSignatureProperties:
    """Property tests for Ed25519 signing and verification."""

    @given(seed=ed25519_seeds)
    def test_sign_verify_roundtrip(self, seed: bytes) -> None:
        """Any payload signed with a key can be verified with the same key."""
        kp = KeyPair.from_seed(seed)
        payload = {"agent": kp.did, "action": "test", "nonce": "abc123"}
        signature_b64 = sign_message(payload, kp.signing_key)
        assert verify_signature(payload, signature_b64, kp.verify_key)

    @given(seed1=ed25519_seeds, seed2=ed25519_seeds)
    def test_wrong_key_rejects(self, seed1: bytes, seed2: bytes) -> None:
        """Signature verified with wrong key must fail."""
        assume(seed1 != seed2)
        kp1 = KeyPair.from_seed(seed1)
        kp2 = KeyPair.from_seed(seed2)
        payload = {"agent": kp1.did, "nonce": "test"}
        signature_b64 = sign_message(payload, kp1.signing_key)
        assert not verify_signature(payload, signature_b64, kp2.verify_key)

    @given(seed=ed25519_seeds, key1=safe_text, key2=safe_text)
    @settings(max_examples=50)
    def test_canonical_serialization_order_independent(
        self, seed: bytes, key1: str, key2: str
    ) -> None:
        """Signing should produce same signature regardless of dict key order."""
        assume(key1 != key2)
        kp = KeyPair.from_seed(seed)
        payload_a = {key1: "value1", key2: "value2"}
        payload_b = {key2: "value2", key1: "value1"}
        sig_a = sign_message(payload_a, kp.signing_key)
        sig_b = sign_message(payload_b, kp.signing_key)
        assert sig_a == sig_b


class TestDIDProperties:
    """Property tests for DID validation."""

    @given(seed=ed25519_seeds)
    def test_did_roundtrip_through_json(self, seed: bytes) -> None:
        """DIDs survive JSON serialization roundtrip."""
        kp = KeyPair.from_seed(seed)
        serialized = json.dumps({"did": kp.did})
        deserialized = json.loads(serialized)
        assert deserialized["did"] == kp.did
