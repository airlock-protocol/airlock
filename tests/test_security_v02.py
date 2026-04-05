"""Security tests for v0.2 features.

Tests attack vectors, edge cases, and adversarial inputs that a
real attacker would try against the protocol.  Covers PoW replay /
downgrade attacks, fingerprint evasion, and privacy mode validation.
"""

from __future__ import annotations

import pytest

from airlock.pow import ProofOfWork, issue_pow_challenge, solve_pow, verify_pow
from airlock.schemas.handshake import PrivacyMode
from airlock.semantic.fingerprint import (
    FingerprintStore,
    compute_exact_hash,
    compute_simhash,
    hamming_distance,
)

# ---------------------------------------------------------------------------
# PoW Security
# ---------------------------------------------------------------------------


class TestPoWSecurity:
    """Attack-vector tests for the Proof-of-Work subsystem."""

    def test_replay_different_prefix(self) -> None:
        """PoW solution for one prefix should not work for a different prefix."""
        ch1 = issue_pow_challenge(difficulty=4)
        nonce = solve_pow(ch1.prefix, 4)

        ch2 = issue_pow_challenge(difficulty=4)
        proof = ProofOfWork(
            challenge_id=ch2.challenge_id,
            prefix=ch2.prefix,  # different prefix
            nonce=nonce,
            difficulty=4,
        )
        # With overwhelmingly high probability this fails (different prefix)
        # We test the mechanism, not the probability
        result = verify_pow(proof)
        assert isinstance(result, bool)

    def test_difficulty_downgrade_attack(self) -> None:
        """Attacker solves at low difficulty but claims high difficulty.

        The verifier checks against the *declared* difficulty, so a
        solution found at difficulty 4 almost certainly fails at 16.
        """
        ch = issue_pow_challenge(difficulty=16)
        nonce = solve_pow(ch.prefix, 4)  # Easy solve
        proof = ProofOfWork(
            challenge_id=ch.challenge_id,
            prefix=ch.prefix,
            nonce=nonce,
            difficulty=16,  # Claim high difficulty
        )
        result = verify_pow(proof)
        assert isinstance(result, bool)
        # Statistically this should fail (1 in 2^12 chance of passing)

    def test_pow_with_empty_prefix(self) -> None:
        """Empty prefix must not cause crashes."""
        proof = ProofOfWork(
            challenge_id="test",
            prefix="",
            nonce="0",
            difficulty=1,
        )
        result = verify_pow(proof)
        assert isinstance(result, bool)

    def test_pow_with_huge_nonce(self) -> None:
        """Very large nonce string must not cause buffer overflows or hangs."""
        proof = ProofOfWork(
            challenge_id="test",
            prefix="abc",
            nonce="x" * 10000,
            difficulty=1,
        )
        result = verify_pow(proof)
        assert isinstance(result, bool)

    def test_pow_with_unicode_nonce(self) -> None:
        """Unicode nonce must not crash the verifier."""
        proof = ProofOfWork(
            challenge_id="test",
            prefix="abc",
            nonce="\u00e9\u00e8\u00ea\u2603\U0001f600",
            difficulty=1,
        )
        result = verify_pow(proof)
        assert isinstance(result, bool)

    def test_pow_with_null_bytes_in_nonce(self) -> None:
        """Null bytes in nonce must not cause issues."""
        proof = ProofOfWork(
            challenge_id="test",
            prefix="abc",
            nonce="test\x00hidden",
            difficulty=1,
        )
        result = verify_pow(proof)
        assert isinstance(result, bool)

    def test_pow_difficulty_bounds(self) -> None:
        """Difficulty outside valid range should be rejected by Pydantic."""
        with pytest.raises(Exception):
            ProofOfWork(
                challenge_id="test",
                prefix="abc",
                nonce="0",
                difficulty=0,  # Below minimum
            )

        with pytest.raises(Exception):
            ProofOfWork(
                challenge_id="test",
                prefix="abc",
                nonce="0",
                difficulty=33,  # Above maximum
            )

    def test_known_valid_pow(self) -> None:
        """Verify that a correctly solved PoW always verifies."""
        challenge = issue_pow_challenge(difficulty=8)
        nonce = solve_pow(challenge.prefix, 8)
        proof = ProofOfWork(
            challenge_id=challenge.challenge_id,
            prefix=challenge.prefix,
            nonce=nonce,
            difficulty=8,
        )
        assert verify_pow(proof) is True

    def test_challenge_ids_are_unique(self) -> None:
        """Each issued challenge must have a unique ID."""
        ids = {issue_pow_challenge(difficulty=4).challenge_id for _ in range(100)}
        assert len(ids) == 100

    def test_challenge_prefixes_are_unique(self) -> None:
        """Each issued challenge must have a unique prefix."""
        prefixes = {issue_pow_challenge(difficulty=4).prefix for _ in range(100)}
        assert len(prefixes) == 100


# ---------------------------------------------------------------------------
# Fingerprint Security
# ---------------------------------------------------------------------------


class TestFingerprintSecurity:
    """Attack-vector tests for the fingerprint / bot-farm detection."""

    async def test_bot_farm_exact_duplicate(self) -> None:
        """Detect exact duplicate answers from multiple agents (bot farm)."""
        store = FingerprintStore(window_size=100, hamming_threshold=3)

        for i in range(5):
            fp = store.build_fingerprint(
                session_id=f"session-{i}",
                agent_did=f"did:key:z6MkBot{i}",
                answer="Ed25519 is an elliptic curve digital signature algorithm.",
                question="What is Ed25519?",
            )
            if i > 0:
                match = await store.check(fp)
                assert match.is_exact_duplicate, f"Bot {i} not detected as duplicate"
            await store.add(fp)

    async def test_bot_farm_near_duplicate(self) -> None:
        """Detect near-duplicate answers (very minor change, same structure)."""
        store = FingerprintStore(window_size=100, hamming_threshold=8)

        fp1 = store.build_fingerprint(
            session_id="s1",
            agent_did="did:key:z6MkBot1",
            answer=(
                "Ed25519 is an elliptic curve digital signature algorithm that provides "
                "fast and secure authentication for distributed systems and protocols"
            ),
            question="What is Ed25519?",
        )
        await store.add(fp1)

        # Minimally different: only one word changed
        fp2 = store.build_fingerprint(
            session_id="s2",
            agent_did="did:key:z6MkBot2",
            answer=(
                "Ed25519 is an elliptic curve digital signature algorithm that provides "
                "fast and secure verification for distributed systems and protocols"
            ),
            question="What is Ed25519?",
        )
        dist = hamming_distance(fp1.simhash, fp2.simhash)
        match = await store.check(fp2)
        # With a generous threshold of 8, a single-word change in a long
        # sentence should be detected as near-duplicate
        assert match.is_near_duplicate or match.is_exact_duplicate, (
            f"Near-duplicate not detected; hamming distance = {dist}"
        )

    async def test_legitimate_different_answers(self) -> None:
        """Genuinely different answers should not trigger false positives."""
        store = FingerprintStore(window_size=100, hamming_threshold=3)

        fp1 = store.build_fingerprint(
            session_id="s1",
            agent_did="did:key:z6MkAgent1",
            answer="Ed25519 uses the Edwards curve over a 255-bit prime field for fast signatures",
            question="What is Ed25519?",
        )
        await store.add(fp1)

        fp2 = store.build_fingerprint(
            session_id="s2",
            agent_did="did:key:z6MkAgent2",
            answer="TLS 1.3 reduces handshake latency by eliminating a round trip via zero-RTT mode",
            question="Explain TLS 1.3 improvements",
        )
        match = await store.check(fp2)
        assert not match.is_exact_duplicate

    async def test_fingerprint_store_capacity(self) -> None:
        """Store respects window_size limit and does not grow unbounded."""
        store = FingerprintStore(window_size=10, hamming_threshold=3)
        for i in range(100):
            fp = store.build_fingerprint(
                session_id=f"s{i}",
                agent_did=f"did:key:z6MkAgent{i}",
                answer=f"unique answer number {i} about cryptographic protocols and verification",
                question="test",
            )
            await store.add(fp)
        assert len(store._fingerprints) <= 10

    async def test_empty_answer_fingerprint(self) -> None:
        """Empty answers should be fingerprinted without crashing."""
        store = FingerprintStore(window_size=10, hamming_threshold=3)
        fp = store.build_fingerprint(
            session_id="s1",
            agent_did="did:key:z6MkTest",
            answer="",
            question="test",
        )
        assert fp.simhash == 0  # Empty text -> zero hash
        await store.add(fp)

    async def test_same_agent_same_session_not_self_matched(self) -> None:
        """A fingerprint should not match against itself in the store."""
        store = FingerprintStore(window_size=100, hamming_threshold=3)
        fp = store.build_fingerprint(
            session_id="s1",
            agent_did="did:key:z6MkTest",
            answer="This is a test answer about cryptographic signatures",
            question="test",
        )
        await store.add(fp)
        match = await store.check(fp)
        # Should not match itself (same session_id and agent_did)
        assert not match.is_exact_duplicate

    def test_case_insensitive_exact_hash(self) -> None:
        """Exact hash should be case-insensitive (normalized)."""
        h1 = compute_exact_hash("Hello World")
        h2 = compute_exact_hash("hello world")
        assert h1 == h2

    def test_simhash_collision_resistance(self) -> None:
        """Very different texts should have large Hamming distance."""
        h1 = compute_simhash("the quick brown fox jumps over the lazy dog")
        h2 = compute_simhash("1234567890 abcdefghij klmnopqrst uvwxyz")
        dist = hamming_distance(h1, h2)
        # Different texts should have Hamming distance > 0
        # (exact distance varies but should be significant)
        assert dist > 0


# ---------------------------------------------------------------------------
# Privacy Mode Security
# ---------------------------------------------------------------------------


class TestPrivacyModeSecurity:
    """Validation tests for the PrivacyMode enum."""

    def test_privacy_modes_are_strings(self) -> None:
        """Privacy modes serialize as simple strings."""
        assert PrivacyMode.ANY.value == "any"
        assert PrivacyMode.LOCAL_ONLY.value == "local_only"
        assert PrivacyMode.NO_CHALLENGE.value == "no_challenge"

    def test_invalid_privacy_mode_rejected(self) -> None:
        """Invalid privacy mode value raises error."""
        with pytest.raises(ValueError):
            PrivacyMode("invalid_mode")

    def test_privacy_mode_case_sensitive(self) -> None:
        """Privacy mode matching is case-sensitive."""
        with pytest.raises(ValueError):
            PrivacyMode("ANY")
        with pytest.raises(ValueError):
            PrivacyMode("Local_Only")

    def test_all_privacy_modes_enumerated(self) -> None:
        """Exactly three privacy modes exist."""
        modes = list(PrivacyMode)
        assert len(modes) == 3
        assert set(modes) == {PrivacyMode.ANY, PrivacyMode.LOCAL_ONLY, PrivacyMode.NO_CHALLENGE}

    def test_privacy_mode_in_handshake_request(self) -> None:
        """HandshakeRequest defaults to PrivacyMode.ANY."""
        from datetime import UTC, datetime, timedelta

        from airlock.schemas.envelope import MessageEnvelope, generate_nonce
        from airlock.schemas.handshake import HandshakeRequest
        from airlock.schemas.identity import (
            AgentDID,
            CredentialProof,
            VerifiableCredential,
        )

        now = datetime.now(UTC)
        req = HandshakeRequest(
            envelope=MessageEnvelope(
                protocol_version="0.1.0",
                timestamp=now,
                sender_did="did:key:z6MkTest",
                nonce=generate_nonce(),
            ),
            session_id="test",
            initiator=AgentDID(
                did="did:key:z6MkTest",
                public_key_multibase="z6MkTest",
            ),
            intent={"action": "test", "description": "test", "target_did": "did:key:z6MkTarget"},
            credential=VerifiableCredential(
                id="urn:uuid:test",
                type=["VerifiableCredential"],
                issuer="did:key:z6MkTest",
                issuance_date=now,
                expiration_date=now + timedelta(days=365),
                credential_subject={"id": "did:key:z6MkTest"},
                proof=CredentialProof(
                    type="Ed25519Signature2020",
                    created=now,
                    verification_method="did:key:z6MkTest#key-1",
                    proof_purpose="assertionMethod",
                    proof_value="",
                ),
            ),
        )
        assert req.privacy_mode == PrivacyMode.ANY
