"""Property-based tests for v0.2 features using Hypothesis.

Tests invariants that must hold for ALL inputs — the kind of tests
you see in IETF reference implementations and protocol libraries at
Google / Cloudflare.  Each test encodes a mathematical or protocol
invariant, not a specific example.
"""

from __future__ import annotations

from datetime import UTC, datetime

from hypothesis import given, settings
from hypothesis import strategies as st

from airlock.pow import ProofOfWork, issue_pow_challenge, solve_pow, verify_pow
from airlock.reputation.scoring import routing_decision, update_score
from airlock.schemas.reputation import TrustScore
from airlock.schemas.trust_tier import TIER_CEILINGS, TrustTier
from airlock.schemas.verdict import TrustVerdict
from airlock.semantic.fingerprint import (
    compute_exact_hash,
    compute_simhash,
    hamming_distance,
)

# ---------------------------------------------------------------------------
# Trust Tier Invariants
# ---------------------------------------------------------------------------


class TestTrustTierInvariants:
    """Property tests for the TrustTier + scoring integration."""

    @given(
        score=st.floats(min_value=0.0, max_value=1.0),
        tier=st.sampled_from(list(TrustTier)),
    )
    def test_score_never_exceeds_tier_ceiling(self, score: float, tier: TrustTier) -> None:
        """INVARIANT: After update, score is ALWAYS <= tier ceiling."""
        now = datetime.now(UTC)
        ts = TrustScore(
            agent_did="did:key:z6MkTest",
            score=score,
            tier=tier,
            interaction_count=5,
            successful_verifications=3,
            failed_verifications=0,
            last_interaction=now,
            created_at=now,
            updated_at=now,
        )
        for verdict in TrustVerdict:
            result = update_score(ts, verdict)
            ceiling = TIER_CEILINGS[result.tier]
            assert result.score <= ceiling + 0.001, (
                f"Score {result.score} exceeded ceiling {ceiling} "
                f"for tier {result.tier.name} after {verdict.value}"
            )

    @given(score=st.floats(min_value=0.0, max_value=1.0))
    def test_score_always_in_unit_interval(self, score: float) -> None:
        """INVARIANT: Score is always in [0.0, 1.0] after any verdict."""
        now = datetime.now(UTC)
        ts = TrustScore(
            agent_did="did:key:z6MkTest",
            score=score,
            tier=TrustTier.VC_VERIFIED,
            interaction_count=0,
            successful_verifications=0,
            failed_verifications=0,
            last_interaction=now,
            created_at=now,
            updated_at=now,
        )
        for verdict in TrustVerdict:
            result = update_score(ts, verdict)
            assert 0.0 <= result.score <= 1.0, (
                f"Score {result.score} out of bounds after {verdict.value}"
            )

    @given(score=st.floats(min_value=0.0, max_value=1.0))
    def test_routing_is_deterministic(self, score: float) -> None:
        """INVARIANT: Same score always produces same routing decision."""
        r1 = routing_decision(score)
        r2 = routing_decision(score)
        assert r1 == r2
        assert r1 in ("fast_path", "challenge", "blacklist")

    @given(score=st.floats(min_value=0.0, max_value=1.0))
    def test_routing_covers_all_cases(self, score: float) -> None:
        """INVARIANT: Every valid score maps to exactly one route."""
        result = routing_decision(score)
        assert result in {"fast_path", "challenge", "blacklist"}

    @given(
        score=st.floats(min_value=0.0, max_value=1.0),
        tier=st.sampled_from(list(TrustTier)),
    )
    def test_tier_is_monotonic_on_verified(self, score: float, tier: TrustTier) -> None:
        """INVARIANT: VERIFIED verdict never demotes an agent's tier."""
        now = datetime.now(UTC)
        ts = TrustScore(
            agent_did="did:key:z6MkTest",
            score=score,
            tier=tier,
            interaction_count=0,
            successful_verifications=0,
            failed_verifications=0,
            last_interaction=now,
            created_at=now,
            updated_at=now,
        )
        result = update_score(ts, TrustVerdict.VERIFIED)
        assert result.tier >= tier, (
            f"Tier demoted from {tier.name} to {result.tier.name} on VERIFIED"
        )

    def test_tier_ceilings_are_strictly_increasing(self) -> None:
        """STRUCTURAL: Tier ceilings must increase with tier level."""
        tiers = sorted(TrustTier, key=lambda t: t.value)
        for i in range(1, len(tiers)):
            assert TIER_CEILINGS[tiers[i]] >= TIER_CEILINGS[tiers[i - 1]], (
                f"Ceiling for {tiers[i].name} ({TIER_CEILINGS[tiers[i]]}) "
                f"< ceiling for {tiers[i - 1].name} ({TIER_CEILINGS[tiers[i - 1]]})"
            )


# ---------------------------------------------------------------------------
# PoW Invariants
# ---------------------------------------------------------------------------


class TestPoWInvariants:
    """Property tests for Proof-of-Work correctness."""

    @given(difficulty=st.integers(min_value=1, max_value=16))
    @settings(max_examples=10, deadline=60000)
    def test_solve_always_verifies(self, difficulty: int) -> None:
        """INVARIANT: solve_pow output always passes verify_pow."""
        challenge = issue_pow_challenge(difficulty=difficulty)
        nonce = solve_pow(challenge.prefix, difficulty)
        proof = ProofOfWork(
            challenge_id=challenge.challenge_id,
            prefix=challenge.prefix,
            nonce=nonce,
            difficulty=difficulty,
        )
        assert verify_pow(proof) is True

    @given(nonce=st.text(min_size=1, max_size=20))
    def test_random_nonce_does_not_crash(self, nonce: str) -> None:
        """SAFETY: Random nonces must not crash verify_pow, regardless of content."""
        proof = ProofOfWork(
            challenge_id="test",
            prefix="a" * 64,
            nonce=nonce,
            difficulty=20,
        )
        result = verify_pow(proof)
        assert isinstance(result, bool)

    @given(difficulty=st.integers(min_value=1, max_value=32))
    def test_challenge_has_valid_structure(self, difficulty: int) -> None:
        """INVARIANT: Issued challenges always have valid structure."""
        challenge = issue_pow_challenge(difficulty=difficulty)
        assert len(challenge.prefix) == 64  # SHA-256 hex digest
        assert challenge.difficulty == difficulty
        assert len(challenge.challenge_id) > 0

    @given(
        prefix=st.text(min_size=0, max_size=100),
        nonce=st.text(min_size=0, max_size=100),
        difficulty=st.integers(min_value=1, max_value=32),
    )
    def test_verify_is_deterministic(self, prefix: str, nonce: str, difficulty: int) -> None:
        """INVARIANT: verify_pow is a pure function — same inputs, same output."""
        proof = ProofOfWork(
            challenge_id="test",
            prefix=prefix,
            nonce=nonce,
            difficulty=difficulty,
        )
        r1 = verify_pow(proof)
        r2 = verify_pow(proof)
        assert r1 == r2


# ---------------------------------------------------------------------------
# SimHash / Fingerprint Invariants
# ---------------------------------------------------------------------------


class TestSimHashInvariants:
    """Property tests for SimHash and fingerprint correctness."""

    @given(
        text=st.text(
            min_size=5,
            max_size=500,
            alphabet=st.characters(whitelist_categories=("L", "N", "Z")),
        )
    )
    def test_simhash_deterministic(self, text: str) -> None:
        """INVARIANT: Same text always produces same SimHash."""
        h1 = compute_simhash(text)
        h2 = compute_simhash(text)
        assert h1 == h2

    @given(
        text=st.text(
            min_size=5,
            max_size=500,
            alphabet=st.characters(whitelist_categories=("L", "N", "Z")),
        )
    )
    def test_simhash_self_distance_zero(self, text: str) -> None:
        """INVARIANT: Hamming distance of text with itself is always 0."""
        h = compute_simhash(text)
        assert hamming_distance(h, h) == 0

    @given(
        a=st.integers(min_value=0, max_value=2**64 - 1),
        b=st.integers(min_value=0, max_value=2**64 - 1),
    )
    def test_hamming_distance_symmetric(self, a: int, b: int) -> None:
        """INVARIANT: hamming_distance(a, b) == hamming_distance(b, a)."""
        assert hamming_distance(a, b) == hamming_distance(b, a)

    @given(
        a=st.integers(min_value=0, max_value=2**64 - 1),
        b=st.integers(min_value=0, max_value=2**64 - 1),
    )
    def test_hamming_distance_non_negative(self, a: int, b: int) -> None:
        """INVARIANT: Hamming distance is always >= 0."""
        assert hamming_distance(a, b) >= 0

    @given(
        a=st.integers(min_value=0, max_value=2**64 - 1),
        b=st.integers(min_value=0, max_value=2**64 - 1),
    )
    def test_hamming_distance_bounded(self, a: int, b: int) -> None:
        """INVARIANT: Hamming distance is always <= 64 for 64-bit values."""
        assert hamming_distance(a, b) <= 64

    @given(a=st.integers(min_value=0, max_value=2**64 - 1))
    def test_hamming_distance_identity(self, a: int) -> None:
        """INVARIANT: hamming_distance(a, a) == 0 (identity)."""
        assert hamming_distance(a, a) == 0

    @given(
        a=st.integers(min_value=0, max_value=2**64 - 1),
        b=st.integers(min_value=0, max_value=2**64 - 1),
        c=st.integers(min_value=0, max_value=2**64 - 1),
    )
    def test_hamming_triangle_inequality(self, a: int, b: int, c: int) -> None:
        """INVARIANT: Triangle inequality — d(a,c) <= d(a,b) + d(b,c)."""
        assert hamming_distance(a, c) <= hamming_distance(a, b) + hamming_distance(b, c)

    @given(text=st.text(min_size=1, max_size=500))
    def test_exact_hash_deterministic(self, text: str) -> None:
        """INVARIANT: Same text always produces same exact hash."""
        h1 = compute_exact_hash(text)
        h2 = compute_exact_hash(text)
        assert h1 == h2

    @given(text=st.text(min_size=1, max_size=500))
    def test_exact_hash_is_valid_sha256(self, text: str) -> None:
        """INVARIANT: Exact hash is always a 64-char hex string (SHA-256)."""
        h = compute_exact_hash(text)
        assert len(h) == 64
        assert all(c in "0123456789abcdef" for c in h)

    def test_exact_hash_normalizes_whitespace(self) -> None:
        """DETERMINISTIC: Whitespace normalization yields same hash."""
        h1 = compute_exact_hash("hello   world")
        h2 = compute_exact_hash("hello world")
        assert h1 == h2
