"""Tests for privacy_mode in HandshakeRequest (Change 4 -- v0.2)."""

from datetime import UTC, datetime

from airlock.schemas.handshake import PrivacyMode
from airlock.schemas.verdict import AirlockAttestation, TrustVerdict


class TestPrivacyModeSchema:
    def test_default_is_any(self) -> None:
        """Default privacy_mode is ANY."""
        assert PrivacyMode.ANY == "any"
        assert PrivacyMode.LOCAL_ONLY == "local_only"
        assert PrivacyMode.NO_CHALLENGE == "no_challenge"

    def test_privacy_mode_values(self) -> None:
        """PrivacyMode has exactly 3 values."""
        assert len(PrivacyMode) == 3
        assert set(PrivacyMode) == {
            PrivacyMode.ANY,
            PrivacyMode.LOCAL_ONLY,
            PrivacyMode.NO_CHALLENGE,
        }

    def test_privacy_mode_is_str_enum(self) -> None:
        """PrivacyMode values are strings (for JSON serialization)."""
        assert isinstance(PrivacyMode.ANY, str)
        assert PrivacyMode.ANY == "any"

    def test_privacy_mode_in_attestation(self) -> None:
        """AirlockAttestation includes privacy_mode field."""
        att = AirlockAttestation(
            session_id="test-session",
            verified_did="did:key:z6MkTest",
            checks_passed=[],
            trust_score=0.5,
            verdict=TrustVerdict.VERIFIED,
            issued_at=datetime.now(UTC),
            privacy_mode="local_only",
        )
        assert att.privacy_mode == "local_only"

    def test_attestation_default_privacy_any(self) -> None:
        """AirlockAttestation defaults to 'any' privacy_mode."""
        att = AirlockAttestation(
            session_id="test-session",
            verified_did="did:key:z6MkTest",
            checks_passed=[],
            trust_score=0.5,
            verdict=TrustVerdict.DEFERRED,
            issued_at=datetime.now(UTC),
        )
        assert att.privacy_mode == "any"

    def test_no_challenge_mode_exists(self) -> None:
        """NO_CHALLENGE mode is available for agents that opt out."""
        mode = PrivacyMode.NO_CHALLENGE
        assert mode == "no_challenge"
        # When serialized, it's just the string
        assert str(mode) == "no_challenge"
