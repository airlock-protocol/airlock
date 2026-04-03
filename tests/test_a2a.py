from __future__ import annotations

"""Tests for the A2A adapter module.

Covers bidirectional conversion between Google A2A types and Airlock schemas:
  - AgentProfile <-> AirlockAgentCard (with embedded A2A AgentCard)
  - A2A Message   -> Airlock HandshakeRequest
  - Airlock HandshakeRequest -> A2A Message
  - AirlockAttestation -> A2A-compatible metadata dict
  - A2A metadata -> Attestation summary extraction
"""

from datetime import UTC, datetime, timedelta

import pytest
from a2a.types import (
    AgentCapabilities,
    AgentCard,
    Message,
    Part,
    Role,
    TextPart,
)

from airlock.a2a.adapter import (
    AirlockAgentCard,
    a2a_card_to_agent_profile,
    a2a_message_to_handshake_request,
    a2a_metadata_to_attestation_summary,
    agent_profile_to_a2a_card,
    airlock_attestation_to_a2a_metadata,
    handshake_request_to_a2a_message,
)
from airlock.schemas.envelope import create_envelope
from airlock.schemas.handshake import HandshakeIntent, HandshakeRequest
from airlock.schemas.identity import (
    AgentCapability,
    AgentDID,
    AgentProfile,
    VerifiableCredential,
)
from airlock.schemas.verdict import (
    AirlockAttestation,
    CheckResult,
    TrustVerdict,
    VerificationCheck,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_profile() -> AgentProfile:
    return AgentProfile(
        did=AgentDID(did="did:key:z6MkTest123", public_key_multibase="z6MkTest123"),
        display_name="Test Agent",
        capabilities=[
            AgentCapability(name="data-fetch", version="2.0", description="Fetch data from APIs"),
            AgentCapability(name="summarize", version="1.0", description="Summarize text"),
        ],
        endpoint_url="https://agent.example.com/a2a",
        protocol_versions=["0.1.0"],
        status="active",
        registered_at=datetime.now(UTC),
    )


def _make_vc() -> VerifiableCredential:
    return VerifiableCredential(
        id="urn:uuid:test-vc-001",
        type=["Credential", "AgentAuthorization"],
        issuer="did:key:z6MkIssuer",
        issuance_date=datetime.now(UTC) - timedelta(days=1),
        expiration_date=datetime.now(UTC) + timedelta(days=365),
        credential_subject={"role": "agent"},
    )


def _make_a2a_message(text: str = "Hello, I need access to your data API") -> Message:
    return Message(
        role=Role.user,
        message_id="msg-001",
        parts=[Part(root=TextPart(text=text))],
        metadata={"airlock_action": "data_access"},
    )


def _make_attestation(verdict: TrustVerdict = TrustVerdict.VERIFIED) -> AirlockAttestation:
    return AirlockAttestation(
        session_id="sess-001",
        verified_did="did:key:z6MkTest123",
        checks_passed=[
            CheckResult(check=VerificationCheck.SCHEMA, passed=True, detail="OK"),
            CheckResult(check=VerificationCheck.SIGNATURE, passed=True, detail="Ed25519 valid"),
            CheckResult(check=VerificationCheck.REPUTATION, passed=True, detail="score=0.85"),
        ],
        trust_score=0.85,
        verdict=verdict,
        issued_at=datetime.now(UTC),
    )


# ---------------------------------------------------------------------------
# AgentProfile <-> AirlockAgentCard
# ---------------------------------------------------------------------------


class TestAgentProfileToA2ACard:
    def test_basic_conversion(self):
        profile = _make_profile()
        airlock_card = agent_profile_to_a2a_card(profile)

        assert isinstance(airlock_card, AirlockAgentCard)
        assert isinstance(airlock_card.a2a_card, AgentCard)

    def test_preserves_did_identity(self):
        profile = _make_profile()
        airlock_card = agent_profile_to_a2a_card(profile)

        assert airlock_card.airlock_did == "did:key:z6MkTest123"
        assert airlock_card.airlock_public_key_multibase == "z6MkTest123"

    def test_maps_display_name(self):
        profile = _make_profile()
        airlock_card = agent_profile_to_a2a_card(profile)

        assert airlock_card.a2a_card.name == "Test Agent"

    def test_maps_endpoint_url(self):
        profile = _make_profile()
        airlock_card = agent_profile_to_a2a_card(profile)

        assert airlock_card.a2a_card.url == "https://agent.example.com/a2a"

    def test_maps_capabilities_to_skills(self):
        profile = _make_profile()
        airlock_card = agent_profile_to_a2a_card(profile)

        skills = airlock_card.a2a_card.skills
        assert len(skills) == 2
        assert skills[0].name == "data-fetch"
        assert skills[0].description == "Fetch data from APIs"
        assert skills[0].tags == ["2.0"]

    def test_maps_version(self):
        profile = _make_profile()
        airlock_card = agent_profile_to_a2a_card(profile)

        assert airlock_card.a2a_card.version == "0.1.0"

    def test_custom_provider(self):
        profile = _make_profile()
        airlock_card = agent_profile_to_a2a_card(
            profile,
            provider_name="My Org",
            provider_url="https://myorg.example.com",
        )

        assert airlock_card.a2a_card.provider.organization == "My Org"
        assert airlock_card.a2a_card.provider.url == "https://myorg.example.com"

    def test_defaults_trust_score(self):
        profile = _make_profile()
        airlock_card = agent_profile_to_a2a_card(profile)

        assert airlock_card.trust_score == 0.5

    def test_supports_semantic_challenge(self):
        profile = _make_profile()
        airlock_card = agent_profile_to_a2a_card(profile)

        assert airlock_card.supports_semantic_challenge is True


class TestA2ACardToAgentProfile:
    def test_roundtrip_preserves_identity(self):
        original = _make_profile()
        card = agent_profile_to_a2a_card(original)
        restored = a2a_card_to_agent_profile(card)

        assert restored.did.did == original.did.did
        assert restored.did.public_key_multibase == original.did.public_key_multibase

    def test_roundtrip_preserves_name(self):
        original = _make_profile()
        card = agent_profile_to_a2a_card(original)
        restored = a2a_card_to_agent_profile(card)

        assert restored.display_name == "Test Agent"

    def test_roundtrip_preserves_capabilities(self):
        original = _make_profile()
        card = agent_profile_to_a2a_card(original)
        restored = a2a_card_to_agent_profile(card)

        assert len(restored.capabilities) == 2
        assert restored.capabilities[0].name == "data-fetch"
        assert restored.capabilities[1].name == "summarize"

    def test_roundtrip_preserves_endpoint(self):
        original = _make_profile()
        card = agent_profile_to_a2a_card(original)
        restored = a2a_card_to_agent_profile(card)

        assert restored.endpoint_url == "https://agent.example.com/a2a"

    def test_restored_status_is_active(self):
        original = _make_profile()
        card = agent_profile_to_a2a_card(original)
        restored = a2a_card_to_agent_profile(card)

        assert restored.status == "active"


# ---------------------------------------------------------------------------
# A2A Message -> Airlock HandshakeRequest
# ---------------------------------------------------------------------------


class TestA2AMessageToHandshakeRequest:
    def test_basic_conversion(self):
        message = _make_a2a_message()
        vc = _make_vc()

        request = a2a_message_to_handshake_request(
            message=message,
            sender_did="did:key:z6MkSender",
            sender_public_key_multibase="z6MkSender",
            target_did="did:key:z6MkTarget",
            credential=vc,
        )

        assert isinstance(request, HandshakeRequest)

    def test_maps_sender_did(self):
        message = _make_a2a_message()
        vc = _make_vc()

        request = a2a_message_to_handshake_request(
            message=message,
            sender_did="did:key:z6MkSender",
            sender_public_key_multibase="z6MkSender",
            target_did="did:key:z6MkTarget",
            credential=vc,
        )

        assert request.initiator.did == "did:key:z6MkSender"
        assert request.initiator.public_key_multibase == "z6MkSender"

    def test_maps_target_did(self):
        message = _make_a2a_message()
        vc = _make_vc()

        request = a2a_message_to_handshake_request(
            message=message,
            sender_did="did:key:z6MkSender",
            sender_public_key_multibase="z6MkSender",
            target_did="did:key:z6MkTarget",
            credential=vc,
        )

        assert request.intent.target_did == "did:key:z6MkTarget"

    def test_extracts_text_parts_as_description(self):
        message = _make_a2a_message("I need data access for analytics")
        vc = _make_vc()

        request = a2a_message_to_handshake_request(
            message=message,
            sender_did="did:key:z6MkSender",
            sender_public_key_multibase="z6MkSender",
            target_did="did:key:z6MkTarget",
            credential=vc,
        )

        assert request.intent.description == "I need data access for analytics"

    def test_extracts_action_from_metadata(self):
        message = _make_a2a_message()
        vc = _make_vc()

        request = a2a_message_to_handshake_request(
            message=message,
            sender_did="did:key:z6MkSender",
            sender_public_key_multibase="z6MkSender",
            target_did="did:key:z6MkTarget",
            credential=vc,
        )

        assert request.intent.action == "data_access"

    def test_default_action_when_no_metadata(self):
        message = Message(
            role=Role.user,
            message_id="msg-no-meta",
            parts=[Part(root=TextPart(text="hello"))],
        )
        vc = _make_vc()

        request = a2a_message_to_handshake_request(
            message=message,
            sender_did="did:key:z6MkSender",
            sender_public_key_multibase="z6MkSender",
            target_did="did:key:z6MkTarget",
            credential=vc,
        )

        assert request.intent.action == "connect"

    def test_uses_message_id_as_session_id(self):
        message = _make_a2a_message()
        vc = _make_vc()

        request = a2a_message_to_handshake_request(
            message=message,
            sender_did="did:key:z6MkSender",
            sender_public_key_multibase="z6MkSender",
            target_did="did:key:z6MkTarget",
            credential=vc,
        )

        assert request.session_id == "msg-001"

    def test_custom_session_id(self):
        message = _make_a2a_message()
        vc = _make_vc()

        request = a2a_message_to_handshake_request(
            message=message,
            sender_did="did:key:z6MkSender",
            sender_public_key_multibase="z6MkSender",
            target_did="did:key:z6MkTarget",
            credential=vc,
            session_id="custom-sess-42",
        )

        assert request.session_id == "custom-sess-42"

    def test_attaches_credential(self):
        message = _make_a2a_message()
        vc = _make_vc()

        request = a2a_message_to_handshake_request(
            message=message,
            sender_did="did:key:z6MkSender",
            sender_public_key_multibase="z6MkSender",
            target_did="did:key:z6MkTarget",
            credential=vc,
        )

        assert request.credential.issuer == "did:key:z6MkIssuer"
        assert not request.credential.is_expired()


# ---------------------------------------------------------------------------
# Airlock HandshakeRequest -> A2A Message
# ---------------------------------------------------------------------------


class TestHandshakeRequestToA2AMessage:
    def test_basic_conversion(self):
        profile = _make_profile()
        vc = _make_vc()
        envelope = create_envelope("did:key:z6MkTest123")

        request = HandshakeRequest(
            envelope=envelope,
            session_id="sess-123",
            initiator=profile.did,
            intent=HandshakeIntent(
                action="connect",
                description="testing",
                target_did="did:key:z6MkTarget",
            ),
            credential=vc,
        )

        msg = handshake_request_to_a2a_message(request)

        assert isinstance(msg, Message)
        assert msg.role == Role.user
        assert msg.message_id == "sess-123"

    def test_embeds_airlock_metadata(self):
        profile = _make_profile()
        vc = _make_vc()
        envelope = create_envelope("did:key:z6MkTest123")

        request = HandshakeRequest(
            envelope=envelope,
            session_id="sess-456",
            initiator=profile.did,
            intent=HandshakeIntent(
                action="data_access",
                description="need data",
                target_did="did:key:z6MkTarget",
            ),
            credential=vc,
        )

        msg = handshake_request_to_a2a_message(request)

        assert msg.metadata is not None
        assert msg.metadata["airlock_session_id"] == "sess-456"
        assert msg.metadata["airlock_initiator_did"] == "did:key:z6MkTest123"
        assert msg.metadata["airlock_target_did"] == "did:key:z6MkTarget"
        assert msg.metadata["airlock_action"] == "data_access"

    def test_text_part_contains_intent(self):
        profile = _make_profile()
        vc = _make_vc()
        envelope = create_envelope("did:key:z6MkTest123")

        request = HandshakeRequest(
            envelope=envelope,
            session_id="sess-789",
            initiator=profile.did,
            intent=HandshakeIntent(
                action="query",
                description="run analytics query",
                target_did="did:key:z6MkTarget",
            ),
            credential=vc,
        )

        msg = handshake_request_to_a2a_message(request)

        text = msg.parts[0].root.text
        assert "query" in text
        assert "run analytics query" in text


# ---------------------------------------------------------------------------
# AirlockAttestation -> A2A metadata
# ---------------------------------------------------------------------------


class TestAttestationToA2AMetadata:
    def test_basic_conversion(self):
        attestation = _make_attestation()
        meta = airlock_attestation_to_a2a_metadata(attestation)

        assert isinstance(meta, dict)
        assert meta["airlock_verdict"] == "VERIFIED"

    def test_includes_session_id(self):
        attestation = _make_attestation()
        meta = airlock_attestation_to_a2a_metadata(attestation)

        assert meta["airlock_session_id"] == "sess-001"

    def test_includes_trust_score(self):
        attestation = _make_attestation()
        meta = airlock_attestation_to_a2a_metadata(attestation)

        assert meta["airlock_trust_score"] == 0.85

    def test_includes_verified_did(self):
        attestation = _make_attestation()
        meta = airlock_attestation_to_a2a_metadata(attestation)

        assert meta["airlock_verified_did"] == "did:key:z6MkTest123"

    def test_includes_checks(self):
        attestation = _make_attestation()
        meta = airlock_attestation_to_a2a_metadata(attestation)

        checks = meta["airlock_checks"]
        assert len(checks) == 3
        assert checks[0]["check"] == "schema"
        assert checks[0]["passed"] is True
        assert checks[1]["check"] == "signature"

    def test_rejected_verdict(self):
        attestation = _make_attestation(TrustVerdict.REJECTED)
        meta = airlock_attestation_to_a2a_metadata(attestation)

        assert meta["airlock_verdict"] == "REJECTED"

    def test_deferred_verdict(self):
        attestation = _make_attestation(TrustVerdict.DEFERRED)
        meta = airlock_attestation_to_a2a_metadata(attestation)

        assert meta["airlock_verdict"] == "DEFERRED"

    def test_issued_at_is_iso_string(self):
        attestation = _make_attestation()
        meta = airlock_attestation_to_a2a_metadata(attestation)

        assert isinstance(meta["airlock_issued_at"], str)
        datetime.fromisoformat(meta["airlock_issued_at"])


# ---------------------------------------------------------------------------
# A2A metadata -> Attestation summary extraction
# ---------------------------------------------------------------------------


class TestMetadataToAttestationSummary:
    def test_extracts_from_valid_metadata(self):
        attestation = _make_attestation()
        meta = airlock_attestation_to_a2a_metadata(attestation)

        summary = a2a_metadata_to_attestation_summary(meta)

        assert summary is not None
        assert summary["verdict"] == "VERIFIED"
        assert summary["trust_score"] == 0.85
        assert summary["session_id"] == "sess-001"

    def test_returns_none_for_non_airlock_metadata(self):
        meta = {"some_key": "some_value"}
        summary = a2a_metadata_to_attestation_summary(meta)

        assert summary is None

    def test_returns_none_for_empty_metadata(self):
        summary = a2a_metadata_to_attestation_summary({})

        assert summary is None

    def test_roundtrip_preserves_checks(self):
        attestation = _make_attestation()
        meta = airlock_attestation_to_a2a_metadata(attestation)
        summary = a2a_metadata_to_attestation_summary(meta)

        assert len(summary["checks"]) == 3
        assert summary["checks"][0]["check"] == "schema"
        assert summary["checks"][2]["check"] == "reputation"


# ---------------------------------------------------------------------------
# AirlockAgentCard model validation
# ---------------------------------------------------------------------------


class TestAirlockAgentCardValidation:
    def test_trust_score_bounds_lower(self):
        with pytest.raises(Exception):
            AirlockAgentCard(
                a2a_card=AgentCard(
                    name="test",
                    description="test",
                    url="http://test",
                    version="1.0",
                    skills=[],
                    capabilities=AgentCapabilities(streaming=False, pushNotifications=False),
                    default_input_modes=["text/plain"],
                    default_output_modes=["text/plain"],
                ),
                airlock_did="did:key:z6MkTest",
                airlock_public_key_multibase="z6MkTest",
                trust_score=-0.1,
            )

    def test_trust_score_bounds_upper(self):
        with pytest.raises(Exception):
            AirlockAgentCard(
                a2a_card=AgentCard(
                    name="test",
                    description="test",
                    url="http://test",
                    version="1.0",
                    skills=[],
                    capabilities=AgentCapabilities(streaming=False, pushNotifications=False),
                    default_input_modes=["text/plain"],
                    default_output_modes=["text/plain"],
                ),
                airlock_did="did:key:z6MkTest",
                airlock_public_key_multibase="z6MkTest",
                trust_score=1.1,
            )

    def test_extension_uri_doc_placeholder(self):
        # Canonical URI for future A2A extension registration (not exported from adapter).
        uri = "https://airlock.ing/extensions/trust/v1"
        assert "airlock" in uri
        assert "/trust/" in uri
