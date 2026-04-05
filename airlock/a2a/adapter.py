from __future__ import annotations

"""A2A Adapter: bridge between Google A2A protocol types and Airlock schemas.

This module provides bidirectional conversion between:
  - A2A AgentCard  <-> Airlock AgentProfile
  - A2A Message    <-> Airlock HandshakeRequest
  - Airlock Attestation -> A2A Task metadata

Airlock does NOT replace A2A -- it layers trust on top. An agent that speaks
A2A can also carry Airlock trust metadata by embedding it in the standard
A2A metadata dictionaries.
"""

from datetime import UTC, datetime
from typing import Any

from a2a.types import (
    AgentCapabilities,
    AgentCard,
    AgentProvider,
    AgentSkill,
    Message,
    Part,
    Role,
    TextPart,
)
from pydantic import BaseModel, Field

from airlock.schemas.envelope import create_envelope
from airlock.schemas.handshake import HandshakeIntent, HandshakeRequest
from airlock.schemas.identity import (
    AgentCapability,
    AgentDID,
    AgentProfile,
    VerifiableCredential,
)
from airlock.schemas.verdict import AirlockAttestation


class AirlockAgentCard(BaseModel):
    """Extended A2A Agent Card with Airlock trust metadata.

    Standard A2A fields live on the `a2a_card` attribute.  Airlock adds
    DID-based identity and trust scoring on top.
    """

    a2a_card: AgentCard
    airlock_did: str
    airlock_public_key_multibase: str
    trust_score: float = Field(default=0.5, ge=0.0, le=1.0)
    airlock_protocol_version: str = "0.1.0"
    supports_semantic_challenge: bool = True

    model_config = {"arbitrary_types_allowed": True}


def agent_profile_to_a2a_card(
    profile: AgentProfile,
    *,
    provider_name: str = "Airlock Protocol",
    provider_url: str = "https://airlock.ing",
) -> AirlockAgentCard:
    """Convert an Airlock AgentProfile into an AirlockAgentCard (A2A-compatible).

    The returned object carries both the standard A2A AgentCard (for
    discovery, JSON-RPC transport) and the Airlock trust metadata
    (DID, public key, trust score).
    """
    skills = [
        AgentSkill(
            id=cap.name,
            name=cap.name,
            description=cap.description,
            tags=[cap.version],
        )
        for cap in profile.capabilities
    ]

    card = AgentCard(
        name=profile.display_name,
        description=f"Airlock-verified agent: {profile.display_name}",
        url=profile.endpoint_url,
        version=profile.protocol_versions[0] if profile.protocol_versions else "0.1.0",
        skills=skills,
        capabilities=AgentCapabilities(streaming=False, push_notifications=False),
        default_input_modes=["application/json"],
        default_output_modes=["application/json"],
        provider=AgentProvider(
            organization=provider_name,
            url=provider_url,
        ),
    )

    return AirlockAgentCard(
        a2a_card=card,
        airlock_did=profile.did.did,
        airlock_public_key_multibase=profile.did.public_key_multibase,
    )


def a2a_card_to_agent_profile(
    airlock_card: AirlockAgentCard,
) -> AgentProfile:
    """Convert an AirlockAgentCard back into an Airlock AgentProfile."""
    a2a = airlock_card.a2a_card

    capabilities = [
        AgentCapability(
            name=skill.name,
            version=skill.tags[0] if skill.tags else "1.0",
            description=skill.description,
        )
        for skill in a2a.skills
    ]

    return AgentProfile(
        did=AgentDID(
            did=airlock_card.airlock_did,
            public_key_multibase=airlock_card.airlock_public_key_multibase,
        ),
        display_name=a2a.name,
        capabilities=capabilities,
        endpoint_url=a2a.url,
        protocol_versions=[a2a.version],
        status="active",
        registered_at=datetime.now(UTC),
    )


def a2a_message_to_handshake_request(
    message: Message,
    sender_did: str,
    sender_public_key_multibase: str,
    target_did: str,
    credential: VerifiableCredential,
    session_id: str | None = None,
) -> HandshakeRequest:
    """Convert an A2A Message into an Airlock HandshakeRequest.

    A2A provides the transport envelope (message_id, parts, metadata).
    This function wraps it into Airlock's trust verification pipeline by
    extracting the intent from the message parts and metadata.
    """
    text_parts = [p.root.text for p in message.parts if isinstance(p.root, TextPart)]
    description = " ".join(text_parts) if text_parts else "A2A agent interaction"

    action = "connect"
    if message.metadata:
        action = message.metadata.get("airlock_action", "connect")

    envelope = create_envelope(sender_did=sender_did)

    return HandshakeRequest(
        envelope=envelope,
        session_id=session_id or message.message_id,
        initiator=AgentDID(
            did=sender_did,
            public_key_multibase=sender_public_key_multibase,
        ),
        intent=HandshakeIntent(
            action=action,
            description=description,
            target_did=target_did,
        ),
        credential=credential,
    )


def handshake_request_to_a2a_message(
    request: HandshakeRequest,
) -> Message:
    """Convert an Airlock HandshakeRequest into an A2A Message.

    Embeds the Airlock session metadata in the A2A message's metadata dict
    so the receiving agent can extract it if Airlock-aware, or ignore it
    if using vanilla A2A.
    """
    text = f"[Airlock Handshake] {request.intent.action}: {request.intent.description}"

    return Message(
        role=Role.user,
        message_id=request.session_id,
        parts=[Part(root=TextPart(text=text))],
        metadata={
            "airlock_session_id": request.session_id,
            "airlock_initiator_did": request.initiator.did,
            "airlock_target_did": request.intent.target_did,
            "airlock_action": request.intent.action,
            "airlock_protocol_version": request.envelope.protocol_version,
        },
    )


def airlock_attestation_to_a2a_metadata(
    attestation: AirlockAttestation,
) -> dict[str, Any]:
    """Serialize an AirlockAttestation into a flat dict suitable for
    embedding in an A2A Message or Task metadata field.

    This allows any A2A-aware agent to inspect trust verification results
    without needing the full Airlock SDK.
    """
    meta: dict[str, Any] = {
        "airlock_session_id": attestation.session_id,
        "airlock_verified_did": attestation.verified_did,
        "airlock_verdict": attestation.verdict.value,
        "airlock_trust_score": attestation.trust_score,
        "airlock_issued_at": attestation.issued_at.isoformat(),
        "airlock_checks": [
            {
                "check": c.check.value,
                "passed": c.passed,
                "detail": c.detail,
            }
            for c in attestation.checks_passed
        ],
    }
    if attestation.trust_token:
        meta["airlock_trust_token"] = attestation.trust_token
    rotation_chain_id = getattr(attestation, "rotation_chain_id", None)
    if rotation_chain_id is not None:
        meta["airlock_rotation_chain_id"] = rotation_chain_id
    return meta


def a2a_metadata_to_attestation_summary(
    metadata: dict[str, Any],
) -> dict[str, Any] | None:
    """Extract Airlock attestation fields from A2A metadata, if present.

    Returns None if the metadata does not contain Airlock fields.
    """
    if "airlock_verdict" not in metadata:
        return None

    summary: dict[str, Any] = {
        "session_id": metadata.get("airlock_session_id"),
        "verified_did": metadata.get("airlock_verified_did"),
        "verdict": metadata.get("airlock_verdict"),
        "trust_score": metadata.get("airlock_trust_score"),
        "issued_at": metadata.get("airlock_issued_at"),
        "checks": metadata.get("airlock_checks", []),
    }
    rotation_chain_id = metadata.get("airlock_rotation_chain_id")
    if rotation_chain_id is not None:
        summary["rotation_chain_id"] = rotation_chain_id
    return summary
