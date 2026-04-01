from __future__ import annotations

"""Demo scenario 2: Hollow identity agent.

This agent:
- Uses an unregistered DID
- Sends a HandshakeRequest with NO signature (or a forged one)
- Is rejected at the gateway HTTP layer (TransportNack) before reaching the orchestrator

Expected outcome: REJECTED immediately at gateway — invalid/missing signature.
The orchestrator is never invoked for this agent.
"""

import uuid
from datetime import UTC, datetime

import httpx

from airlock.crypto.keys import KeyPair
from airlock.schemas.envelope import create_envelope
from airlock.schemas.handshake import HandshakeIntent, HandshakeRequest
from airlock.schemas.identity import CredentialProof, VerifiableCredential

# A random seed — this agent is "hollow" (no trust, no registration)
_HOLLOW_SEED = b"hollow_agent_demo_seed__00000000"


def _build_fake_vc(agent_did: str) -> VerifiableCredential:
    """Build a plausible-looking but cryptographically invalid VC.

    The VC has a proof but the signature is a garbage base64 string — it will
    fail validation at the orchestrator level (though the gateway only checks
    the HandshakeRequest signature, not the VC at transport time).
    """
    now = datetime.now(UTC)
    from datetime import timedelta

    return VerifiableCredential(
        **{
            "@context": ["https://www.w3.org/2018/credentials/v1"],
            "id": f"{agent_did}#fake-vc-{uuid.uuid4().hex}",
            "type": ["VerifiableCredential", "AgentAuthorization"],
            "issuer": agent_did,  # self-signed — not trusted
            "issuance_date": now,
            "expiration_date": now + timedelta(days=365),
            "credential_subject": {"id": agent_did, "role": "impersonator"},
            "proof": CredentialProof(
                type="Ed25519Signature2020",
                created=now,
                verification_method=agent_did,
                proof_purpose="assertionMethod",
                proof_value="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",  # forged
            ),
        }
    )


async def run_hollow_scenario(http_client: httpx.AsyncClient) -> dict:
    """Run the hollow agent scenario via HTTP.

    The hollow agent sends a HandshakeRequest with no signature. The gateway's
    handle_handshake() function calls verify_model() → returns False → returns
    TransportNack immediately, before any event reaches the orchestrator.

    Args:
        http_client: An httpx.AsyncClient connected to the running gateway.

    Returns:
        dict with keys: scenario, verdict, session_id, rejection_reason, trace
    """
    hollow_kp = KeyPair.from_seed(_HOLLOW_SEED)

    envelope = create_envelope(sender_did=hollow_kp.did)
    fake_vc = _build_fake_vc(hollow_kp.did)
    session_id = str(uuid.uuid4())

    # Build request WITHOUT signing it — signature=None → gateway NACK
    req = HandshakeRequest(
        envelope=envelope,
        session_id=session_id,
        initiator=hollow_kp.to_agent_did(),
        intent=HandshakeIntent(
            action="exfiltrate_data",
            description="Attempting to access restricted data without credentials",
            target_did="did:key:z6MkAirlockGateway",
        ),
        credential=fake_vc,
        signature=None,  # <-- deliberately omitted
    )

    # POST to /handshake — expect TransportNack
    resp = await http_client.post(
        "/handshake",
        content=req.model_dump_json(),
        headers={"Content-Type": "application/json"},
    )

    data = resp.json()

    trace = [
        {
            "event": "http_response",
            "status_code": resp.status_code,
            "status": data.get("status"),
            "error_code": data.get("error_code"),
            "reason": data.get("reason"),
            "session_id": data.get("session_id"),
        }
    ]

    return {
        "scenario": "hollow",
        "agent_did": hollow_kp.did,
        "verdict": "REJECTED",
        "session_id": data.get("session_id", session_id),
        "rejection_reason": data.get("reason", "unknown"),
        "error_code": data.get("error_code", "unknown"),
        "trace": trace,
    }
