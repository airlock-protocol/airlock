from __future__ import annotations

"""Demo scenario 4: A2A-native agent verified through Airlock.

This agent:
- Speaks the Google A2A protocol (uses A2A Message format)
- Has a valid Ed25519 keypair and VC
- Registers via the /a2a/register endpoint
- Requests verification via /a2a/verify
- Receives Airlock trust metadata in A2A-compatible format

Expected outcome: Verification result (DEFERRED at default 0.5 score)
with A2A-compatible metadata that the agent can embed in future A2A messages.

This demonstrates that an A2A-native agent can use Airlock's trust layer
without needing the Airlock SDK -- just standard HTTP + JSON.
"""

from datetime import datetime, timezone

from httpx import AsyncClient

from airlock.crypto.keys import KeyPair
from airlock.crypto.vc import issue_credential

_A2A_AGENT_SEED = b"a2a_demo_agent_seed_000000000000"
_ISSUER_SEED = b"trusted_issuer_keypair_seed_0000"


async def run_a2a_scenario(client: AsyncClient, airlock_did: str) -> dict:
    """Run the A2A-native agent scenario using HTTP endpoints.

    Steps:
    1. Create agent keypair and VC
    2. Fetch the gateway's A2A Agent Card (discovery)
    3. Register via /a2a/register
    4. Submit verification request via /a2a/verify
    5. Inspect the returned A2A-compatible trust metadata
    """
    agent_kp = KeyPair.from_seed(_A2A_AGENT_SEED)
    issuer_kp = KeyPair.from_seed(_ISSUER_SEED)

    vc = issue_credential(
        issuer_key=issuer_kp,
        subject_did=agent_kp.did,
        credential_type="AgentAuthorization",
        claims={
            "role": "analytics_agent",
            "authorization_level": "standard",
            "domain": "business_intelligence",
        },
        validity_days=365,
    )

    trace: list[dict] = []
    result: dict = {
        "scenario": "a2a_native",
        "agent_did": agent_kp.did,
        "verdict": None,
        "trust_score": None,
        "trace": trace,
    }

    # Step 1: Discover the gateway via A2A Agent Card
    card_resp = await client.get("/a2a/agent-card")
    card_data = card_resp.json()
    trace.append({
        "event": "a2a_discovery",
        "gateway_name": card_data["a2a_card"]["name"],
        "gateway_did": card_data["airlock_did"],
        "skills": [s["name"] for s in card_data["a2a_card"]["skills"]],
    })

    # Step 2: Register via A2A-style endpoint
    reg_resp = await client.post("/a2a/register", json={
        "did": agent_kp.did,
        "public_key_multibase": agent_kp.public_key_multibase,
        "display_name": "A2A Analytics Agent",
        "endpoint_url": "https://agents.example.com/analytics",
        "skills": [
            {"name": "data_analysis", "version": "2.0", "description": "Analyze business data"},
            {"name": "report_gen", "version": "1.5", "description": "Generate PDF reports"},
        ],
    })
    reg_data = reg_resp.json()
    trace.append({
        "event": "a2a_registration",
        "registered": reg_data["registered"],
        "format": reg_data["format"],
    })

    # Step 3: Verify via /a2a/verify (A2A message format)
    verify_resp = await client.post("/a2a/verify", json={
        "sender_did": agent_kp.did,
        "sender_public_key_multibase": agent_kp.public_key_multibase,
        "target_did": airlock_did,
        "credential": vc.model_dump(mode="json", by_alias=True),
        "message_parts": [
            {"type": "text", "text": "Requesting access to quarterly sales data for BI dashboard"},
        ],
        "message_metadata": {
            "airlock_action": "data_access",
            "context": "Q4 2025 analytics pipeline",
        },
    })
    verify_data = verify_resp.json()

    result["verdict"] = verify_data["verdict"]
    result["trust_score"] = verify_data["trust_score"]
    result["session_id"] = verify_data["session_id"]

    trace.append({
        "event": "a2a_verification",
        "session_id": verify_data["session_id"],
        "verdict": verify_data["verdict"],
        "trust_score": verify_data["trust_score"],
        "checks": verify_data["checks"],
    })

    # Step 4: Show the A2A metadata that can be embedded in future messages
    a2a_meta = verify_data["a2a_metadata"]
    trace.append({
        "event": "a2a_metadata_received",
        "airlock_verdict": a2a_meta["airlock_verdict"],
        "airlock_trust_score": a2a_meta["airlock_trust_score"],
        "airlock_session_id": a2a_meta["airlock_session_id"],
        "checks_count": len(a2a_meta["airlock_checks"]),
    })

    # Step 5: Verify the agent is now resolvable via standard Airlock /resolve
    resolve_resp = await client.post("/resolve", json={"target_did": agent_kp.did})
    resolve_data = resolve_resp.json()
    trace.append({
        "event": "cross_protocol_resolve",
        "found": resolve_data["found"],
        "display_name": resolve_data.get("profile", {}).get("display_name", "N/A"),
    })

    return result
