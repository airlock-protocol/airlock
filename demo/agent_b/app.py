"""Payment Gateway Agent — Uses raw A2A HTTP (no Airlock SDK) to verify counterparties."""

from __future__ import annotations

import asyncio
import logging
import os
import uuid
from contextlib import asynccontextmanager
from typing import Any

import httpx
from fastapi import FastAPI
from nacl.signing import SigningKey
from pydantic import BaseModel

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(message)s")
logger = logging.getLogger("agent_b")

# ── Configuration ──────────────────────────────────────────────────────────
GATEWAY_URL = os.environ.get("AIRLOCK_GATEWAY_URL", "http://airlock-gateway:8000")
AGENT_SEED = os.environ.get("AGENT_B_SEED_HEX", "bb" * 32)
ISSUER_SEED = os.environ.get("ISSUER_SEED_HEX", "11" * 32)


# ── Minimal crypto (no SDK dependency) ─────────────────────────────────────
def _seed_to_did(seed_hex: str) -> tuple[SigningKey, str, str]:
    """Generate Ed25519 key + DID:key from hex seed. No SDK needed."""
    import base58

    sk = SigningKey(bytes.fromhex(seed_hex))
    vk = sk.verify_key
    raw = vk.encode()
    multicodec = b"\xed\x01" + raw
    encoded = base58.b58encode(multicodec).decode("ascii")
    multibase = f"z{encoded}"
    did = f"did:key:{multibase}"
    return sk, did, multibase


agent_sk, agent_did, agent_pub_multibase = _seed_to_did(AGENT_SEED)
issuer_sk, issuer_did, issuer_pub_multibase = _seed_to_did(ISSUER_SEED)

logger.info("Agent B DID: %s", agent_did)
logger.info("Issuer DID:  %s", issuer_did)


# ── Models ─────────────────────────────────────────────────────────────────
class PaymentRequest(BaseModel):
    order_id: str
    amount: float
    currency: str = "INR"
    trust_token: str | None = None  # JWT from Airlock if pre-verified


class PaymentResponse(BaseModel):
    payment_id: str
    order_id: str
    status: str
    message: str
    verified_by_airlock: bool


class A2AVerifyResult(BaseModel):
    session_id: str
    verdict: str
    trust_score: float
    checks: list[dict[str, Any]]
    trust_token: str | None = None
    challenge: dict[str, Any] | None = None


# ── A2A Registration ───────────────────────────────────────────────────────
async def register_via_a2a() -> None:
    """Register with gateway using A2A protocol (no SDK)."""
    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.post(
            f"{GATEWAY_URL}/a2a/register",
            json={
                "did": agent_did,
                "public_key_multibase": agent_pub_multibase,
                "display_name": "Payment Gateway Agent",
                "endpoint_url": "http://agent-b:5002",
                "skills": [
                    {"name": "payment_processing", "version": "3.0"},
                    {"name": "fraud_detection", "version": "2.1"},
                    {"name": "settlement", "version": "1.0"},
                ],
                "protocol_versions": ["0.1.0"],
            },
        )
        if resp.status_code == 200:
            logger.info("Registered via A2A: %s", resp.json())
        else:
            logger.warning("A2A registration failed (%d): %s", resp.status_code, resp.text)


async def discover_gateway() -> dict[str, Any]:
    """Discover the Airlock gateway via A2A agent card."""
    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.get(f"{GATEWAY_URL}/a2a/agent-card")
        card = resp.json()
        logger.info("Gateway agent card: DID=%s", card.get("airlock_did", "unknown"))
        return card


@asynccontextmanager
async def lifespan(app: FastAPI):  # type: ignore[type-arg]
    """Discover gateway + register on startup."""
    for attempt in range(15):
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                resp = await client.get(f"{GATEWAY_URL}/live")
                if resp.status_code == 200:
                    logger.info("Gateway is live")
                    break
        except Exception:
            pass
        logger.info("Waiting for gateway (attempt %d/15)...", attempt + 1)
        await asyncio.sleep(2)

    await discover_gateway()
    await register_via_a2a()
    yield


# ── App ────────────────────────────────────────────────────────────────────
app = FastAPI(
    title="Payment Gateway Agent",
    description="Processes payments — verifies order agents via A2A + Airlock Protocol",
    version="1.0.0",
    lifespan=lifespan,
)


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "healthy", "agent": "Payment Gateway Agent", "did": agent_did}


@app.post("/process-payment", response_model=PaymentResponse)
async def process_payment(payment: PaymentRequest) -> PaymentResponse:
    """Process a payment. If trust_token provided, validates it. Otherwise, rejects."""
    payment_id = str(uuid.uuid4())[:8]
    logger.info("Payment %s: %s %.2f for order %s", payment_id, payment.currency, payment.amount, payment.order_id)

    if not payment.trust_token:
        return PaymentResponse(
            payment_id=payment_id,
            order_id=payment.order_id,
            status="REJECTED",
            message="No trust token provided — cannot verify sender",
            verified_by_airlock=False,
        )

    # ── Validate trust token via Airlock introspection ──────────────────
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(
                f"{GATEWAY_URL}/token/introspect",
                json={"token": payment.trust_token},
            )
            token_data = resp.json()
            logger.info("Token introspection: %s", token_data)

            if token_data.get("valid"):
                return PaymentResponse(
                    payment_id=payment_id,
                    order_id=payment.order_id,
                    status="PROCESSED",
                    message=f"Payment processed! Sender verified (DID: {token_data.get('sub', 'unknown')})",
                    verified_by_airlock=True,
                )
            else:
                return PaymentResponse(
                    payment_id=payment_id,
                    order_id=payment.order_id,
                    status="REJECTED",
                    message=f"Trust token invalid: {token_data.get('error', 'unknown')}",
                    verified_by_airlock=False,
                )
    except Exception as e:
        logger.exception("Token introspection failed")
        return PaymentResponse(
            payment_id=payment_id,
            order_id=payment.order_id,
            status="ERROR",
            message=f"Verification error: {e}",
            verified_by_airlock=False,
        )


@app.post("/verify-sender")
async def verify_sender(sender_did: str) -> A2AVerifyResult:
    """Verify a sender agent using A2A protocol (raw HTTP, no SDK)."""
    logger.info("Verifying sender via A2A: %s", sender_did)

    # This endpoint demonstrates the A2A verify flow from Agent B's perspective
    # In a real scenario, Agent B would call this before accepting work from Agent A

    # Note: A full A2A verify requires building a signed HandshakeRequest
    # For the demo, we show the discovery + registration path
    # The actual verification happens when Agent A calls /handshake through the gateway

    async with httpx.AsyncClient(timeout=10) as client:
        # Check reputation
        resp = await client.get(f"{GATEWAY_URL}/reputation/{sender_did}")
        rep_data = resp.json()

        return A2AVerifyResult(
            session_id="check-only",
            verdict="CHECKED",
            trust_score=rep_data.get("trust_score", 0.0),
            checks=[{"check": "reputation_lookup", "passed": True, "detail": str(rep_data)}],
        )


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=5002)
