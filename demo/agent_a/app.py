"""Swiggy Order Agent — Uses Airlock Python SDK to verify counterparties."""

from __future__ import annotations

import asyncio
import logging
import os
import uuid
from contextlib import asynccontextmanager
from datetime import UTC, datetime

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from airlock.crypto.keys import KeyPair
from airlock.crypto.signing import sign_model
from airlock.crypto.vc import issue_credential
from airlock.schemas.envelope import MessageEnvelope, generate_nonce
from airlock.schemas.handshake import HandshakeIntent, HandshakeRequest
from airlock.schemas.identity import AgentCapability, AgentProfile

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(message)s")
logger = logging.getLogger("agent_a")

# ── Configuration ──────────────────────────────────────────────────────────
GATEWAY_URL = os.environ.get("AIRLOCK_GATEWAY_URL", "http://airlock-gateway:8000")
AGENT_SEED = os.environ.get("AGENT_A_SEED_HEX", "aa" * 32)
ISSUER_SEED = os.environ.get("ISSUER_SEED_HEX", "11" * 32)

# ── Keys ───────────────────────────────────────────────────────────────────
agent_kp = KeyPair.from_seed(bytes.fromhex(AGENT_SEED))
issuer_kp = KeyPair.from_seed(bytes.fromhex(ISSUER_SEED))

logger.info("Agent A DID: %s", agent_kp.did)
logger.info("Issuer DID:  %s", issuer_kp.did)


# ── Models ─────────────────────────────────────────────────────────────────
class OrderRequest(BaseModel):
    item: str
    quantity: int = 1
    delivery_address: str
    payment_agent_did: str  # DID of the payment agent to verify


class OrderResponse(BaseModel):
    order_id: str
    status: str
    verification_verdict: str
    trust_score: float
    message: str


# ── Startup ────────────────────────────────────────────────────────────────
async def register_with_gateway() -> None:
    """Register Agent A with the Airlock gateway on startup."""
    import httpx

    profile = AgentProfile(
        did=agent_kp.to_agent_did(),
        display_name="Swiggy Order Agent",
        capabilities=[
            AgentCapability(name="food_ordering", version="2.0", description="Process food delivery orders"),
            AgentCapability(name="logistics", version="1.5", description="Coordinate delivery routing"),
            AgentCapability(name="payments", version="1.0", description="Initiate payment collection"),
        ],
        endpoint_url="http://agent-a:5001",
        protocol_versions=["0.1.0"],
        status="active",
        registered_at=datetime.now(UTC),
    )

    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.post(
            f"{GATEWAY_URL}/register",
            json=profile.model_dump(mode="json"),
        )
        if resp.status_code == 200:
            logger.info("Registered with gateway: %s", resp.json())
        else:
            logger.warning("Registration failed (%d): %s", resp.status_code, resp.text)


@asynccontextmanager
async def lifespan(app: FastAPI):  # type: ignore[type-arg]
    """Register on startup, clean up on shutdown."""
    # Wait for gateway to be ready
    import httpx

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

    await register_with_gateway()
    yield


# ── App ────────────────────────────────────────────────────────────────────
app = FastAPI(
    title="Swiggy Order Agent",
    description="Food delivery order agent — verifies payment agents via Airlock Protocol",
    version="1.0.0",
    lifespan=lifespan,
)


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "healthy", "agent": "Swiggy Order Agent", "did": agent_kp.did}


@app.post("/order", response_model=OrderResponse)
async def place_order(order: OrderRequest) -> OrderResponse:
    """Place an order. First verifies the payment agent through Airlock."""
    order_id = str(uuid.uuid4())[:8]
    logger.info("Order %s: %dx %s to %s", order_id, order.quantity, order.item, order.delivery_address)
    logger.info("Verifying payment agent: %s", order.payment_agent_did)

    # ── Step 1: Issue a VC for this session ─────────────────────────────
    vc = issue_credential(
        issuer_key=issuer_kp,
        subject_did=agent_kp.did,
        credential_type="AgentAuthorization",
        claims={
            "role": "order_agent",
            "service": "food_delivery",
            "order_id": order_id,
        },
        validity_days=1,
    )

    # ── Step 2: Build signed handshake request ──────────────────────────
    session_id = str(uuid.uuid4())
    envelope = MessageEnvelope(
        protocol_version="0.1.0",
        timestamp=datetime.now(UTC),
        sender_did=agent_kp.did,
        nonce=generate_nonce(),
    )

    handshake = HandshakeRequest(
        envelope=envelope,
        session_id=session_id,
        initiator=agent_kp.to_agent_did(),
        intent=HandshakeIntent(
            action="payment_verification",
            description=f"Verify payment agent for order {order_id}",
            target_did=order.payment_agent_did,
        ),
        credential=vc,
    )
    handshake.signature = sign_model(handshake, agent_kp.signing_key)

    # ── Step 3: Send handshake to Airlock gateway ───────────────────────
    import httpx

    try:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.post(
                f"{GATEWAY_URL}/handshake",
                json=handshake.model_dump(mode="json"),
            )
            ack = resp.json()
            logger.info("Handshake response: %s", ack)

            if ack.get("status") == "REJECTED":
                return OrderResponse(
                    order_id=order_id,
                    status="FAILED",
                    verification_verdict="REJECTED",
                    trust_score=0.0,
                    message=f"Payment agent verification failed: {ack.get('reason', 'unknown')}",
                )

            # ── Step 4: Poll for verdict ────────────────────────────────
            session_view_token = ack.get("session_view_token")
            for _ in range(10):
                await asyncio.sleep(1)
                headers: dict[str, str] = {}
                if session_view_token:
                    headers["Authorization"] = f"Bearer {session_view_token}"

                session_resp = await client.get(
                    f"{GATEWAY_URL}/session/{session_id}",
                    headers=headers,
                )
                session_data = session_resp.json()
                state = session_data.get("state", "")

                if state in ("verdict_issued", "sealed"):
                    verdict = session_data.get("verdict", "UNKNOWN")
                    trust_score = session_data.get("trust_score", 0.0)
                    trust_token = session_data.get("trust_token")

                    logger.info("Verdict: %s (score: %.2f)", verdict, trust_score)

                    if verdict == "VERIFIED" and trust_token:
                        return OrderResponse(
                            order_id=order_id,
                            status="CONFIRMED",
                            verification_verdict=verdict,
                            trust_score=trust_score,
                            message=f"Order confirmed! Payment agent verified with trust score {trust_score:.2f}",
                        )
                    elif verdict == "DEFERRED":
                        return OrderResponse(
                            order_id=order_id,
                            status="PENDING",
                            verification_verdict=verdict,
                            trust_score=trust_score,
                            message="Payment agent under review — semantic challenge issued",
                        )
                    else:
                        return OrderResponse(
                            order_id=order_id,
                            status="FAILED",
                            verification_verdict=verdict,
                            trust_score=trust_score,
                            message=f"Payment agent not trusted: {verdict}",
                        )

            return OrderResponse(
                order_id=order_id,
                status="TIMEOUT",
                verification_verdict="TIMEOUT",
                trust_score=0.0,
                message="Verification timed out",
            )

    except Exception as e:
        logger.exception("Verification error")
        raise HTTPException(status_code=502, detail=f"Gateway error: {e}") from e


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=5001)
