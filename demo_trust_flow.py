"""
demo_trust_flow.py — Agentic Airlock Trust Verification Demo
============================================================
Run against a live gateway:  python demo_trust_flow.py

Requires the gateway to be running:
  python -m uvicorn airlock.gateway.app:create_app --factory --port 8000 --env-file .env

Scenarios:
  1. Legitimate agent (MerchantPayBot) → VERIFIED
  2. Rogue agent (tampered signature)    → REJECTED
  3. Replay attack (same nonce twice)    → BLOCKED
"""

from __future__ import annotations

import asyncio
import sys
import time

# Force UTF-8 output on Windows so box-drawing characters render correctly
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
import uuid
from datetime import UTC, datetime

import httpx

from airlock.crypto.keys import KeyPair
from airlock.crypto.signing import sign_model
from airlock.schemas.envelope import create_envelope
from airlock.schemas.reputation import SignedFeedbackReport
from airlock.sdk.simple import build_signed_handshake, ensure_registered_profile

GATEWAY = "http://localhost:8000"


# ─────────────────────────────────────────────────────────────────────────────
# Print helpers
# ─────────────────────────────────────────────────────────────────────────────

def _banner(title: str) -> None:
    print()
    print("═" * 55)
    print(f"  {title}")
    print("═" * 55)
    print()


def _step(n: int, msg: str) -> None:
    print(f"[Step {n}] {msg}")


def _ok(msg: str) -> None:
    print(f"         ✓ {msg}")


def _fail(msg: str) -> None:
    print(f"         ✗ {msg}")


def _info(msg: str) -> None:
    print(f"         → {msg}")


# ─────────────────────────────────────────────────────────────────────────────
# Gateway helpers
# ─────────────────────────────────────────────────────────────────────────────

async def _gateway_did(client: httpx.AsyncClient) -> str:
    """Fetch the gateway's own DID from /health."""
    r = await client.get(f"{GATEWAY}/health")
    r.raise_for_status()
    return r.json()["airlock_did"]


async def _check_gateway(client: httpx.AsyncClient) -> bool:
    try:
        r = await client.get(f"{GATEWAY}/live", timeout=3)
        return r.status_code == 200
    except Exception:
        return False


async def _poll_verdict(
    client: httpx.AsyncClient,
    session_id: str,
    *,
    token: str | None = None,
    max_wait: float = 10.0,
) -> dict | None:
    """Poll GET /session/{id} until verdict is set or timeout."""
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    deadline = time.monotonic() + max_wait
    while time.monotonic() < deadline:
        r = await client.get(
            f"{GATEWAY}/session/{session_id}", headers=headers
        )
        if r.status_code == 200:
            data = r.json()
            if data.get("verdict"):
                return data
        await asyncio.sleep(0.02)
    return None


async def _boost_reputation(
    client: httpx.AsyncClient,
    reporter_kp: KeyPair,
    subject_did: str,
    count: int = 7,
) -> bool:
    """Send `count` positive signed feedbacks to push subject_did into fast-path (≥0.75)."""
    for _ in range(count):
        report = SignedFeedbackReport(
            session_id=str(uuid.uuid4()),
            reporter_did=reporter_kp.did,
            subject_did=subject_did,
            rating="positive",
            detail="Known registered payment agent — verified by trust reporter",
            timestamp=datetime.now(UTC),
            envelope=create_envelope(sender_did=reporter_kp.did),
            signature=None,
        )
        report.signature = sign_model(report, reporter_kp.signing_key)
        r = await client.post(
            f"{GATEWAY}/feedback", json=report.model_dump(mode="json")
        )
        if r.status_code != 200:
            return False
    return True


# ─────────────────────────────────────────────────────────────────────────────
# Scenario 1: Legitimate agent → VERIFIED
# ─────────────────────────────────────────────────────────────────────────────

async def scenario_verified(
    client: httpx.AsyncClient, gateway_did: str
) -> tuple[bool, float]:
    _banner("SCENARIO 1 — LEGITIMATE AGENT: MerchantPayBot")
    t0 = time.perf_counter()

    agent_kp = KeyPair.generate()
    issuer_kp = KeyPair.generate()   # credential issuer
    reporter_kp = KeyPair.generate()  # trust reporter agent

    # ── Step 1: Register ─────────────────────────────────────────────────────
    _step(1, 'Registering agent "MerchantPayBot"...')
    _info(f"DID: {agent_kp.did[:46]}...")
    profile = ensure_registered_profile(
        agent_kp,
        display_name="MerchantPayBot",
        endpoint_url="https://agents.example.com/payment",
        capabilities=[
            ("payment_transfer", "1.0", "Execute payment transfers on behalf of users"),
            ("refund_processing", "1.0", "Process and track refund transactions"),
        ],
    )
    r = await client.post(
        f"{GATEWAY}/register", json=profile.model_dump(mode="json")
    )
    if r.status_code != 200 or not r.json().get("registered"):
        _fail(f"Registration failed: {r.text}")
        return False, 0.0
    _ok("Agent registered successfully")

    # ── Step 2: Build trust score via positive reputation signals ─────────────────
    _step(2, "Seeding reputation via trust signals...")
    _info("Submitting 7 positive trust signals")
    boosted = await _boost_reputation(client, reporter_kp, agent_kp.did, count=7)
    if not boosted:
        _fail("Reputation boost failed")
        return False, 0.0
    r = await client.get(f"{GATEWAY}/reputation/{agent_kp.did}")
    score_before = r.json().get("score", 0.0) if r.status_code == 200 else 0.0
    _ok(f"Trust score: {score_before:.4f}  (fast-path threshold: ≥0.75)")

    # ── Step 3: Handshake ─────────────────────────────────────────────────────
    _step(3, "Initiating trust handshake...")
    _info("POST /handshake")
    hs = build_signed_handshake(
        agent_kp,
        issuer_kp,
        target_did=gateway_did,
        action="request_payment_authorization",
        description="MerchantPayBot requesting payment transfer authorization for order #ORD-20260330",
        claims={
            "role": "payment_agent",
            "platform": "merchant_app",
            "max_txn_inr": 50000,
            "user_consent": "verified",
        },
    )
    r = await client.post(f"{GATEWAY}/handshake", json=hs.model_dump(mode="json"))
    if r.status_code != 200:
        _fail(f"Handshake HTTP {r.status_code}: {r.text}")
        return False, 0.0
    ack = r.json()
    if ack.get("status") != "ACCEPTED":
        _fail(f"Handshake NACK — {ack.get('reason')}")
        return False, 0.0
    session_id = ack["session_id"]
    session_view_token: str | None = ack.get("session_view_token")
    _ok(f"Challenge accepted  (session: {session_id[:18]}...)")
    _info("Challenge type: cryptographic (Ed25519 + VC)")

    # ── Step 4: Poll for verdict ──────────────────────────────────────────────
    _step(4, "Awaiting verification verdict...")
    _info(f"GET /session/{session_id[:18]}... (polling)")
    session = await _poll_verdict(
        client, session_id, token=session_view_token, max_wait=10.0
    )
    if session is None:
        _fail("Timed out waiting for verdict")
        return False, 0.0

    elapsed = (time.perf_counter() - t0) * 1000
    verdict = session.get("verdict", "UNKNOWN")
    trust_score = session.get("trust_score", 0.0)
    trust_token: str | None = session.get("trust_token")

    if verdict == "VERIFIED":
        _ok("Verification: PASSED")
        _info("Verdict:       VERIFIED")
        _info(f"Trust score:   {trust_score:.4f}")
        if trust_token:
            _info(f"Trust token:   {trust_token[:40]}... (valid 600s)")
        print()
        print(f"   ⏱  End-to-end: {elapsed:.1f}ms")
        return True, elapsed
    else:
        _fail(f"Unexpected verdict: {verdict}")
        return False, elapsed


# ─────────────────────────────────────────────────────────────────────────────
# Scenario 2: Rogue agent → REJECTED
# ─────────────────────────────────────────────────────────────────────────────

async def scenario_rejected(
    client: httpx.AsyncClient, gateway_did: str
) -> tuple[bool, float]:
    _banner("SCENARIO 2 — ROGUE AGENT (Tampered Signature)")
    t0 = time.perf_counter()

    rogue_kp = KeyPair.generate()
    wrong_kp = KeyPair.generate()   # attacker's key — used to forge the signature
    issuer_kp = KeyPair.generate()

    _step(1, "Unregistered agent builds a handshake...")
    _info(f"DID: {rogue_kp.did[:46]}...")
    _info("(No prior registration in gateway registry)")

    hs = build_signed_handshake(
        rogue_kp,
        issuer_kp,
        target_did=gateway_did,
        action="access_payment_rails",
        description="Attempting to access payment infrastructure",
    )
    # Re-sign with wrong key — DID says rogue_kp but signature is from wrong_kp
    hs.signature = sign_model(hs, wrong_kp.signing_key)

    _step(2, "Sending tampered handshake to gateway...")
    _info("POST /handshake  (signature does NOT match declared DID)")
    r = await client.post(f"{GATEWAY}/handshake", json=hs.model_dump(mode="json"))
    data = r.json()
    elapsed = (time.perf_counter() - t0) * 1000

    status = data.get("status")
    reason = data.get("reason", "")
    error_code = data.get("error_code", "")

    if status == "REJECTED":
        _ok("REJECTED at transport layer (before orchestrator)")
        _info(f"Reason:      {reason}")
        _info(f"Error code:  {error_code}")
        print()
        print(f"   ⏱  Rejected in: {elapsed:.1f}ms")
        return True, elapsed
    else:
        _fail(f"Expected REJECTED, got: {status}")
        return False, elapsed


# ─────────────────────────────────────────────────────────────────────────────
# Scenario 3: Replay attack → BLOCKED
# ─────────────────────────────────────────────────────────────────────────────

async def scenario_replay(
    client: httpx.AsyncClient, gateway_did: str
) -> tuple[bool, float]:
    _banner("SCENARIO 3 — REPLAY ATTACK BLOCKED")
    t0 = time.perf_counter()

    agent_kp = KeyPair.generate()
    issuer_kp = KeyPair.generate()
    reporter_kp = KeyPair.generate()

    # Pre-seed reputation so the first handshake goes fast-path (no LLM timeout)
    await _boost_reputation(client, reporter_kp, agent_kp.did, count=7)

    _step(1, "Building a valid handshake (fixed nonce)...")
    _info("Agent has been previously verified — replaying its handshake")
    hs = build_signed_handshake(
        agent_kp,
        issuer_kp,
        target_did=gateway_did,
        action="connect",
        description="DeliveryAgentBot requesting payment authorization",
    )
    nonce = hs.envelope.nonce
    _info(f"Nonce: {nonce}")

    _step(2, "First transmission (legitimate)...")
    _info("POST /handshake")
    r1 = await client.post(f"{GATEWAY}/handshake", json=hs.model_dump(mode="json"))
    d1 = r1.json()
    if d1.get("status") == "ACCEPTED":
        _ok("First handshake accepted by gateway")
    else:
        _fail(f"First handshake failed unexpectedly: {d1}")
        return False, 0.0

    _step(3, "Attacker replays the SAME handshake (identical nonce)...")
    _info("POST /handshake  (exact replay — nonce already consumed)")
    r2 = await client.post(f"{GATEWAY}/handshake", json=hs.model_dump(mode="json"))
    data = r2.json()
    elapsed = (time.perf_counter() - t0) * 1000

    status = data.get("status")
    error_code = data.get("error_code", "")
    reason = data.get("reason", "")

    if status == "REJECTED" and "REPLAY" in error_code:
        _ok("BLOCKED — Replay attack detected and rejected")
        _info(f"Reason:      {reason}")
        _info(f"Error code:  {error_code}")
        print()
        print(f"   ⏱  Replay blocked in: {elapsed:.1f}ms")
        return True, elapsed
    else:
        _fail(f"Expected REPLAY NACK, got: {status} / {error_code}")
        return False, elapsed


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

async def main() -> None:
    print()
    print("═" * 55)
    print("   AGENTIC AIRLOCK — TRUST VERIFICATION LIVE DEMO")
    print("   Agentic Airlock  ·  Trust Verification Protocol")
    print("═" * 55)
    print()
    print("  Protocol:  Ed25519 · DID:key · W3C VC · HS256 JWT")
    print("  Gateway:   http://localhost:8000")
    print()

    async with httpx.AsyncClient(timeout=30.0) as client:

        # ── Gateway check ─────────────────────────────────────────────────────
        if not await _check_gateway(client):
            print("  ERROR: Gateway not responding at http://localhost:8000")
            print()
            print("  Start it with:")
            print("    python -m uvicorn airlock.gateway.app:create_app \\")
            print("           --factory --port 8000 --env-file .env")
            sys.exit(1)

        gateway_did = await _gateway_did(client)
        print("  Gateway:   ONLINE")
        print(f"  DID:       {gateway_did[:46]}...")
        print()

        # ── Run scenarios ─────────────────────────────────────────────────────
        r1, t1 = await scenario_verified(client, gateway_did)
        r2, t2 = await scenario_rejected(client, gateway_did)
        r3, t3 = await scenario_replay(client, gateway_did)

        # ── Task 5: Pure verification latency ─────────────────────────────
        _banner("PERFORMANCE CHECK — Pure Verification Latency")
        print("  Measuring handshake → VERIFIED  (pre-seeded high-trust agent)")
        print()

        perf_kp = KeyPair.generate()
        perf_issuer = KeyPair.generate()
        perf_reporter = KeyPair.generate()
        await _boost_reputation(client, perf_reporter, perf_kp.did, count=7)

        samples: list[float] = []
        for i in range(5):
            hs = build_signed_handshake(
                perf_kp, perf_issuer, target_did=gateway_did,
                action="perf_check", description=f"Latency sample {i + 1}",
            )
            t_start = time.perf_counter()
            r = await client.post(f"{GATEWAY}/handshake", json=hs.model_dump(mode="json"))
            ack = r.json()
            if ack.get("status") != "ACCEPTED":
                print(f"  Sample {i+1}: NACK — {ack.get('reason')}")
                continue
            tok = ack.get("session_view_token")
            session = await _poll_verdict(client, ack["session_id"], token=tok)
            elapsed_ms = (time.perf_counter() - t_start) * 1000
            verdict = (session or {}).get("verdict", "TIMEOUT")
            samples.append(elapsed_ms)
            print(f"  Sample {i+1}: {elapsed_ms:.1f}ms  [{verdict}]")

        if samples:
            avg = sum(samples) / len(samples)
            mn = min(samples)
            print()
            print(f"  Average: {avg:.1f}ms  |  Min: {mn:.1f}ms")
            if avg < 200:
                print(f"  ✓ Sub-200ms verified  ({avg:.0f}ms avg)")
            else:
                print(f"  ⚠  Above 200ms  ({avg:.0f}ms avg) — bottleneck: poll interval")

    # ── Summary ───────────────────────────────────────────────────────────────
    print()
    print("═" * 55)
    print("  DEMO SUMMARY")
    print("═" * 55)
    print()
    print("  Scenario 1 — Legitimate agent (MerchantPayBot)")
    print(f"    Result:  {'PASS ✓' if r1 else 'FAIL ✗'}  ({t1:.0f}ms)")
    print()
    print("  Scenario 2 — Rogue agent (tampered signature)")
    print(f"    Result:  {'PASS ✓' if r2 else 'FAIL ✗'}  ({t2:.0f}ms)")
    print()
    print("  Scenario 3 — Replay attack (same nonce)")
    print(f"    Result:  {'PASS ✓' if r3 else 'FAIL ✗'}  ({t3:.0f}ms)")
    print()

    all_passed = r1 and r2 and r3
    if all_passed:
        print("  ALL SCENARIOS PASSED")
        print()
        print("  Agentic Airlock is working end-to-end.")
        print("  The trust verification layer for AI agents.")
    else:
        print("  SOME SCENARIOS FAILED — see output above")

    print()
    print("═" * 55)
    print()

    sys.exit(0 if all_passed else 1)


if __name__ == "__main__":
    asyncio.run(main())
