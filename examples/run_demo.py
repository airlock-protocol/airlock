from __future__ import annotations

"""
Agentic Airlock — 3-Agent Demo
================================

Run with:
    python examples/run_demo.py

Shows three distinct verification paths through the Airlock protocol:

  1. VERIFIED  — Legitimate agent with high trust score (fast-path, no LLM challenge)
  2. REJECTED  — Hollow identity, missing signature (rejected at gateway transport layer)
  3. DEFERRED  — Suspicious agent routed to semantic challenge (LLM call patched for demo)

The demo starts the FastAPI gateway in-process using asgi-lifespan and
httpx.AsyncClient with ASGITransport — no actual network ports are opened.
"""

import asyncio
import io
import sys
from pathlib import Path

# Force UTF-8 output on Windows so box-drawing characters render correctly
if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

# Allow running from the project root: python examples/run_demo.py
sys.path.insert(0, str(Path(__file__).parent.parent))

import httpx
from asgi_lifespan import LifespanManager

from airlock.gateway.app import create_app
from examples.agent_a2a import run_a2a_scenario
from examples.agent_hollow import run_hollow_scenario
from examples.agent_legitimate import run_legitimate_scenario
from examples.agent_suspicious import run_suspicious_scenario

# ─────────────────────────────────────────────────────────────────────────────
# Terminal formatting helpers
# ─────────────────────────────────────────────────────────────────────────────

_WIDTH = 58


def _box_top(char: str = "═") -> str:
    return f"╔{'═' * _WIDTH}╗"


def _box_bot(char: str = "═") -> str:
    return f"╚{'═' * _WIDTH}╝"


def _box_row(text: str = "") -> str:
    padded = text.center(_WIDTH)
    return f"║{padded}║"


def _rule(char: str = "─") -> str:
    return f"┌{'─' * _WIDTH}┐"


def _rule_bot() -> str:
    return f"└{'─' * _WIDTH}┘"


def _table_row(text: str) -> str:
    padded = f"  {text}".ljust(_WIDTH)
    return f"│{padded}│"


def _print_header() -> None:
    print()
    print(_box_top())
    print(_box_row())
    print(_box_row("AGENTIC AIRLOCK — VERIFICATION DEMO"))
    print(_box_row("DMARC for AI Agents"))
    print(_box_row())
    print(_box_bot())
    print()


def _short_did(did: str, n: int = 24) -> str:
    """Truncate a DID for display: did:key:z6MkXxxx...xxx"""
    if len(did) <= n + 12:
        return did
    return did[:20] + "..." + did[-8:]


def _print_scenario_header(number: int, title: str) -> None:
    print(f"[SCENARIO {number}] {title}")
    print(f"  {'─' * 54}")


def _print_result(verdict: str | None, description: str) -> None:
    if verdict == "VERIFIED":
        symbol = "✓"
    elif verdict == "REJECTED":
        symbol = "✗"
    elif verdict == "DEFERRED":
        symbol = "~"
    else:
        symbol = "?"
    print(f"  Result:  {symbol} {verdict or 'UNKNOWN'} — {description}")


def _print_trace(trace: list) -> None:
    if not trace:
        return
    print("  Trace:")
    for entry in trace:
        evt = entry.get("event", "unknown")
        if evt == "verdict":
            score = entry.get("trust_score", "?")
            checks = entry.get("checks", [])
            print(f"    • Verdict issued: {entry.get('verdict')} (trust_score={score:.4f})")
            for chk in checks:
                mark = "✓" if chk["passed"] else "✗"
                print(f"      {mark} [{chk['check']}] {chk['detail']}")
        elif evt == "challenge_issued":
            print(f"    • Challenge issued (type={entry.get('challenge_type')})")
            q = entry.get("question", "")
            print(f"      Q: {q[:80]}{'...' if len(q) > 80 else ''}")
        elif evt == "session_deferred":
            print(f"    • {entry.get('reason', '')}")
        elif evt == "http_response":
            print(f"    • HTTP {entry.get('status_code')}: {entry.get('status')}")
            if entry.get("error_code"):
                print(f"      error_code={entry.get('error_code')}")
            if entry.get("reason"):
                print(f"      reason={entry.get('reason')}")
        else:
            print(f"    • {entry}")
    print()


def _print_summary(results: list[dict]) -> None:
    print()
    print(_rule())
    print(_table_row("SUMMARY"))
    print(_table_row(""))
    labels = {
        "legitimate": "Scenario 1 (Legitimate):",
        "hollow": "Scenario 2 (Hollow):    ",
        "suspicious": "Scenario 3 (Suspicious):",
        "a2a_native": "Scenario 4 (A2A):       ",
    }
    for r in results:
        scenario = r.get("scenario", "?")
        verdict = r.get("verdict", "UNKNOWN")
        label = labels.get(scenario, scenario)
        print(_table_row(f"  {label}  {verdict}"))
    print(_table_row(""))
    print(_rule_bot())
    print()


def _print_llm_note() -> None:
    print("  Note: No LLM is configured (demo mode).")
    print("        In production, the semantic challenge would be")
    print("        evaluated by an LLM (e.g. ollama/llama3).")
    print("        Set AIRLOCK_LITELLM_MODEL + AIRLOCK_LITELLM_API_BASE")
    print("        to enable full LLM-backed challenge evaluation.")
    print()


# ─────────────────────────────────────────────────────────────────────────────
# Main demo orchestration
# ─────────────────────────────────────────────────────────────────────────────


async def main() -> None:
    _print_header()

    # Use a temp LanceDB path so demo data doesn't pollute dev data
    import os
    import tempfile

    from airlock.config import AirlockConfig

    tmpdir = tempfile.mkdtemp(prefix="airlock_demo_")
    cfg = AirlockConfig(lancedb_path=os.path.join(tmpdir, "reputation.lance"))

    app = create_app(config=cfg)

    async with LifespanManager(app):
        # All shared state is in app.state after lifespan startup
        orchestrator = app.state.orchestrator
        reputation_store = app.state.reputation
        airlock_did = app.state.airlock_kp.did

        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            # ── Scenario 1: Legitimate agent ───────────────────────────────
            _print_scenario_header(1, "Legitimate Agent")
            print("  Action:  Registering with high trust score (0.80 → fast-path)")
            print("           Sending signed HandshakeRequest with valid VC")
            print()

            legit_result = await run_legitimate_scenario(
                orchestrator, reputation_store, airlock_did
            )

            print(f"  DID:     {_short_did(legit_result['agent_did'])}")
            print(f"  Score:   {legit_result['trust_score']:.2f} (threshold for fast-path: 0.75)")
            _print_result(
                legit_result.get("verdict"),
                f"fast-path, trust score: {legit_result['trust_score']:.2f}",
            )
            _print_trace(legit_result.get("trace", []))

            # ── Scenario 2: Hollow agent ───────────────────────────────────
            _print_scenario_header(2, "Hollow Identity")
            print("  Action:  Sending HandshakeRequest with NO signature")
            print("           (unregistered agent, forged VC, no Ed25519 proof)")
            print()

            hollow_result = await run_hollow_scenario(client)

            print(f"  DID:     {_short_did(hollow_result['agent_did'])} (unregistered)")
            _print_result(
                hollow_result.get("verdict"),
                f"gateway rejected — {hollow_result.get('rejection_reason', 'invalid signature')}",
            )
            _print_trace(hollow_result.get("trace", []))

            # ── Scenario 3: Suspicious agent ──────────────────────────────
            _print_scenario_header(3, "Suspicious Agent")
            print("  Action:  Sending signed HandshakeRequest with valid VC")
            print("           (no prior reputation → routed to semantic challenge)")
            print()

            suspicious_result = await run_suspicious_scenario(
                orchestrator, reputation_store, airlock_did
            )

            print(f"  DID:     {_short_did(suspicious_result['agent_did'])}")
            print(
                f"  Score:   {suspicious_result['trust_score']:.2f} "
                f"(0.15–0.75 → semantic challenge path)"
            )
            _print_result(
                suspicious_result.get("verdict"),
                "routed to semantic challenge, awaiting agent response",
            )
            _print_trace(suspicious_result.get("trace", []))
            _print_llm_note()

            # ── Scenario 4: A2A-native agent ─────────────────────────────
            _print_scenario_header(4, "A2A-Native Agent (Google A2A Protocol)")
            print("  Action:  Using A2A endpoints (/a2a/agent-card, /a2a/register, /a2a/verify)")
            print("           Agent speaks A2A protocol, Airlock adds trust layer on top")
            print()

            a2a_result = await run_a2a_scenario(client, airlock_did)

            print(f"  DID:     {_short_did(a2a_result['agent_did'])}")
            print(
                f"  Score:   {a2a_result['trust_score']:.2f} (default 0.50 → credential check path)"
            )

            a2a_trace = a2a_result.get("trace", [])
            for entry in a2a_trace:
                evt = entry.get("event", "")
                if evt == "a2a_discovery":
                    print("  Step 1:  Discovered gateway via GET /a2a/agent-card")
                    print(f"           Gateway: {entry['gateway_name']}")
                    print(f"           Skills:  {', '.join(entry['skills'])}")
                elif evt == "a2a_registration":
                    print(
                        f"  Step 2:  Registered via POST /a2a/register (format={entry['format']})"
                    )
                elif evt == "a2a_verification":
                    symbol = {"VERIFIED": "✓", "REJECTED": "✗", "DEFERRED": "~"}.get(
                        entry["verdict"], "?"
                    )
                    print("  Step 3:  Verified via POST /a2a/verify")
                    print(
                        f"  Result:  {symbol} {entry['verdict']} (trust_score={entry['trust_score']:.4f})"
                    )
                    for chk in entry.get("checks", []):
                        mark = "✓" if chk["passed"] else "✗"
                        print(f"           {mark} [{chk['check']}] {chk['detail']}")
                elif evt == "a2a_metadata_received":
                    print("  Step 4:  Received A2A-compatible trust metadata")
                    print(f"           airlock_verdict={entry['airlock_verdict']}")
                    print(f"           checks_count={entry['checks_count']}")
                elif evt == "cross_protocol_resolve":
                    found_str = "YES" if entry["found"] else "NO"
                    print(f"  Step 5:  Cross-protocol resolve via /resolve → found={found_str}")
                    if entry["found"]:
                        print(f"           display_name={entry['display_name']}")
            print()

    # ── Summary table ──────────────────────────────────────────────────────
    _print_summary([legit_result, hollow_result, suspicious_result, a2a_result])

    print("Demo complete. All four verification code paths exercised.")
    print("  Protocol: Agentic Airlock v0.1.0")
    print(f"  Gateway DID: {_short_did(airlock_did)}")
    print()


if __name__ == "__main__":
    asyncio.run(main())
