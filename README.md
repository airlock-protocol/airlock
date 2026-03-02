# Agentic Airlock

**DMARC for AI Agents** — an open protocol for agent-to-agent trust verification in the agentic web.

---

## The Problem

AI agents are rapidly gaining the ability to communicate with each other autonomously (via protocols like Google A2A and Anthropic MCP). There is no standard mechanism for verifying agent identity, authorization, or trustworthiness. The agent ecosystem is repeating the same mistake email made — building communication without authentication. Email took 20 years to bolt on SPF, DKIM, and DMARC after spam became an existential crisis. The Agentic Airlock builds the trust layer *before* the agent spam crisis hits.

---

## The Solution

A **5-phase cryptographic verification protocol** with Ed25519 signing at every hop. Each agent interaction passes through:

```
Resolve → Handshake → Challenge → Verdict → Seal
```

95%+ of verifications complete in microseconds using pure cryptography. The semantic LLM challenge only fires for unknown agents — and only once per reputation tier.

---

## Architecture

```
                        ┌─────────────────────────────────────────┐
                        │           Agentic Airlock                │
                        │                                          │
  Agent A ──────────►  │  [Gateway]  ──►  EventBus               │
   (HandshakeRequest)   │     │               │                    │
                        │     │ ACK/NACK      ▼                    │
                        │     │         [Orchestrator]             │
                        │     │               │                    │
                        │     │         ┌─────┴──────┐            │
                        │     │         ▼            ▼            │
                        │     │   ReputationStore  SemanticChallenge│
                        │     │         │            │            │
                        │     │    fast-path?   ChallengeRequest  │
                        │     │         │         → Agent A       │
                        │     │         ▼            ▼            │
                        │     │      TrustVerdict (VERIFIED /      │
                        │     │      REJECTED / DEFERRED)         │
                        │     │         │                          │
                        │     │         ▼                          │
                        │     │   AirlockAttestation → Agent B    │
                        └─────┴─────────────────────────────────── ┘
```

---

## The 5 Phases

| # | Phase | What Happens |
|---|-------|--------------|
| 1 | **Resolve** | Caller discovers the target agent's capabilities, DID, and endpoint status. The gateway looks up the agent registry and logs the event. |
| 2 | **Handshake** | Initiating agent presents a signed `HandshakeRequest` with its DID (`did:key`), intent, and a W3C Verifiable Credential. The gateway verifies the Ed25519 signature at transport time — invalid signatures are NACK'd instantly. |
| 3 | **Challenge** | If the agent's trust score is in the unknown zone (0.15–0.75), the orchestrator issues a `ChallengeRequest` — a semantic question about the agent's intended behaviour and capabilities. |
| 4 | **Verdict** | The orchestrator evaluates the challenge response (LLM-backed) and issues a signed `TrustVerdict`: `VERIFIED`, `REJECTED`, or `DEFERRED`. High-reputation agents skip phases 3 & 4 entirely (fast-path). |
| 5 | **Seal** | Both parties receive a signed `SessionSeal` containing the full verification trace, attestation, and updated trust score. The seal provides an auditable receipt for every interaction. |

---

## Quickstart

```bash
# Install the package with dev dependencies
pip install -e ".[dev]"

# Run the 3-agent demo (no LLM or external services required)
python demo/run_demo.py

# Run the full test suite
python -m pytest tests/ -v
```

---

## SDK Usage

```python
from airlock.crypto.keys import KeyPair
from airlock.sdk.client import AirlockClient
from airlock.sdk.middleware import AirlockMiddleware

# Option A — direct client
async with AirlockClient("https://your-airlock.example.com", agent_keypair=kp) as client:
    result = await client.handshake(handshake_request)

# Option B — decorator middleware (drop-in protection for any async handler)
airlock = AirlockMiddleware("https://your-airlock.example.com", agent_private_key=kp)

@airlock.protect
async def handle_incoming(request: HandshakeRequest):
    ...  # only called if Airlock returns ACCEPTED
```

---

## API Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/resolve` | Look up an agent by DID and return its profile |
| `POST` | `/handshake` | Submit a signed `HandshakeRequest` for verification |
| `POST` | `/challenge-response` | Submit an agent's answer to a semantic challenge |
| `POST` | `/register` | Register an `AgentProfile` (DID + capabilities + endpoint) |
| `POST` | `/heartbeat` | Record a liveness ping with a TTL timestamp |
| `GET` | `/reputation/{did}` | Return the current trust score for an agent DID |
| `GET` | `/session/{session_id}` | Poll the state of an in-progress verification session |
| `GET` | `/health` | Gateway health check (returns protocol version + airlock DID) |

---

## Trust Scoring

### Initial Score
New agents start at a neutral score of **0.50**.

### Routing Thresholds

| Score Range | Routing Decision | Outcome |
|-------------|-----------------|---------|
| `≥ 0.75` | **Fast-path** | VERIFIED immediately — no LLM challenge |
| `0.15 – 0.74` | **Semantic challenge** | LLM evaluates the agent's intent |
| `≤ 0.15` | **Blacklist** | REJECTED immediately |

### Score Updates

| Verdict | Delta |
|---------|-------|
| `VERIFIED` | `+0.05 / (1 + count × 0.1)` (diminishing returns) |
| `REJECTED` | `−0.15` (fixed penalty) |
| `DEFERRED` | `−0.02` (small nudge — ambiguity is a signal) |

### Half-Life Decay

Scores decay toward neutral (0.50) over time using the standard radioactive decay formula:

```
decayed = 0.5 + (score − 0.5) × 2^(−elapsed_days / 30)
```

An agent that stops interacting gradually becomes "unknown" rather than "suspect" — matching real-world trust intuitions. The half-life is 30 days.

---

## Project Structure

```
airlock-protocol/
├── airlock/
│   ├── config.py                  # Pydantic settings (env vars with AIRLOCK_ prefix)
│   ├── crypto/
│   │   ├── keys.py                # Ed25519 KeyPair + did:key encoding/decoding
│   │   ├── signing.py             # sign_model / verify_model + canonicalization
│   │   └── vc.py                  # W3C Verifiable Credential issue + validate
│   ├── engine/
│   │   ├── event_bus.py           # Typed async EventBus (asyncio.Queue backed)
│   │   ├── orchestrator.py        # LangGraph verification state machine (8 nodes)
│   │   └── state.py               # SessionManager with TTL expiry
│   ├── gateway/
│   │   ├── app.py                 # FastAPI application factory + lifespan
│   │   ├── handlers.py            # Request handlers (signature gate + event publish)
│   │   └── routes.py              # FastAPI router + endpoint wiring
│   ├── reputation/
│   │   ├── scoring.py             # Half-life decay + verdict delta computation
│   │   └── store.py               # LanceDB-backed TrustScore persistence
│   ├── schemas/
│   │   ├── challenge.py           # ChallengeRequest + ChallengeResponse
│   │   ├── envelope.py            # MessageEnvelope, TransportAck, TransportNack
│   │   ├── events.py              # VerificationEvent hierarchy (typed)
│   │   ├── handshake.py           # HandshakeRequest + HandshakeResponse
│   │   ├── identity.py            # AgentDID, AgentProfile, VerifiableCredential
│   │   ├── reputation.py          # TrustScore schema
│   │   ├── session.py             # VerificationSession + SessionSeal
│   │   └── verdict.py             # TrustVerdict, AirlockAttestation, CheckResult
│   ├── sdk/
│   │   ├── client.py              # AirlockClient (async httpx wrapper)
│   │   └── middleware.py          # AirlockMiddleware (protect decorator)
│   └── semantic/
│       └── challenge.py           # LLM-backed challenge generation + evaluation
├── demo/
│   ├── agent_legitimate.py        # Scenario 1: VERIFIED via fast-path
│   ├── agent_hollow.py            # Scenario 2: REJECTED at gateway
│   ├── agent_suspicious.py        # Scenario 3: DEFERRED via semantic challenge
│   └── run_demo.py                # Demo orchestrator (in-process gateway)
└── tests/                         # 92 tests across all modules
```

---

## Design Principles

| Principle | Implementation |
|-----------|---------------|
| **PKI-first** | All identities are `did:key` — DID documents derived from the Ed25519 public key, no registry required |
| **Signed everything** | Every message (`HandshakeRequest`, `ChallengeRequest`, `ChallengeResponse`, `SessionSeal`) carries an Ed25519 signature over its canonical JSON form |
| **Challenge-response** | Unknown agents face semantic questions that probe their stated capabilities — bad actors cannot fake plausible answers at scale |
| **Event-driven** | The gateway is a thin transport layer; all verification logic runs in an async `EventBus` + `LangGraph` state machine |
| **Reputation with memory** | Half-life decay means reputation is time-sensitive — a trusted agent that goes dark eventually becomes "unknown" again |
| **Local-first** | LanceDB is embedded (no server). The entire stack runs on a laptop: `python demo/run_demo.py` |
| **A2A compatible** | The `HandshakeRequest` schema is designed to wrap Google A2A `message` objects |

---

## Environment Variables

All settings can be configured via environment variables with the `AIRLOCK_` prefix:

| Variable | Default | Description |
|----------|---------|-------------|
| `AIRLOCK_HOST` | `0.0.0.0` | Gateway bind address |
| `AIRLOCK_PORT` | `8000` | Gateway port |
| `AIRLOCK_SESSION_TTL` | `180` | Session expiry in seconds |
| `AIRLOCK_LANCEDB_PATH` | `./data/reputation.lance` | Path to reputation database |
| `AIRLOCK_LITELLM_MODEL` | `ollama/llama3` | LLM model for semantic challenges |
| `AIRLOCK_LITELLM_API_BASE` | `http://localhost:11434` | LLM API endpoint |

---

## License

Apache License 2.0. See [LICENSE](LICENSE).

## Author

Shivdeep Singh ([@shivdeep1](https://github.com/shivdeep1))
