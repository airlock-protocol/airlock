# Agentic Airlock

[![CI](https://github.com/airlock-protocol/airlock/actions/workflows/ci.yml/badge.svg)](https://github.com/airlock-protocol/airlock/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/License-Multi--License-blue.svg)](#license)
[![PyPI version](https://img.shields.io/pypi/v/airlock-protocol.svg)](https://pypi.org/project/airlock-protocol/)
[![DCO](https://img.shields.io/badge/DCO-required-brightgreen.svg)](https://developercertificate.org/)

**DMARC for AI Agents** — an open protocol for agent-to-agent trust verification in the agentic web.

**Registry:** [api.airlock.ing](https://api.airlock.ing) — every verification routes through the central trust registry by default.

---

## What's New in v0.2

### Trust & Security
- **Trust Tiers** — Progressive trust levels (Unknown -> Challenge-Verified -> Domain-Verified -> VC-Verified) with score ceilings
- **Proof-of-Work** — SHA-256 Hashcash anti-Sybil protection on handshake
- **Privacy Mode** — `local_only`, `any`, `no_challenge` modes for GDPR/DPDP compliance
- **Dual-LLM Evaluation** — Optional cross-validation with conservative agreement
- **Answer Fingerprinting** — SimHash + SHA-256 bot farm detection
- **Structured LLM Output** — JSON schema evaluation (no free-text parsing)
- **Tiered Decay** — Per-tier reputation half-lives with floor protection

See [CHANGELOG.md](CHANGELOG.md) for the full release notes.

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

**v0.2 additions:** Handshake now supports optional **Proof-of-Work** (SHA-256 Hashcash) for anti-Sybil protection. Agents are assigned a **Trust Tier** (Unknown/Challenge-Verified/Domain-Verified/VC-Verified) that governs score ceilings and decay rates. **Privacy Mode** (`local_only`/`any`/`no_challenge`) allows callers to control data residency for GDPR/DPDP compliance. Challenge evaluation supports **Dual-LLM** cross-validation with conservative agreement.

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
pip install airlock-protocol

# Verify an agent in 7 lines
python -c "
from airlock import AirlockClient
client = AirlockClient()  # defaults to api.airlock.ing
result = client.verify('did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK')
print(f'Verified: {result.verified}, Score: {result.trust_score}')
"
```

### CLI

```bash
# Verify an agent from the command line
airlock verify did:key:z6Mk...

# Start a local gateway for development
airlock serve

# Scaffold a new Airlock-protected project
airlock init
```

### Self-hosting

```bash
# Clone and run locally
git clone https://github.com/airlock-protocol/airlock.git
cd airlock
pip install -e ".[dev]"
python demo/run_demo.py       # 3-agent demo, no external services needed
python -m pytest tests/ -v    # 399+ tests
```

> **[→ Full Getting Started Guide](GETTING_STARTED.md)**

---

## SDK Usage

```python
from airlock import AirlockClient

# Default — routes through central Airlock registry (api.airlock.ing)
client = AirlockClient()
result = client.verify("did:key:z6Mk...")
if result.verified:
    print(f"Trusted: {result.agent_name}, Score: {result.trust_score}")

# Self-hosted — point to your own gateway
client = AirlockClient(gateway_url="http://localhost:8000")

# Async support
result = await client.averify("did:key:z6Mk...")
```

### TypeScript client (`airlock-client`)

The npm workspace under `sdks/typescript` exposes the same REST operations via `fetch` (Node 18+). See [`sdks/typescript/README.md`](sdks/typescript/README.md). Published PyPI name remains **`airlock-protocol`** (Python); the TS package is **`airlock-client`** on npm when released.

### MCP adapter (`airlock-mcp`)

[`integrations/airlock-mcp`](integrations/airlock-mcp) is a stdio [Model Context Protocol](https://modelcontextprotocol.io/) server that surfaces gateway tools (`health`, `resolve`, `session`, `reputation`, etc.) to MCP hosts. Build from repo root: `npm install && npm run build:mcp`.

When you publish: see **[RELEASING.md](RELEASING.md)** (PyPI OIDC, npm `NPM_TOKEN`, workflows).

---

## Deploy (Docker)

- **Docker Compose** (gateway + Redis, persistent LanceDB volume): **[docs/deploy/docker.md](docs/deploy/docker.md)**
- Quick start: copy [`.env.example`](.env.example) to `.env`, set `AIRLOCK_GATEWAY_SEED_HEX`, then `docker compose up --build`.

---

## API Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/resolve` | Look up an agent by DID and return its profile |
| `POST` | `/handshake` | Submit a signed `HandshakeRequest` for verification (optional PoW + privacy_mode) |
| `GET` | `/pow-challenge` | Issue a Proof-of-Work challenge (SHA-256 Hashcash, adaptive difficulty) |
| `POST` | `/challenge-response` | Submit an agent's answer to a semantic challenge |
| `POST` | `/register` | Register an `AgentProfile` (DID + capabilities + endpoint) |
| `POST` | `/feedback` | Signed `SignedFeedbackReport` (Ed25519 + nonce); see SDKs |
| `POST` | `/heartbeat` | Signed heartbeat (`HeartbeatRequest` with envelope + signature) |
| `GET` | `/reputation/{did}` | Return the current trust score for an agent DID |
| `GET` | `/session/{session_id}` | Poll session; use `Authorization: Bearer` with `session_view_token` from handshake ACK (or service token). Without auth in dev, **`trust_token` is omitted**. |
| `WS` | `/ws/session/{session_id}` | Push session updates; same auth via `Authorization` or `?token=` (session viewer JWT) |
| `GET` | `/health` | Diagnostics (subsystems, queue depth, dead letters, uptime; HTTP 200 even if degraded) |
| `GET` | `/live` | Process liveness (cheap; Docker `HEALTHCHECK`) |
| `GET` | `/ready` | Readiness (**HTTP 503** if deps not ready or shutting down) |
| `GET` | `/metrics` | Prometheus text; requires `AIRLOCK_SERVICE_TOKEN` bearer when that env is set (always in `AIRLOCK_ENV=production`) |
| `POST` | `/token/introspect` | Validate a trust JWT; requires gateway HS256 secret + service bearer when configured |
| `*` | `/admin/*` | Optional ops API when `AIRLOCK_ADMIN_TOKEN` is set (Bearer) |

**Public production:** set `AIRLOCK_ENV=production` and the env vars documented in [docs/deploy/docker.md](docs/deploy/docker.md) (non-wildcard CORS, issuer allowlist, `AIRLOCK_SERVICE_TOKEN`, `AIRLOCK_SESSION_VIEW_SECRET`, etc.). **LanceDB v1:** use a **single active writer** or one replica with the LanceDB volume—see the deploy guide.

A2A routes under `/a2a/*` are documented in the gateway module; see `airlock/gateway/a2a_routes.py`.

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

### Trust Tiers (v0.2)

| Tier | Score Ceiling | Decay Half-Life |
|------|---------------|-----------------|
| `UNKNOWN` | 0.50 | 30 days |
| `CHALLENGE_VERIFIED` | 0.70 | 90 days |
| `DOMAIN_VERIFIED` | 0.90 | 180 days |
| `VC_VERIFIED` | 1.00 | 365 days |

Agents with 10+ interactions have a decay floor of **0.60** — established agents never drop back to fully unknown.

### Half-Life Decay

Scores decay toward neutral (0.50) over time using the standard radioactive decay formula:

```
decayed = 0.5 + (score − 0.5) × 2^(−elapsed_days / half_life)
```

In v0.2, `half_life` is tier-specific (see table above) instead of a single global value. An agent that stops interacting gradually becomes "unknown" rather than "suspect" — matching real-world trust intuitions.

---

## Project Structure

```
airlock-protocol/
├── airlock/
│   ├── config.py                  # Pydantic settings (env vars with AIRLOCK_ prefix)
│   ├── pow.py                     # Proof-of-Work (SHA-256 Hashcash, adaptive difficulty)
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
│   │   ├── scoring.py             # Tiered decay + verdict delta + floor protection
│   │   └── store.py               # LanceDB-backed TrustScore persistence
│   ├── schemas/
│   │   ├── challenge.py           # ChallengeRequest + ChallengeResponse
│   │   ├── envelope.py            # MessageEnvelope, TransportAck, TransportNack
│   │   ├── events.py              # VerificationEvent hierarchy (typed)
│   │   ├── handshake.py           # HandshakeRequest + HandshakeResponse (PoW + privacy_mode)
│   │   ├── identity.py            # AgentDID, AgentProfile, VerifiableCredential
│   │   ├── reputation.py          # TrustScore schema
│   │   ├── session.py             # VerificationSession + SessionSeal
│   │   ├── trust_tier.py          # TrustTier IntEnum + score ceilings
│   │   └── verdict.py             # TrustVerdict, AirlockAttestation, CheckResult
│   ├── sdk/
│   │   ├── client.py              # AirlockClient (async httpx wrapper)
│   │   └── middleware.py          # AirlockMiddleware (protect decorator)
│   └── semantic/
│       ├── challenge.py           # LLM-backed challenge generation + evaluation
│       └── fingerprint.py         # SimHash + SHA-256 answer fingerprinting
├── integrations/
│   └── airlock-mcp/               # MCP stdio server (gateway tools)
├── sdks/
│   └── typescript/                # npm package `airlock-client` (HTTP + types)
├── examples/                      # Agent scenarios + demos
└── tests/                         # Pytest suite — 399+ tests (gateway, engine, SDK, A2A, security, property-based)
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
| **Progressive trust** | Trust tiers gate score ceilings — LLM-only agents are capped at 0.70; full VC verification unlocks 1.00 |
| **Privacy-aware** | `privacy_mode` lets callers control data residency (`local_only` keeps all data on the gateway instance) |
| **Anti-Sybil** | Proof-of-Work on handshake + answer fingerprinting make bot farm attacks economically infeasible |

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

| Component | License |
|-----------|---------|
| SDKs, crypto, schemas (`sdks/`, `airlock/crypto/`, `airlock/schemas/`) | Apache 2.0 |
| Gateway, engine (`airlock/gateway/`, `airlock/engine/`) | BSL 1.1 (converts to Apache 2.0 on 2030-04-04) |
| Specification (`docs/spec/`) | CC-BY-4.0 |

See [LICENSE](LICENSE) for details.

## Author

Shivdeep Singh ([@shivdeep1](https://github.com/shivdeep1)) — [airlock.ing](https://airlock.ing)
