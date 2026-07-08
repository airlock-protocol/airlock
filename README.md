<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/logo-dark.png">
    <img src="docs/assets/logo-light.png" alt="Airlock" width="96" height="96">
  </picture>
</p>

# Agentic Airlock

[![CI](https://github.com/airlock-protocol/airlock/actions/workflows/ci.yml/badge.svg)](https://github.com/airlock-protocol/airlock/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/License-Multi--License-blue.svg)](#license)
[![PyPI version](https://img.shields.io/pypi/v/airlock-protocol.svg)](https://pypi.org/project/airlock-protocol/)
[![DCO](https://img.shields.io/badge/DCO-required-brightgreen.svg)](https://developercertificate.org/)

**Identity & policy enforcement for AI agents** — an open protocol that answers one question before any agent tool call runs: *who is this agent, and is it authorized to do that?* Cryptographic identity (Ed25519, W3C DID), deterministic policy decisions, and a signed, hash-chained receipt for every allow and every deny. Built on OAuth 2.1, with delegation chains and tamper-evident audit trails.

Works with Claude (Anthropic SDK integration included), OpenAI, LangChain, or your own agents — one identity & policy layer across all of them.

**Registry:** [api.airlock.ing](https://api.airlock.ing)

---

## What's New in v1.0

### OAuth 2.1 Authorization Server
- Full OAuth 2.1 server with `private_key_jwt` authentication (Ed25519)
- EdDSA-signed JWT access tokens with trust score claims
- RFC 8693 Token Exchange for delegation chains with scope narrowing
- Token introspection with live trust data, OIDC discovery, JWKS endpoints

### Compliance Engine
- Agent inventory, risk classification (low/medium/high/critical), incident tracking
- Hash-chain integrity for tamper-evident compliance records
- Automated compliance report generation with regulatory framework mapping
- Bias detection for verification outcome patterns

### Dual-Mode Identity Verification
- Orchestrator accepts both Ed25519 signatures and OAuth bearer tokens
- Backward-compatible — existing Ed25519 flows work unchanged

### Semantic Challenge Deprecation
- LLM-based challenge disabled by default (now optional via `pip install airlock-protocol[llm]`)
- Trust decisions based on cryptographic verification and behavioral scoring

See [CHANGELOG.md](CHANGELOG.md) for the full release history.

---

## The Problem

AI agents now take real actions — they call tools, move data, run commands, execute transactions. A prompt injection or a misbehaving model turns a helpful agent into a confused deputy: a *legitimate* operation performed by the *wrong* agent, and no content guardrail will catch it. Guardrails filter content; they cannot distinguish an authorized tool call from an unauthorized one. There is no standard mechanism for verifying agent identity and enforcing authorization before the action runs.

## The Solution

Airlock is an access-control layer that sits between the agent and its tools. Every tool call is checked — deterministically, whatever model is driving:

```
Agent ──tool call──> Airlock ──allowed──> Tool executes
                        │
                        ├── Identify   who is this agent? (Ed25519 / OAuth 2.1, verified not asserted)
                        ├── Decide     does policy allow it? (deterministic — same answer, any model)
                        ├── Enforce    allow or deny — before the tool ever runs
                        └── Receipt    signed, hash-chained record of every decision
```

The receipt chain is tamper-evident (Ed25519 signatures + SHA-256 hash chain) — it's the artifact you hand an auditor. OAuth 2.1 provides identity; Airlock adds trust scoring, delegation with scope narrowing (RFC 8693), and the enforcement + audit layer on top.

---

## Architecture

```
                        +------------------------------------------+
                        |           Agentic Airlock                 |
                        |                                           |
  Agent A ---------->  |  [Gateway]  --->  EventBus                |
   (OAuth token or      |     |               |                     |
    Ed25519 handshake)  |     | ACK/NACK      v                    |
                        |     |         [Orchestrator]              |
                        |     |               |                     |
                        |     |         +-----+------+             |
                        |     |         v            v             |
                        |     |   ReputationStore  OAuth Server    |
                        |     |         |            |             |
                        |     |    trust score   token + claims    |
                        |     |         v                          |
                        |     |   TrustVerdict (VERIFIED /          |
                        |     |   REJECTED / DEFERRED)             |
                        |     |         |                          |
                        |     |         v                          |
                        |     |   Attestation + Compliance Audit   |
                        +-----+------------------------------------+
```

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
python -m pytest tests/ -v    # 853 tests
```

> **[Full Getting Started Guide](GETTING_STARTED.md)**

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

### Core Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/resolve` | Look up an agent by DID and return its profile |
| `POST` | `/handshake` | Submit a signed `HandshakeRequest` for verification |
| `GET` | `/pow-challenge` | Issue a Proof-of-Work challenge (SHA-256 or Argon2id) |
| `POST` | `/challenge-response` | Submit an agent's answer to a semantic challenge |
| `POST` | `/register` | Register an `AgentProfile` (DID + capabilities + endpoint) |
| `POST` | `/feedback` | Signed `SignedFeedbackReport` (Ed25519 + nonce) |
| `POST` | `/heartbeat` | Signed heartbeat (liveness probe) |
| `GET` | `/reputation/{did}` | Return the current trust score for an agent DID |
| `GET` | `/session/{session_id}` | Poll session state (Bearer auth required) |
| `WS` | `/ws/session/{session_id}` | Push session updates via WebSocket |

### OAuth 2.1 Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/oauth/token` | Token endpoint (client credentials + token exchange) |
| `POST` | `/oauth/register` | Dynamic client registration (RFC 7591) |
| `POST` | `/oauth/introspect` | Token introspection with live trust data (RFC 7662) |
| `POST` | `/oauth/revoke` | Token revocation |
| `GET` | `/.well-known/openid-configuration` | OIDC discovery document |
| `GET` | `/.well-known/jwks.json` | Ed25519 public key (JWK format) |

### Compliance Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/compliance/inventory` | List all registered agents |
| `POST` | `/compliance/inventory` | Register an agent in the compliance inventory |
| `GET` | `/compliance/inventory/{did}` | Get agent compliance profile |
| `GET` | `/compliance/report` | Generate compliance report |
| `GET` | `/compliance/report/{did}` | Per-agent compliance report |
| `POST` | `/compliance/incident` | Report a compliance incident |
| `GET` | `/compliance/incidents` | List incidents (paginated) |
| `GET` | `/compliance/risk/{did}` | Get risk classification for an agent |
| `GET` | `/compliance/audit-summary` | Audit summary for inspection |

### Operations Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/health` | Diagnostics (subsystems, queue depth, uptime) |
| `GET` | `/live` | Process liveness (Docker `HEALTHCHECK`) |
| `GET` | `/ready` | Readiness (HTTP 503 if deps not ready) |
| `GET` | `/metrics` | Prometheus text (requires `AIRLOCK_SERVICE_TOKEN`) |
| `POST` | `/token/introspect` | Validate a trust JWT |
| `*` | `/admin/*` | Ops API (when `AIRLOCK_ADMIN_TOKEN` is set) |

---

## Trust Scoring

### Initial Score
New agents start at a neutral score of **0.50**.

### Routing Thresholds

| Score Range | Routing Decision | Outcome |
|-------------|-----------------|---------|
| `>= 0.75` | **Fast-path** | VERIFIED immediately |
| `0.15 - 0.74` | **Standard verification** | Cryptographic + behavioral checks |
| `<= 0.15` | **Blacklist** | REJECTED immediately |

### Score Updates

| Verdict | Delta |
|---------|-------|
| `VERIFIED` | `+0.05 / (1 + count * 0.1)` (diminishing returns) |
| `REJECTED` | `-0.15` (fixed penalty) |
| `DEFERRED` | `-0.02` (ambiguity signal) |

### Trust Tiers

| Tier | Score Ceiling | Decay Half-Life |
|------|---------------|-----------------|
| `UNKNOWN` | 0.50 | 30 days |
| `CHALLENGE_VERIFIED` | 0.70 | 90 days |
| `DOMAIN_VERIFIED` | 0.90 | 180 days |
| `VC_VERIFIED` | 1.00 | 365 days |

Agents with 10+ interactions have a decay floor of **0.60** — established agents never drop back to fully unknown.

### Half-Life Decay

Scores decay toward neutral (0.50) over time:

```
decayed = 0.5 + (score - 0.5) * 2^(-elapsed_days / half_life)
```

Decay half-life is tier-specific (see table above). An agent that stops interacting gradually becomes "unknown" rather than "suspect."

---

## Project Structure

```
airlock-protocol/
├── airlock/
│   ├── config.py                  # Pydantic settings (env vars with AIRLOCK_ prefix)
│   ├── pow.py                     # Proof-of-Work (SHA-256 Hashcash / Argon2id)
│   ├── trust_jwt.py               # HS256 trust tokens for verified outcomes
│   ├── compliance/
│   │   ├── inventory.py           # Agent inventory registry
│   │   ├── risk_classifier.py     # Risk classification engine
│   │   ├── report_generator.py    # Compliance report generation
│   │   ├── incident.py            # Incident tracking with hash-chain integrity
│   │   ├── bias_detector.py       # Bias detection for verification patterns
│   │   ├── regulatory_mapper.py   # Regulatory framework principle mapping
│   │   └── schemas.py             # Compliance Pydantic models
│   ├── crypto/
│   │   ├── keys.py                # Ed25519 KeyPair + did:key encoding/decoding
│   │   ├── signing.py             # sign_model / verify_model + canonicalization
│   │   └── vc.py                  # W3C Verifiable Credential issue + validate
│   ├── engine/
│   │   ├── event_bus.py           # Typed async EventBus (asyncio.Queue backed)
│   │   ├── orchestrator.py        # LangGraph verification state machine
│   │   └── state.py               # SessionManager with TTL expiry
│   ├── gateway/
│   │   ├── app.py                 # FastAPI application factory + lifespan
│   │   ├── handlers.py            # Request handlers (dual-mode auth + event publish)
│   │   ├── routes.py              # Core protocol routes
│   │   ├── oauth_routes.py        # OAuth 2.1 endpoints
│   │   ├── compliance_routes.py   # Compliance endpoints
│   │   ├── revocation.py          # DID revocation store (sync + async + Redis)
│   │   └── rate_limit.py          # Per-IP + per-DID throttling
│   ├── oauth/
│   │   ├── server.py              # OAuth 2.1 authorization server
│   │   ├── grants/                # Client credentials + token exchange
│   │   ├── token_generator.py     # EdDSA JWT generation with trust claims
│   │   ├── token_validator.py     # JWT validation + delegation depth check
│   │   ├── introspection.py       # RFC 7662 token introspection
│   │   ├── discovery.py           # OIDC discovery + JWKS
│   │   ├── dependencies.py        # FastAPI Depends helpers
│   │   ├── registration.py        # RFC 7591 dynamic client registration
│   │   ├── models.py              # OAuth Pydantic models
│   │   ├── scopes.py              # Scope definitions + validation
│   │   └── store.py               # Client + token persistence
│   ├── reputation/
│   │   ├── scoring.py             # Tiered decay + verdict delta + floor protection
│   │   └── store.py               # LanceDB-backed TrustScore persistence
│   ├── rotation/                  # Key rotation with pre-rotation commitments
│   ├── schemas/                   # Pydantic models (identity, events, verdict, etc.)
│   ├── sdk/
│   │   ├── client.py              # AirlockClient (async httpx wrapper)
│   │   └── middleware.py          # AirlockMiddleware (protect decorator)
│   └── semantic/
│       ├── challenge.py           # LLM-backed challenge (optional, disabled by default)
│       └── fingerprint.py         # SimHash + SHA-256 bot detection
├── integrations/
│   └── airlock-mcp/               # MCP stdio server (gateway tools)
├── sdks/
│   └── typescript/                # npm package `airlock-client` (HTTP + types)
├── examples/                      # Agent scenarios + demos
└── tests/                         # 853 tests (unit, integration, property-based, security)
```

---

## Design Principles

| Principle | Implementation |
|-----------|---------------|
| **PKI-first** | All identities are `did:key` — DID documents derived from Ed25519 public key |
| **OAuth-native** | Standard OAuth 2.1 token flows with trust claims — no proprietary auth |
| **Signed everything** | Every message carries an Ed25519 signature over its canonical JSON form |
| **Event-driven** | Thin transport layer; all verification logic in async EventBus + LangGraph |
| **Reputation with memory** | Half-life decay means reputation is time-sensitive — inactive agents fade |
| **Local-first** | LanceDB is embedded (no server). The entire stack runs on a laptop |
| **A2A compatible** | HandshakeRequest wraps Google A2A message objects |
| **Progressive trust** | Trust tiers gate score ceilings — VC verification unlocks 1.00 |
| **Privacy-aware** | `privacy_mode` lets callers control data residency |
| **Anti-Sybil** | Proof-of-Work (SHA-256 / Argon2id) + answer fingerprinting |
| **Audit-ready** | Hash-chained audit trail + compliance reporting for regulators |

---

## Environment Variables

All settings use the `AIRLOCK_` prefix:

| Variable | Default | Description |
|----------|---------|-------------|
| `AIRLOCK_HOST` | `0.0.0.0` | Gateway bind address |
| `AIRLOCK_PORT` | `8000` | Gateway port |
| `AIRLOCK_ENV` | `development` | `development` or `production` |
| `AIRLOCK_GATEWAY_SEED_HEX` | (random) | 64-char hex Ed25519 seed (required in production) |
| `AIRLOCK_LANCEDB_PATH` | `./data/reputation.lance` | Path to reputation database |
| `AIRLOCK_OAUTH_ENABLED` | `true` | Enable OAuth 2.1 authorization server |
| `AIRLOCK_OAUTH_TOKEN_TTL_SECONDS` | `3600` | OAuth access token lifetime |
| `AIRLOCK_OAUTH_MAX_DELEGATION_DEPTH` | `5` | Max token exchange chain depth |
| `AIRLOCK_COMPLIANCE_ENABLED` | `true` | Enable compliance module |
| `AIRLOCK_TRUST_TOKEN_SECRET` | (empty) | HS256 secret for trust tokens |
| `AIRLOCK_SERVICE_TOKEN` | (empty) | Bearer token for ops endpoints |
| `AIRLOCK_REDIS_URL` | (empty) | Redis URL for multi-replica mode |
| `AIRLOCK_CHALLENGE_FALLBACK_MODE` | `disabled` | `disabled`, `ambiguous`, or `rule_based` |

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
