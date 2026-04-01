# Agentic Airlock Protocol — Work Summary

**Project:** Agentic Airlock
**Repo:** github.com/shivdeep1/airlock-protocol
**Built with:** Claude Opus 4.6 (1M context)
**Date:** April 2026

---

## What Was Built

A production-grade **agent trust verification protocol** — a cryptographic trust layer that sits between AI agents and the systems they interact with. Every agent that wants to act must prove its identity, pass semantic challenge, and earn a trust score before receiving an access token.

**The gap it fills:** Transport security (TLS) exists. Authorization frameworks (OAuth) exist. But nobody has built a layer that verifies *who the agent is* and *whether it should be trusted to act* — that is what Airlock does.

---

## Architecture

```
Agent → [1. Resolve DID] → [2. Handshake + VC] → [3. Semantic Challenge] → [4. Verdict + JWT] → [5. Seal Session]
```

**Stack:**
- FastAPI gateway (14+ endpoints)
- LangGraph state machine (10-node orchestration pipeline)
- Ed25519 cryptography (DID:key, W3C Verifiable Credentials)
- Python SDK with middleware
- Optional Redis backend (nonce replay, rate limiting, revocation)

---

## All Files Built

### Core Protocol (Phase 1–3, initial build)

| Module | What it does |
|--------|-------------|
| `airlock/crypto/keys.py` | Ed25519 key generation, DID:key derivation |
| `airlock/crypto/signing.py` | Sign/verify messages, build signed handshakes |
| `airlock/crypto/vc.py` | W3C Verifiable Credential issuance + verification |
| `airlock/engine/orchestrator.py` | LangGraph 10-node pipeline (the brain) |
| `airlock/engine/state.py` | Shared pipeline state model |
| `airlock/engine/event_bus.py` | Async event pub/sub |
| `airlock/reputation/scoring.py` | Trust score: 0.5 initial, +0.05 VERIFIED, -0.15 REJECTED, 30-day decay |
| `airlock/reputation/store.py` | In-memory reputation store |
| `airlock/semantic/challenge.py` | LLM-powered domain challenge generation + evaluation |
| `airlock/schemas/` | Pydantic models: HandshakeRequest, AirlockAttestation, TrustVerdict |
| `airlock/gateway/app.py` | FastAPI app, lifespan setup |
| `airlock/gateway/handlers.py` | Core endpoint logic |
| `airlock/gateway/routes.py` | Public routes |
| `airlock/gateway/admin_routes.py` | Admin routes (auth-gated) |
| `airlock/gateway/auth.py` | Bearer token auth |
| `airlock/sdk/client.py` | Python SDK for agents to call the gateway |
| `airlock/sdk/middleware.py` | ASGI middleware: auto-verify before every request |
| `airlock/trust_jwt.py` | JWT trust token issuance + introspection |

### A2A Integration (Phase 4)

| File | What it does |
|------|-------------|
| `airlock/a2a/adapter.py` | Bidirectional type conversion: A2A ↔ Airlock schemas |
| `airlock/gateway/a2a_routes.py` | `/a2a/agent-card`, `/a2a/register`, `/a2a/verify` endpoints |

### Security Hardening (Phase 5)

| File | What it does |
|------|-------------|
| `airlock/gateway/url_validator.py` | SSRF protection: blocks 127.x, 10.x, 192.168.x, 172.16-31.x, 169.254.x |
| `airlock/semantic/challenge.py` | Prompt injection mitigation, 30s LLM timeout, answer sanitization |
| `airlock/engine/orchestrator.py` | SSRF callback validation, expired challenge sweep, 10k hard cap |
| `airlock/gateway/handlers.py` | DID format validation, endpoint_url scheme check |

### Revocation System

| File | What it does |
|------|-------------|
| `airlock/gateway/revocation.py` | `RevocationStore` (in-memory set, O(1) lookup) |
| `airlock/gateway/revocation.py` | `RedisRevocationStore` (SADD/SISMEMBER/SREM + local cache for sync calls) |
| `airlock/engine/orchestrator.py` | `_node_check_revocation` pipeline node |
| `airlock/gateway/admin_routes.py` | `POST /admin/revoke/{did}`, `POST /admin/unrevoke/{did}`, `GET /admin/revoked` |

### Delegation Model

| File | What it does |
|------|-------------|
| `airlock/schemas/handshake.py` | `DelegationIntent` model (scope, max_depth, expires_at) |
| `airlock/schemas/handshake.py` | Optional `delegator_did`, `credential_chain`, `delegation` fields on HandshakeRequest |
| `airlock/engine/orchestrator.py` | `_node_validate_delegation`: checks delegator not revoked, score ≥ 0.75, chain depth, expiry |
| `airlock/gateway/revocation.py` | `register_delegation()` + cascade revoke: revoke delegator → auto-revokes all delegates |

### Audit Trail

| File | What it does |
|------|-------------|
| `airlock/audit/trail.py` | Hash-chained audit log (SHA-256 of entry + previous hash, genesis = "0"×64) |
| `airlock/gateway/handlers.py` | `_audit_bg()` fire-and-forget audit on register/handshake/resolve |
| `airlock/gateway/admin_routes.py` | `GET /admin/audit` (paginated), `GET /admin/audit/verify` (chain integrity) |
| `airlock/gateway/routes.py` | `GET /audit/latest` (public chain tip) |

### Framework Integrations

| File | What it does |
|------|-------------|
| `airlock/integrations/langchain.py` | `AirlockToolGuard.wrap(tool)` — wraps any LangChain tool with pre-handshake verification |
| `airlock/integrations/openai_agents.py` | `@airlock_guard` decorator + `AirlockAgentGuard` class for OpenAI Agents SDK |
| `airlock/integrations/anthropic_sdk.py` | `AirlockToolInterceptor.verify_before_tool()` for Claude tool_use content blocks |

### Infrastructure

| File | What it does |
|------|-------------|
| `airlock/semantic/rule_evaluator.py` | Rule-based LLM fallback: keyword matching, evasion detection, answer complexity heuristics |
| `airlock/gateway/metrics.py` | Prometheus counters: revocations, verdicts, challenges, delegations, audit entries |
| `airlock/gateway/observability.py` | OpenTelemetry tracing |
| `airlock/gateway/policy.py` | Policy engine |
| `airlock/gateway/rate_limit.py` | Rate limiting (in-memory + Redis) |
| `airlock/gateway/replay.py` | Nonce replay protection (in-memory + Redis) |
| `airlock/gateway/ws.py` | WebSocket gateway |

### Docs

| File | What it is |
|------|-----------|
| `docs/PROTOCOL_SPEC.md` | 790-line RFC-style specification (12 sections + 3 appendices) |
| `docs/draft-airlock-agent-trust-00.md` | 1226-line IETF Internet-Draft (formal submission format) |
| `docs/monitoring.md` | Prometheus scrape config, alerting guide |
| `docs/deploy/internal.md` | Internal deployment guide |
| `SECURITY_AUDIT.md` | 6 vulnerabilities found and fixed |

### Demo + Tests

| File | What it is |
|------|-----------|
| `demo_trust_flow.py` | Live end-to-end demo: VERIFIED (73ms avg), REJECTED (3.5ms), Replay BLOCKED |
| `examples/` | SDK usage examples |

---

## Test Coverage

| Test File | Tests | What it covers |
|-----------|-------|----------------|
| test_crypto.py | — | Ed25519 sign/verify, DID:key derivation, VC issuance |
| test_schemas.py | — | All Pydantic models |
| test_engine.py | — | Orchestrator pipeline |
| test_gateway.py | — | All public API endpoints |
| test_admin_api.py | — | Admin endpoint auth and logic |
| test_reputation.py | — | Trust scoring, decay, thresholds |
| test_sdk.py | — | SDK client, middleware |
| test_trust_jwt.py | — | JWT issuance, introspection |
| test_a2a.py | — | A2A adapter type conversion |
| test_a2a_gateway.py | — | A2A endpoints |
| test_revocation.py | 15 | Revoke, unrevoke, cascade, fast-path |
| test_revocation_redis.py | 8 | Redis SET operations, local cache |
| test_delegation.py | 15 | DelegationIntent, chain depth, expiry, score gating |
| test_audit.py | 18 | Hash chain, verify_chain(), tamper detection |
| test_integrations.py | 14 | LangChain, OpenAI, Anthropic integration wrappers |
| test_rule_evaluator.py | 10 | Keyword match, evasion detection, quality heuristics |
| test_domain_metrics.py | 6 | Prometheus counter increments |
| test_security.py | 22 | SSRF, prompt injection, DID validation, replay |
| + 11 others | — | Rate limit, policy, WS, observability, error shapes |
| **TOTAL** | **306** | **All passing** |

---

## Performance

| Scenario | Result |
|----------|--------|
| VERIFIED (fast-path, score ≥ 0.75) | **73ms average** |
| REJECTED (rogue agent) | **3.5ms** |
| Replay attack blocked | **< 400ms** |
| Target | < 200ms |

---

## API Endpoints

### Public
| Endpoint | Method | What it does |
|----------|--------|-------------|
| `/register` | POST | Register agent DID + endpoint |
| `/handshake` | POST | 5-phase trust verification |
| `/resolve/{did}` | GET | Look up registered agent |
| `/token/introspect` | POST | Inspect trust JWT |
| `/challenge/submit` | POST | Submit challenge response |
| `/audit/latest` | GET | Get audit chain tip hash |
| `/metrics` | GET | Prometheus metrics |

### Admin (Bearer token required)
| Endpoint | Method | What it does |
|----------|--------|-------------|
| `/admin/revoke/{did}` | POST | Revoke agent (cascades to delegates) |
| `/admin/unrevoke/{did}` | POST | Lift revocation |
| `/admin/revoked` | GET | List all revoked DIDs |
| `/admin/audit` | GET | Paginated audit log |
| `/admin/audit/verify` | GET | Verify chain integrity |
| `/admin/agents` | GET | List registered agents |

### A2A (Google A2A compatible)
| Endpoint | Method | What it does |
|----------|--------|-------------|
| `/a2a/agent-card` | GET | Gateway's own A2A agent card |
| `/a2a/register` | POST | A2A-style registration |
| `/a2a/verify` | POST | A2A-style verification |

---

## Git History

```
6f5f66b  feat: complete protocol hardening — delegation, audit trail, integrations, IETF draft
915db2d  feat: production hardening sprint — revocation, security audit, protocol spec, demo
36d16d7  refactor: rename demo/ to examples/
ce13d5a  Merge A2A integration into main
8568ce9  feat: A2A-native gateway routes
902c873  feat: A2A adapter module
fc66115  Phase 1–4: schemas, engine, gateway, SDK, demo
```

---

## What Makes This Different

1. **Not authorization** — this isn't "can this agent do X". This is "is this agent who it claims to be, and should it be trusted at all."

2. **Cryptographic identity** — Ed25519 DID:key, not just API keys. Unforgeable, verifiable by anyone.

3. **Semantic verification** — agents are challenged with domain questions. A misconfigured or hijacked agent fails even if it has valid credentials.

4. **Trust scoring with memory** — agents build reputation over time. Compromised agents are detected and scored down automatically.

5. **Tamper-evident audit trail** — every action is hash-chained. If someone edits the log, `GET /admin/audit/verify` will catch it.

6. **Cascade revocation** — revoke a delegator, all agents it delegated to are automatically revoked.

7. **Framework-agnostic** — works with LangChain, OpenAI Agents SDK, Anthropic SDK. Drop-in wrappers, no lock-in.

---

## Positioning

Airlock operates at **Layer 2** of the agent security stack — between transport (TLS) and authorization (OAuth). It does not replace authorization frameworks. It answers the question that comes before authorization: *is this agent who it claims to be, and should it be trusted?*

Existing approaches address different layers:
- **Authorization frameworks** control what an agent *can do* (scopes, permissions)
- **Runtime guardrails** filter what an agent *says* (content safety, sandboxing)
- **Airlock** verifies *who the agent is* and whether it should be trusted to act at all

These layers are complementary. Airlock integrates with any authorization framework via its trust token (JWT) output.

**The gap:** Every existing solution assumes the agent is who it says it is. Airlock verifies that assumption.

---

*306 tests. 0 failures. 73ms average verification. Apache 2.0 licensed.*
