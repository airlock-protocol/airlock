# Changelog

All notable changes to the Airlock Protocol are documented in this file.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-04-13

### Added
- **OAuth 2.1 Authorization Server**: client credentials grant with `private_key_jwt` (Ed25519) client authentication, RFC 8693 token exchange for delegation chains with scope narrowing, EdDSA-signed access tokens carrying trust score claims
- OAuth endpoints: `POST /oauth/token`, `POST /oauth/register`, `POST /oauth/introspect`, `POST /oauth/revoke`, plus OIDC discovery (`/.well-known/openid-configuration`) and JWKS (`/.well-known/jwks.json`)
- **Compliance module**: agent inventory, risk classification (low/medium/high/critical), incident tracking with hash-chain integrity, automated report generation with regulatory framework mapping, bias detection for verification outcome patterns
- **Dual-mode identity verification**: orchestrator accepts both Ed25519 signatures and OAuth bearer tokens; existing Ed25519 flows unchanged
- 853 tests passing

### Changed
- Semantic (LLM) challenge disabled by default; trust decisions rest on cryptographic verification and behavioral scoring
- `litellm` moved from core dependencies to the optional `[llm]` extra

## [0.4.0] - 2026-04-05

### Added
- SQLite-backed persistent audit store (WAL mode, `asyncio.to_thread` for async safety)
- Redis-backed rotation chain registry using single-key Lua scripts (Redis Cluster-safe)
- Redis-backed pre-commitment store for multi-replica pre-rotation commitments
- Trust-weighted VC capability cross-referencing (1.0/0.5/0.0 scoring) with graduated enforcement mode (`off`/`audit`/`warn`/`enforce`)
- 760 tests passing

### Changed
- `rotation_chain_id` threaded through sessions, audit entries, and A2A metadata
- DID resolution for reputation lookups goes through the rotation chain registry
- LangChain integration gains a sync wrapper for nested event loops
- mypy `--strict` passing across all source files

## [0.3.0] - 2026-04-05

### Added
- **Signed CRL**: `GET /crl` and `GET /.well-known/airlock-crl` with Ed25519 signatures, monotonic `crl_number`, ETag caching, and tiered freshness degradation (NORMAL -> DEGRADED -> EMERGENCY -> FAIL_CLOSED); optional separate CRL signing key
- **Key rotation with chain continuity**: `rotation_chain_id` (SHA-256 of the first public key) links successive DIDs; trust scores, rate limits, and fingerprints follow the chain; first-write-wins prevents fork attacks. New endpoints: `POST /rotate-key`, `POST /pre-commit-key`
- **Pre-rotation commitments** (KERI-inspired): agents commit the SHA-256 of their next public key before rotating; mandatory from Tier 1, with a 72-hour update lockout
- **Argon2id proof-of-work**: optional memory-hard PoW with SHA-256 pre-filter, three server-assigned presets (light/standard/hardened), and bounded verification concurrency
- Per-DID rate limiting (`DIDRateLimiter`) with structured 429 responses and `Retry-After` headers
- Rotation chain registry JSON persistence; startup guard blocks multi-replica deployments with in-memory rotation state
- Security Considerations document (IETF BCP 72 style)
- 685 tests passing

### Changed
- Trust token introspection now checks revocation status; revoked or suspended DIDs are rejected even while the JWT is unexpired
- Default trust token TTL reduced from 600s to 120s to shrink the revocation gap window
- `FingerprintStore` uses `asyncio.Lock` instead of `threading.Lock` for non-blocking concurrent request handling

### Fixed
- `FingerprintStore.check_sync()`/`add_sync()` now raise `RuntimeError` when called from a running event loop instead of silently bypassing the lock (race condition vector removed)
- Orchestrator resolves reputation through the chain ID so mid-session key rotation keeps the agent's trust score
- CRL is force-regenerated after a key-compromise rotation

## [0.2.1] - 2026-04-05

### Fixed
- **PoW Challenge Replay** (CRITICAL): `verify_pow()` now validates challenges against a server-side store with one-time use enforcement and expiry checks
- **RFC 8785 Canonical JSON** (CRITICAL): Removed `default=str` from `canonicalize()` — explicit type conversion ensures cross-language signature verification (Go, Rust, JS)

### Changed
- **Revocation model**: `revoke()` is now permanent and irreversible for key compromise scenarios; added `suspend()`/`reinstate()` for reversible holds
- **Attestation signing**: `AirlockAttestation.airlock_signature` is now populated with a real Ed25519 signature, enabling cryptographic verification by relying parties
- Added `RevocationReason` enum with 7 reason codes
- New admin endpoints: `POST /admin/suspend/{did}`, `POST /admin/reinstate/{did}`

### Removed
- `unrevoke()` method — replaced by `suspend()`/`reinstate()`
- `DELETE /admin/revoke/{did}` endpoint

### Security
- 4 security audit documents added to `docs/security/`

## [0.2.0] - 2026-04-05

### Added
- **Trust Tiers**: Progressive trust levels (UNKNOWN -> CHALLENGE_VERIFIED -> DOMAIN_VERIFIED -> VC_VERIFIED) with configurable score ceilings per tier
- **Tiered Decay**: Per-tier reputation half-lives (30/90/180/365 days) with decay floor at 0.60 for established agents
- **Proof-of-Work**: SHA-256 Hashcash anti-Sybil protection on handshake with adaptive difficulty
- **Privacy Mode**: `privacy_mode` field in HandshakeRequest (`any`/`local_only`/`no_challenge`) for GDPR/DPDP compliance
- **Structured LLM Output**: JSON schema evaluation via LiteLLM `response_format` parameter
- **Dual-LLM Evaluation**: Optional second model cross-validation with conservative agreement protocol
- **Answer Fingerprinting**: SimHash + SHA-256 duplicate/near-duplicate detection for bot farm defense
- New `GET /pow-challenge` endpoint for PoW challenge issuance
- `TrustTier` IntEnum in attestations for relying party visibility
- `fingerprint_flags` field in AirlockAttestation
- 131 new tests across 10 test files (property-based, security, integration)

### Changed
- `AirlockAttestation` now includes `tier`, `privacy_mode`, and `fingerprint_flags` fields
- `HandshakeRequest` now includes optional `pow` and `privacy_mode` fields
- Reputation scoring respects tier ceilings (LLM-only agents capped at 0.70)
- Decay uses tier-specific half-lives instead of single global value

### Security
- PoW prevents Sybil/DoS attacks on handshake endpoint
- Answer fingerprinting detects coordinated bot farm submissions
- Dual-LLM evaluation requires attacker to fool two independent models
- `privacy_mode: local_only` prevents data from leaving gateway instance

## [0.1.0] - 2026-04-01

### Added
- 5-phase trust verification pipeline (Resolve, Handshake, Challenge, Verdict, Seal)
- Ed25519 DID:key identity layer with W3C Verifiable Credentials
- LangGraph 10-node orchestrator with revocation and delegation nodes
- Trust scoring with temporal decay (30-day half-life, diminishing returns)
- Agent revocation with cascade delegation support
- Hash-chained audit trail (SHA-256, tamper-evident, genesis anchored)
- Semantic challenge with LLM evaluation and rule-based fallback
- Framework integrations: LangChain, OpenAI Agents SDK, Anthropic SDK
- FastAPI gateway with 20+ endpoints (public, admin, A2A-native)
- Python SDK: async client, ASGI middleware, simple decorator
- Google A2A protocol compatibility (agent card, register, verify)
- JWT trust tokens (HS256) with introspection endpoint
- SSRF protection on callback URLs
- LLM prompt injection mitigation with answer sanitization
- Rate limiting per-IP and per-DID (in-memory and Redis)
- Nonce-based replay protection (in-memory and Redis)
- DID format validation and endpoint URL scheme validation
- Expired challenge sweep with 10,000 hard cap
- Prometheus metrics for verdicts, revocations, challenges, delegations
- Redis backend support for multi-replica deployments
- Docker deployment with liveness, readiness, and health probes
- Startup validation for production configuration
- IETF Internet-Draft specification (draft-airlock-agent-trust-00)
- Protocol specification (790 lines, RFC-style)
- Monitoring and deployment documentation
- 338 tests passing across 30 test files
- BSL 1.1 gateway license, Apache 2.0 SDKs, CC-BY-4.0 spec
