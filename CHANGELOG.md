# Changelog

All notable changes to the Airlock Protocol are documented in this file.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
- 60+ new tests (property-based, security, integration)

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
