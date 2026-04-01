# Changelog

All notable changes to the Airlock Protocol are documented in this file.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
- 306 tests passing across 30 test files
- Apache 2.0 license
