# Roadmap

Current version: 1.0.0

## Vision

Airlock aims to become the standard trust verification layer for agent-to-agent communication, analogous to what TLS and DMARC are for the web and email.

## Shipped

See [CHANGELOG.md](CHANGELOG.md) for full details.

### v0.1 — Core Protocol (2026-04)
- 5-phase verification pipeline, Ed25519 DID:key identity, LangGraph orchestrator
- FastAPI gateway, Python SDK, A2A compatibility, hash-chained audit trail

### v0.2 — Trust Tiers & Anti-Sybil (2026-04)
- Progressive trust tiers with per-tier score ceilings and tiered reputation decay
- SHA-256 Hashcash proof-of-work with adaptive difficulty
- Answer fingerprinting (SimHash + SHA-256), dual-LLM evaluation, privacy modes

### v0.3 — Revocation & Key Rotation (2026-04)
- Signed CRL with tiered freshness degradation
- Key rotation with chain continuity and pre-rotation commitments
- Argon2id memory-hard PoW option, per-DID rate limiting

### v0.4 — Persistence & Multi-Replica (2026-04)
- SQLite-backed audit trail; Redis-backed rotation and pre-commitment stores
- Trust-weighted VC capability verification with graduated enforcement
- mypy --strict across the package

### v1.0 — Production (2026-04)
- OAuth 2.1 authorization server (client credentials, RFC 8693 token exchange, introspection, OIDC discovery)
- Compliance engine: agent inventory, risk classification, incident tracking, reports
- Dual-mode identity verification (Ed25519 signatures and OAuth bearer tokens)

## Next

### Federation
- [ ] Multi-gateway federation protocol
- [ ] Cross-domain trust delegation
- [ ] Distributed reputation store (CRDTs)
- [ ] Gateway-to-gateway trust peering

### Standards & Interop
- [ ] IETF RFC submission (from Internet-Draft)
- [ ] Reference implementations in Go and Rust
- [ ] Backward compatibility guarantees and LTS policy

### Hardening & Assurance
- [ ] Formal security audit by third party
- [ ] Formal verification of trust scoring model
- [ ] OpenSSF Scorecard integration and CII Best Practices badge
- [ ] Performance benchmarks suite (target: <50ms p99 verification)

### Extensibility
- [ ] Plugin architecture for custom verification checks
- [ ] WebSocket-based real-time trust stream

## Future Directions
- Hardware-backed agent identity (TPM, Secure Enclave)
- Zero-knowledge proof integration for privacy-preserving verification
- Integration with W3C Decentralized Identifier (DID) universal resolver
- Regulatory compliance modules (PSD2, Open Banking)

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for how to get involved. Protocol changes follow the RFC process described in [GOVERNANCE.md](GOVERNANCE.md).
