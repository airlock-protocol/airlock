# Roadmap

Current version: 0.1.0 (Beta)

## Vision

Airlock aims to become the standard trust verification layer for agent-to-agent communication, analogous to what TLS and DMARC are for the web and email.

## v0.2.0 — Protocol Hardening (Q2 2026)
- [ ] OpenSSF Scorecard integration and CII Best Practices badge
- [ ] Formal verification of trust scoring model
- [ ] Plugin architecture for custom verification checks
- [ ] WebSocket-based real-time trust stream
- [ ] Performance benchmarks suite (target: <50ms p99 verification)

## v0.3.0 — Federation (Q3 2026)
- [ ] Multi-gateway federation protocol
- [ ] Cross-domain trust delegation
- [ ] Distributed reputation store (CRDTs)
- [ ] Gateway-to-gateway trust peering

## v1.0.0 — Production (Q4 2026)
- [ ] IETF RFC submission (from Internet-Draft)
- [ ] Formal security audit by third party
- [ ] Backward compatibility guarantees
- [ ] LTS release with semantic versioning commitment
- [ ] Reference implementations in Go and Rust

## Future Directions
- Hardware-backed agent identity (TPM, Secure Enclave)
- Zero-knowledge proof integration for privacy-preserving verification
- Integration with W3C Decentralized Identifier (DID) universal resolver
- Regulatory compliance modules (PSD2, Open Banking)

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for how to get involved. Protocol changes follow the RFC process described in [GOVERNANCE.md](GOVERNANCE.md).
