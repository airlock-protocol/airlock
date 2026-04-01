# ADR 001: Ed25519 for Agent Identity and Signing

**Status:** Accepted

**Date:** 2026-03-15

## Context

The Airlock Protocol requires a digital signature algorithm for agent identity
(DID:key) and message signing across all protocol phases. The algorithm must
support fast verification, compact keys, and deterministic signatures.

Options considered:

- **RSA-2048** — widely deployed but large keys (256 bytes), slow signing,
  non-deterministic without additional padding schemes.
- **ECDSA P-256** — compact keys but non-deterministic signatures (random nonce
  required), NIST curve provenance concerns.
- **Ed25519 (Curve25519)** — deterministic, fast, compact, modern.

## Decision

Use Ed25519 via PyNaCl for all cryptographic signing operations.

Reasons:

- Deterministic signatures (no random nonce) produce reproducible output,
  simplifying testing and auditability.
- Fast: approximately 62,000 signatures per second on commodity hardware.
- Small keys (32 bytes public, 64 bytes secret) produce compact DID strings.
- Resistant to side-channel timing attacks by design.
- Widely supported: SSH, TLS 1.3, W3C DID:key, libsodium ecosystem.
- No NIST curve provenance concerns (Bernstein curve).

## Consequences

**Positive:**
- Compact `did:key` identifiers derived directly from public keys.
- Verification is fast enough to run at transport time (gateway signature gate).
- Strong security margins with 128-bit equivalent strength.

**Negative:**
- No built-in key recovery mechanism; lost keys mean lost identity.
- Requires secure seed storage (the 32-byte seed is the entire secret).
- Not natively supported by older Java/JVM cryptography providers (BouncyCastle
  needed for JVM interop).
