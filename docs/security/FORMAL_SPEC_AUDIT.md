# Airlock Protocol -- Formal Specification Audit

**Audit Date:** 2026-04-05
**Auditor:** Airlock Security Team
**Scope:** Protocol specification (`docs/PROTOCOL_SPEC.md`), IETF Internet-Draft (`docs/draft-airlock-agent-trust-00.md`), and reference implementation (`airlock/`)
**Purpose:** Identify gaps between specification claims, implementation behavior, and IETF/W3C standards requirements.

---

## Summary

| Severity | Count | Description |
|----------|-------|-------------|
| CRITICAL | 3 | Interoperability blockers, protocol non-determinism, spec completeness |
| HIGH | 6 | Standards timeline, conformance testing, version negotiation, test vectors, language leakage, attestation integrity |
| MEDIUM | 5 | Wire format, IANA registrations, timing parameters, error code registry, privacy enforcement |

**Total Findings: 14**

---

## CRITICAL Findings

### C-1: Canonical JSON Uses `default=str` -- RFC 8785 Conformance Violation

**Severity:** CRITICAL
**Component:** `airlock/crypto/signing.py`, line 26
**Affects:** Cross-implementation signature verification, interoperability with non-Python implementations

**Finding:**

The `canonicalize()` function claims to follow RFC 8785 (JSON Canonicalization Scheme) but uses Python's `json.dumps()` with `default=str` as a fallback serializer:

```python
return json.dumps(cleaned, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
```

RFC 8785 defines a strict canonical form for JSON values. The `default=str` parameter causes Python to silently coerce non-serializable types (datetime objects, UUIDs, enums, bytes, Pydantic models) into their `str()` representations. This creates three interoperability failures:

1. **datetime serialization is implementation-defined.** Python's `str(datetime)` produces `2026-04-05 12:00:00+00:00` (space-separated, no `T`), while ISO 8601 requires `2026-04-05T12:00:00+00:00`. A Go, Rust, or JavaScript implementation following ISO 8601 will produce a different canonical form and therefore a different signature. Signatures computed by the Python implementation will fail verification on any non-Python implementation, and vice versa.

2. **Enum serialization leaks Python internals.** `str(TrustTier.UNKNOWN)` produces `"TrustTier.UNKNOWN"` or `"0"` depending on the enum type (IntEnum vs StrEnum), not a portable value.

3. **UUID coercion.** `str(uuid.UUID(...))` produces a specific hyphenated format, but RFC 8785 has no concept of UUID types -- they must be serialized as strings before canonicalization.

The spec document (`PROTOCOL_SPEC.md`, Section 10.7) states the procedure "follows principles from RFC 8785" but does not acknowledge the `default=str` deviation. Any implementation following the spec text literally (without Python's `default=str` behavior) will produce incompatible signatures.

**Recommendation:**

1. Remove `default=str` from the `json.dumps()` call entirely. Force all values to be JSON-native types (str, int, float, bool, None, list, dict) *before* canonicalization.
2. Add an explicit pre-serialization step that converts datetime to ISO 8601 strings (`isoformat()`), enums to their `.value`, and UUIDs to `str()` *in a deterministic, documented format*.
3. Add a normative section to the spec defining the exact pre-serialization rules for each non-JSON type used in protocol messages.
4. Consider using a proper RFC 8785 library (e.g., `canonicaljson` for Python) instead of hand-rolling canonicalization.

**References:**
- RFC 8785: JSON Canonicalization Scheme (JCS)
- `airlock/crypto/signing.py:16-26` (canonicalize function)
- `docs/PROTOCOL_SPEC.md` Section 10.7 (Canonical JSON Signing)
- Pydantic `model.model_dump(mode="json")` already handles some conversions -- verify whether the `sign_model()` path (line 65) avoids this issue by pre-converting via Pydantic, while raw `sign_message()` does not.

---

### C-2: LLM Challenge Non-Determinism in Protocol Specification

**Severity:** CRITICAL
**Component:** `airlock/semantic/challenge.py`, `docs/PROTOCOL_SPEC.md` Section 6 (Verification Pipeline), `docs/draft-airlock-agent-trust-00.md` Section 6
**Affects:** Protocol reproducibility, conformance testing, formal verification

**Finding:**

The protocol specification defines the Challenge phase (Phase 3) as a core protocol step, but the challenge question generation and evaluation are delegated to an LLM (`litellm.acompletion()`), making them inherently non-deterministic. This creates several specification problems:

1. **Challenge generation is non-reproducible.** The `generate_challenge()` function calls an LLM to produce questions (line 304-334). Two conforming implementations using different LLM models/providers will generate different questions for the same agent capabilities. The spec does not define what constitutes a "valid" challenge question beyond informal prose.

2. **Evaluation is non-reproducible.** The `evaluate_response()` function (line 431-475) delegates verdict decisions to an LLM. The same answer may receive PASS from one LLM and FAIL from another. The dual-LLM evaluation mode (line 478-535) mitigates but does not eliminate this: two implementations using different model pairs will produce different verdicts.

3. **The spec cannot be formally verified.** A protocol specification must have deterministic state transitions for conformance testing. The Challenge->Verdict transition depends on LLM output, which is not deterministic.

4. **Fallback behavior is underspecified.** When the LLM is unavailable, the system falls back to rule-based evaluation or AMBIGUOUS (line 467-474). The spec does not mandate which fallback behavior is normative, creating implementation divergence.

The IETF draft (`draft-airlock-agent-trust-00.md`) lists the semantic challenge as a normative protocol phase but does not acknowledge the non-determinism or specify how conformance should be tested.

**Recommendation:**

1. Formally partition the spec into a **deterministic core** (Resolve, Handshake, Signature Verification, Seal) and a **non-deterministic extension** (LLM Challenge). Make the LLM Challenge MAY/OPTIONAL rather than MUST.
2. Define a deterministic minimum conformance path: if LLM is unavailable, the rule-based evaluator (`airlock/semantic/rule_evaluator.py`) MUST be the normative fallback, not AMBIGUOUS.
3. Specify concrete evaluation criteria (keyword density, coherence score, complexity thresholds) as normative requirements for the rule-based path, so two implementations can produce the same verdict for the same input.
4. Add a conformance clause: "Implementations MAY use LLM-based evaluation as an enhancement but MUST also implement the deterministic rule-based evaluator as a baseline."
5. In the IETF draft, add an "Operational Considerations" section explicitly acknowledging non-determinism and documenting the dual-evaluation mitigation.

**References:**
- `airlock/semantic/challenge.py:304-334` (generate_challenge)
- `airlock/semantic/challenge.py:431-475` (evaluate_response)
- `airlock/semantic/challenge.py:478-535` (evaluate_response_dual)
- `airlock/semantic/rule_evaluator.py` (deterministic fallback)
- `docs/PROTOCOL_SPEC.md` Phase 3 description
- `docs/draft-airlock-agent-trust-00.md` Section 6

---

### C-3: Security Considerations Section Incomplete for IETF Submission

**Severity:** CRITICAL
**Component:** `docs/draft-airlock-agent-trust-00.md` Section 10, `docs/PROTOCOL_SPEC.md` Section 10
**Affects:** IETF Area Director review, BCP 72 compliance

**Finding:**

Both specification documents contain a Security Considerations section (Section 10), but the coverage is insufficient for IETF publication. BCP 72 (RFC 3552, "Guidelines for Writing RFC Text on Security Considerations") requires that security considerations sections address:

The existing section covers nonce replay (10.1), rate limiting (10.2), signature-first validation (10.3), VC issuer allowlist (10.4), canonical JSON signing (10.5/10.7), subject binding (10.6), Sybil protection (10.7), session TTL (10.8), SSRF prevention (10.9), and trust token security (10.10).

**Missing topics required by BCP 72:**

1. **Threat model.** No formal threat model is defined. Who are the adversaries? What are their capabilities? The section lists mitigations without stating what they mitigate against.

2. **LLM prompt injection.** The protocol uses LLM-evaluated challenges, but the security section does not discuss prompt injection attacks where a malicious agent crafts answers to manipulate the evaluation LLM. The implementation has mitigations (`_sanitize_answer()`, control character stripping, length limits) but these are not documented in the spec.

3. **Downgrade attacks.** No discussion of what happens when an attacker forces fallback from LLM evaluation to rule-based evaluation, or from dual-LLM to single-LLM. The fallback path may be weaker.

4. **Privacy analysis.** The protocol collects agent capabilities, challenge answers, trust scores, and behavioral fingerprints (SimHash). The security section does not discuss data minimization, storage duration, or what information is exposed to other agents.

5. **Key compromise recovery.** No discussion of what happens when an agent's Ed25519 private key is compromised. How does the agent revoke its DID? How do relying parties learn of the compromise?

6. **Gateway trust model.** The gateway is a trusted third party that holds all verification data. The security section does not discuss gateway compromise, multi-gateway federation trust, or gateway operator malfeasance.

7. **Timing side-channel attacks.** Signature verification and reputation lookups may leak information through timing differences. The section does not discuss constant-time operations.

8. **Denial of service beyond rate limiting.** The PoW mechanism is mentioned in config but not in the security section. No discussion of computational DoS via expensive LLM evaluations.

**Recommendation:**

1. Add a formal threat model section (Section 10.0) listing adversary classes: malicious agents, compromised gateways, network attackers, colluding agents.
2. Add subsections for each missing topic listed above.
3. For each mitigation, state which threat it addresses (traceability).
4. Reference BCP 72 explicitly in the IETF draft.
5. The PROTOCOL_SPEC.md should mirror these additions for consistency.

**References:**
- RFC 3552 (BCP 72): Guidelines for Writing RFC Text on Security Considerations
- `docs/draft-airlock-agent-trust-00.md` Section 10
- `docs/PROTOCOL_SPEC.md` Section 10
- `airlock/semantic/challenge.py:25-28` (_sanitize_answer -- undocumented mitigation)
- `airlock/config.py:128-131` (PoW configuration -- not in security section)

---

## HIGH Findings

### H-1: IETF Standards Track Timeline Unrealistic

**Severity:** HIGH
**Component:** `docs/draft-airlock-agent-trust-00.md`
**Affects:** Project planning, investor expectations, go-to-market strategy

**Finding:**

The Internet-Draft (`draft-airlock-agent-trust-00`) is formatted as an Informational I-D but the project materials and spec positioning suggest Standards Track ambitions. The IETF standardization process has significant timeline implications that are not acknowledged:

1. **Minimum timeline.** An I-D must go through Working Group adoption, WG Last Call, IETF Last Call, IESG review, and RFC Editor processing. Typical minimum for a *well-supported* document: 2-3 years from first I-D submission to published RFC.

2. **No Working Group exists.** There is no existing IETF WG focused on AI agent trust. Creating a new WG requires a BOF (Birds of a Feather) session, charter development, and area director sponsorship. This alone adds 6-12 months.

3. **Dependency on evolving standards.** The spec references W3C DID Core and W3C VC Data Model 1.1, both of which are still maturing. Any changes to those specs may require Airlock spec revisions.

4. **The LLM-dependent challenge phase is unprecedented in IETF.** No existing RFC includes LLM-based verification. This will face significant pushback during IESG review and may require novel security analysis.

5. **Copyright notice.** The draft's copyright notice says "Copyright (c) 2026 Shivdeep Singh. All rights reserved." -- but IETF I-Ds must use the IETF Trust copyright per BCP 78. This needs correction before any formal submission.

**Recommendation:**

1. Acknowledge the 2-3.5 year timeline explicitly in project planning documents.
2. Pursue parallel standardization paths: submit to IETF for credibility, but also publish as an independent specification that implementations can adopt immediately.
3. Fix the copyright notice to comply with BCP 78 before submission.
4. Consider starting with an Individual Submission I-D to an area director (SEC or ART area) rather than waiting for WG formation.
5. Engage with the IETF OAuth WG and W3C DID WG to build cross-standards-body support.

**References:**
- `docs/draft-airlock-agent-trust-00.md` lines 46-49 (copyright notice)
- RFC 2026: The Internet Standards Process
- BCP 78: Rights Contributors Provide to the IETF Trust

---

### H-2: No Conformance Test Suite

**Severity:** HIGH
**Component:** Test infrastructure
**Affects:** Third-party implementations, protocol interoperability

**Finding:**

The project has 399+ tests (`tests/` directory), but these are implementation tests for the Python reference implementation. There is no conformance test suite that a third-party implementor (Go, Rust, JavaScript, Java) could run to verify their implementation conforms to the protocol spec.

For a protocol to be interoperable, it needs:

1. **Test vectors.** Deterministic input/output pairs that any implementation must produce. Currently absent.
2. **Wire-format examples.** Complete JSON examples for every message type. The spec has field tables but no complete examples.
3. **Conformance assertions.** A numbered list of "MUST" requirements that can be individually tested. These exist in the spec text but are not extracted into a testable format.
4. **Negative test cases.** Examples of invalid messages that MUST be rejected (malformed DIDs, expired challenges, replayed nonces, invalid signatures). Currently absent from the spec.

Without a conformance test suite, two implementations claiming Airlock compatibility may be incompatible. This is especially critical given the canonicalization issue (C-1).

**Recommendation:**

1. Create a `conformance/` directory with language-agnostic test vectors in JSON format.
2. For each message type, provide at least 3 valid examples and 3 invalid examples.
3. Provide canonical-form test vectors: given input dict -> expected canonical bytes -> expected Ed25519 signature (using a known test key pair).
4. Publish test vectors alongside the spec (as an appendix or companion document).
5. Include test vectors for edge cases: empty fields, maximum-length fields, Unicode normalization, datetime serialization.

**References:**
- `tests/` directory (implementation tests, not conformance tests)
- RFC 8785 Section 4 (provides its own test vectors -- Airlock should follow this pattern)
- `docs/PROTOCOL_SPEC.md` (no test vectors section)

---

### H-3: Version Negotiation Absent

**Severity:** HIGH
**Component:** `airlock/config.py`, `airlock/schemas/envelope.py`, 11+ files with hardcoded version strings
**Affects:** Protocol evolution, backward compatibility, multi-version deployments

**Finding:**

The protocol version is hardcoded as `"0.1.0"` in 11+ locations across the codebase:

- `airlock/config.py:22` -- `protocol_version: str = "0.1.0"`
- `airlock/cli.py:17` -- `@click.version_option(version="0.1.0")`
- `airlock/schemas/envelope.py:41` -- `create_envelope(..., protocol_version: str = "0.1.0")`
- `airlock/a2a/adapter.py:52,84` -- hardcoded in adapter
- `airlock/gateway/a2a_routes.py:90` -- `protocol_versions: list[str] = Field(default_factory=lambda: ["0.1.0"])`
- `airlock/sdk/simple.py:118` -- hardcoded in SDK
- `airlock/gateway/app.py:207` -- hardcoded in app factory
- `airlock/engine/orchestrator.py:383,476` -- hardcoded in orchestrator
- `airlock/semantic/challenge.py:320` -- hardcoded in challenge generation

The `MessageEnvelope` carries a `protocol_version` field, but neither the spec nor the implementation defines:

1. **Version negotiation.** How does a client discover which versions a gateway supports? How does a gateway reject messages with unsupported versions?
2. **Backward compatibility rules.** When version 0.2.0 is released, can a 0.1.0 client talk to a 0.2.0 gateway? The spec is silent.
3. **Version mismatch handling.** There is no error code for `VERSION_UNSUPPORTED`. The `TransportNack` error codes are: `INVALID_SIGNATURE`, `INVALID_SCHEMA`, `REPLAY`, `RATE_LIMITED`, `SENDER_MISMATCH` -- none for version mismatch.
4. **Semver semantics.** The spec uses semver-style versions but does not define what constitutes a breaking change vs. a backward-compatible change.

The A2A adapter has a `protocol_versions: list[str]` field (plural), suggesting some awareness of multi-version support, but it defaults to a single-element list and no negotiation logic exists.

**Recommendation:**

1. Add a `VERSION_UNSUPPORTED` error code to `TransportNack`.
2. Define version negotiation: the gateway SHOULD advertise supported versions in its agent card or health endpoint; the client SHOULD send its preferred version in the envelope; the gateway MUST reject envelopes with unsupported versions.
3. Define backward compatibility policy: minor version bumps (0.1.x -> 0.1.y) MUST be backward compatible; minor version bumps (0.1.x -> 0.2.x) MAY break compatibility; the gateway SHOULD support at least the current and previous minor version.
4. Centralize the version string to a single source of truth (e.g., `airlock/__version__.py`) and import it everywhere.
5. Add the version negotiation mechanism to both spec documents.

**References:**
- `airlock/config.py:22`
- `airlock/schemas/envelope.py:41`
- `airlock/gateway/a2a_routes.py:90`
- `airlock/engine/orchestrator.py:383,476`
- `airlock/semantic/challenge.py:320`
- HTTP Content Negotiation (RFC 7231) as a pattern reference

---

### H-4: 44+ Test Vectors Required for Spec Completeness

**Severity:** HIGH
**Component:** Spec documents (both), `tests/`
**Affects:** Interoperability, third-party implementors

**Finding:**

A protocol specification intended for multi-language implementation requires test vectors for each normative behavior. Based on the spec's MUST/SHOULD requirements, the following test vectors are needed (minimum):

**Canonicalization (8 vectors):**
1. Simple flat dict -> canonical bytes
2. Nested dict with sorted keys -> canonical bytes
3. Dict with datetime value -> canonical bytes (showing expected ISO 8601 format)
4. Dict with enum value -> canonical bytes (showing expected value serialization)
5. Dict with `signature` field -> canonical bytes (field must be stripped)
6. Dict with Unicode characters -> canonical bytes (UTF-8 normalization)
7. Dict with numeric values (int, float) -> canonical bytes (JSON number format)
8. Empty dict -> canonical bytes

**Signature (6 vectors):**
9. Known key pair + known message -> expected base64 signature
10. Valid signature verification -> True
11. Tampered message + original signature -> False
12. Wrong key + valid signature -> False
13. Malformed base64 signature -> False
14. Empty message dict -> expected signature

**HandshakeRequest (6 vectors):**
15. Valid complete HandshakeRequest -> expected canonical form
16. HandshakeRequest with delegation fields -> expected canonical form
17. HandshakeRequest with PoW -> expected canonical form
18. Invalid DID format -> rejection
19. Envelope sender != initiator DID -> rejection (INVALID_ENVELOPE)
20. Replayed nonce -> rejection (REPLAY)

**VerifiableCredential (5 vectors):**
21. Valid VC with matching subject DID -> accepted
22. Expired VC -> rejected
23. VC with untrusted issuer (allowlist enabled) -> rejected
24. VC with mismatched subject DID -> rejected
25. VC with invalid proof signature -> rejected

**Trust scoring (6 vectors):**
26. New agent initial score -> 0.5
27. VERIFIED verdict score delta -> +0.05
28. REJECTED verdict score delta -> -0.15
29. Tier ceiling enforcement -> score capped at tier ceiling
30. Temporal decay calculation -> expected decayed score after N days
31. Floor protection -> score does not drop below floor after N interactions

**Challenge/Response (5 vectors):**
32. Expired challenge -> FAIL
33. Empty answer -> FAIL
34. Rule-based evaluation: below keyword density threshold -> expected outcome
35. Rule-based evaluation: below coherence threshold -> expected outcome
36. Rule-based evaluation: below complexity threshold -> expected outcome

**Error codes (4 vectors):**
37. INVALID_SIGNATURE -> 400 or 403
38. REPLAY -> 409
39. RATE_LIMIT -> 429 with headers
40. INVALID_ENVELOPE -> 400

**Privacy modes (4 vectors):**
41. `privacy_mode=any` -> full pipeline, reputation written
42. `privacy_mode=local_only` -> no reputation write
43. `privacy_mode=no_challenge` -> challenge skipped, DEFERRED verdict
44. Invalid privacy_mode value -> rejection or default

**Answer fingerprinting (3 vectors):**
45. Exact duplicate answer -> configured action (fail/flag)
46. Near duplicate (SimHash hamming distance <= threshold) -> configured action
47. Unique answer -> no flag

**Recommendation:**

Create a `conformance/test-vectors.json` file containing all 44+ vectors. Each vector should include:
- Vector ID and description
- Input data (as JSON)
- Expected output (canonical bytes as hex, signatures as base64, verdicts as strings)
- Test key pairs (Ed25519 seed + public key + DID)

**References:**
- RFC 8785 Section 4 (test vectors pattern)
- RFC 8032 Section 7.1 (Ed25519 test vectors)
- `airlock/crypto/signing.py` (canonicalization rules)
- `airlock/config.py:80-108` (scoring parameters)
- `airlock/schemas/trust_tier.py` (tier definitions)

---

### H-5: Python-Specific Constructs Leak into Protocol Definitions

**Severity:** HIGH
**Component:** `docs/PROTOCOL_SPEC.md`, `docs/draft-airlock-agent-trust-00.md`, schema definitions
**Affects:** Language-agnostic implementability

**Finding:**

The protocol specification contains several constructs that assume Python and/or Pydantic, making it difficult for non-Python implementors to build conforming implementations:

1. **Pydantic model references.** The spec references Pydantic-specific patterns: `model.model_dump(mode="json")`, `BaseModel`, `Field(ge=0.0, le=1.0)`. These are implementation details, not protocol definitions.

2. **Python type syntax.** Field types are written in Python syntax: `str | None`, `list[str]`, `dict[str, Any]`. The IETF draft should use ABNF, JSON Schema, or CDDL (RFC 8610) for type definitions.

3. **StrEnum/IntEnum.** Protocol enumerations are defined as Python enums (`class TrustVerdict(StrEnum)`, `class TrustTier(IntEnum)`) rather than as enumerated string/integer sets in a language-agnostic format.

4. **Configuration via environment variables.** The spec defines configuration as `AIRLOCK_*` environment variables, which is a deployment convention, not a protocol requirement. The protocol should define abstract configuration parameters; the env-var mapping belongs in the reference implementation docs.

5. **`default=str` in canonicalization.** As noted in C-1, this is a Python-specific serialization escape hatch that has no equivalent in other languages.

6. **`asyncio` patterns.** The spec's reference to `asyncio.wait_for` and `asyncio.gather` in describing dual-LLM evaluation is implementation-specific.

**Recommendation:**

1. Replace Python type syntax with JSON Schema (or CDDL for the IETF draft) for all message type definitions.
2. Define enumerations as explicit value sets: `TrustVerdict := "VERIFIED" | "REJECTED" | "DEFERRED"` rather than as Python classes.
3. Separate the protocol spec from the implementation guide. Protocol messages should be defined in terms of JSON objects with typed fields. Implementation guidance (env vars, Pydantic models, async patterns) should be in a separate document.
4. In the IETF draft, use ABNF (RFC 5234) for string formats and JSON Schema for message structure.

**References:**
- RFC 8610: Concise Data Definition Language (CDDL)
- RFC 5234: ABNF
- `docs/PROTOCOL_SPEC.md` (throughout)
- `airlock/schemas/verdict.py` (Python enum definitions)
- `airlock/schemas/handshake.py` (Pydantic model definitions)

---

### H-6: Attestation Signatures Never Populated

**Severity:** HIGH
**Component:** `airlock/schemas/verdict.py`, `airlock/engine/orchestrator.py`
**Affects:** Attestation integrity, trust chain verification

**Finding:**

The `AirlockAttestation` model (`airlock/schemas/verdict.py`, line 36-47) defines an `airlock_signature` field:

```python
airlock_signature: str | None = None
```

This field is intended to contain the gateway's Ed25519 signature over the attestation, providing cryptographic proof that the gateway issued this attestation. However, a search of the codebase shows that `airlock_signature` is **never populated** in the orchestrator or any other component.

In `airlock/engine/orchestrator.py`, when the attestation is constructed (around lines 400-410 and 490-495), the `airlock_signature` field is omitted, leaving it at its default `None` value.

This means:
1. **Attestations are unsigned.** Any party can forge an attestation by constructing a valid-looking `AirlockAttestation` JSON object. There is no way for a relying party to verify that a specific gateway actually issued the attestation.
2. **The trust chain is broken.** The protocol's value proposition is cryptographic trust verification, but the final output (the attestation) is not cryptographically bound to the issuing gateway.
3. **The `trust_token` field** (also in `AirlockAttestation`) is an HS256 JWT and does provide signed proof, but it requires the relying party to have the gateway's shared secret. The `airlock_signature` was presumably intended as a publicly verifiable alternative using Ed25519.

The protocol spec (Section 5, Seal phase) describes the attestation as signed but the implementation does not fulfill this.

**Recommendation:**

1. After constructing the `AirlockAttestation`, sign its canonical JSON form with the gateway's Ed25519 key and populate `airlock_signature`.
2. Add a verification method to the SDK that allows relying parties to verify attestation signatures using the gateway's public key (derivable from the gateway's DID).
3. Update the spec to make attestation signing a MUST requirement.
4. Add test cases verifying that attestations are always signed and that the signature is valid.

**References:**
- `airlock/schemas/verdict.py:36-47` (AirlockAttestation model)
- `airlock/engine/orchestrator.py:400-410,490-495` (attestation construction)
- `airlock/crypto/signing.py:58-71` (sign_model -- exists but not used for attestations)

---

## MEDIUM Findings

### M-1: Wire Format Not Fully Specified

**Severity:** MEDIUM
**Component:** `docs/PROTOCOL_SPEC.md` Section 11, `docs/draft-airlock-agent-trust-00.md` Section 5
**Affects:** Interoperability, transport independence claim

**Finding:**

The spec claims transport-agnostic design but only defines a REST/HTTPS binding. Key wire format details are missing:

1. **Content-Type.** The spec does not mandate a Content-Type for request/response bodies. Is it `application/json`? `application/airlock+json`? A custom media type would enable content negotiation and middleware routing.

2. **Character encoding.** While the canonicalization section specifies UTF-8, the wire format section does not mandate `Content-Type: application/json; charset=utf-8` headers.

3. **Message framing for WebSocket.** The WS transport (Section 11.3) does not specify whether messages are sent as text frames or binary frames, or whether multiple messages can be batched in a single frame.

4. **Binary encoding option.** For performance-sensitive deployments, the spec does not discuss CBOR (RFC 8949) or other binary encodings. This is not required but is typically addressed in protocol specs as a future consideration.

5. **HTTP method semantics.** All state-changing operations use POST, including `/resolve` which is a read operation. This violates HTTP semantics (RFC 7231) and prevents caching.

**Recommendation:**

1. Register a custom media type (`application/airlock+json`) or document the use of `application/json`.
2. Mandate `charset=utf-8` in Content-Type headers.
3. Define WebSocket framing: one JSON text frame per message, no batching.
4. Change `/resolve` from POST to GET with query parameters (DID as query param) to enable HTTP caching.
5. Add a "Future Considerations" note about CBOR for constrained environments.

**References:**
- RFC 6838: Media Type Specifications and Registration
- RFC 7231: HTTP Semantics and Content
- RFC 8949: CBOR
- `docs/PROTOCOL_SPEC.md` Section 11

---

### M-2: IANA Registrations Not Drafted

**Severity:** MEDIUM
**Component:** `docs/draft-airlock-agent-trust-00.md` Section 11
**Affects:** Standards compliance, future IETF submission

**Finding:**

The IANA Considerations section (Section 11) states: "This document has no IANA actions at this stage." It then lists three future registration possibilities without providing draft registration templates:

1. Media type for Airlock protocol messages
2. `airlock` well-known URI suffix
3. Custom DID method identifier

For IETF publication, even Informational RFCs should provide complete IANA registration templates if they intend to register anything. Deferring all registrations signals to reviewers that the spec is premature.

**Recommendation:**

1. Draft a media type registration for `application/airlock+json` following RFC 6838 Section 4.2.
2. Draft a well-known URI registration for `/.well-known/airlock` following RFC 8615.
3. If a custom DID method is planned, draft a DID Method Specification following W3C DID Core Section 8.
4. Even if actual registration is deferred, having the templates demonstrates specification maturity.

**References:**
- RFC 6838: Media Type Specifications
- RFC 8615: Well-Known URIs
- W3C DID Core Section 8 (DID Method Specifications)
- `docs/draft-airlock-agent-trust-00.md` Section 11

---

### M-3: Timing Parameters Not Normatively Specified

**Severity:** MEDIUM
**Component:** `airlock/config.py`, `docs/PROTOCOL_SPEC.md`
**Affects:** Interoperability, security consistency across deployments

**Finding:**

The protocol defines several timing-critical parameters but treats them as deployment configuration rather than protocol constants:

| Parameter | Default | Spec Status |
|-----------|---------|-------------|
| Session TTL | 180s | Mentioned as default |
| Challenge TTL | 120s | Hardcoded in implementation, not in spec |
| Nonce replay TTL | 600s | Mentioned as default |
| Heartbeat TTL | 60s | Not in spec |
| Trust token TTL | 600s | Not in spec |
| PoW TTL | 120s | Not in spec |
| LLM timeout | 30s | Not in spec |
| Rate limit window | 60s | Not in spec |
| Decay half-life | 30-365d | Not in spec |

The challenge TTL of 120 seconds is hardcoded in `airlock/semantic/challenge.py:60` as `_CHALLENGE_TTL_SECONDS = 120` but is not mentioned in either spec document.

Without normative timing ranges, implementations may use wildly different values, leading to:
- A 5-second challenge TTL that no agent can meet
- A 24-hour nonce replay window that consumes unbounded memory
- A 1-second LLM timeout that always falls back to AMBIGUOUS

**Recommendation:**

1. Define RECOMMENDED ranges for each timing parameter in the spec.
2. Define MUST-level bounds: e.g., "Session TTL MUST be between 60 and 600 seconds."
3. Define the challenge TTL in the spec (currently undocumented).
4. Add timing parameters to the IETF draft's operational considerations.

**References:**
- `airlock/config.py:17-19` (session_ttl, heartbeat_ttl)
- `airlock/config.py:27-29` (nonce_replay_ttl, rate limits)
- `airlock/config.py:50` (trust_token_ttl)
- `airlock/config.py:128-130` (PoW TTL)
- `airlock/semantic/challenge.py:60` (challenge TTL -- hardcoded, not configurable)

---

### M-4: Error Code Registry Incomplete

**Severity:** MEDIUM
**Component:** `airlock/schemas/envelope.py`, `airlock/gateway/handlers.py`, `airlock/gateway/handshake_precheck.py`
**Affects:** Client error handling, protocol extensibility

**Finding:**

The `TransportNack` model has an `error_code: str` field, and the IETF draft (Section 5.3) lists five defined error codes: `INVALID_SIGNATURE`, `INVALID_SCHEMA`, `REPLAY`, `RATE_LIMITED`, `SENDER_MISMATCH`.

However, the implementation uses error codes that differ from the spec:

| Spec-defined | Implementation-used | Notes |
|-------------|-------------------|-------|
| INVALID_SIGNATURE | INVALID_SIGNATURE | Match |
| INVALID_SCHEMA | (not found in gateway code) | Defined but not used |
| REPLAY | REPLAY | Match |
| RATE_LIMITED | RATE_LIMIT | Inconsistent (missing "ED") |
| SENDER_MISMATCH | INVALID_ENVELOPE | Different name entirely |
| (not defined) | RATE_LIMIT | Used but spec says RATE_LIMITED |
| (not defined) | INVALID_ENVELOPE | Used but not in spec |

Additionally:
1. Error codes are `str` typed with no validation. Any string can be an error code.
2. There is no error code for version mismatch (see H-3).
3. There is no error code for PoW validation failure.
4. There is no registry or enum constraining valid error codes.
5. The spec references RFC 7807 (Problem Details) for error format but the implementation does not use RFC 7807 structure.

**Recommendation:**

1. Create an `ErrorCode` enum in `airlock/schemas/` that constrains valid error codes.
2. Align spec and implementation error code names (pick one: `RATE_LIMITED` or `RATE_LIMIT`).
3. Add missing error codes: `VERSION_UNSUPPORTED`, `POW_INVALID`, `POW_EXPIRED`, `CHALLENGE_EXPIRED`, `SESSION_EXPIRED`.
4. Either implement RFC 7807 format or remove the reference from the spec.
5. In the IETF draft, define error codes in an IANA-registerable format with a registration policy (e.g., "Specification Required").

**References:**
- `airlock/schemas/envelope.py:32` (error_code field)
- `airlock/gateway/handshake_precheck.py:58,69,87,91,103` (error codes used)
- `docs/draft-airlock-agent-trust-00.md` Section 5.3 (defined error codes)
- RFC 7807: Problem Details for HTTP APIs

---

### M-5: Privacy Mode Enforcement Gaps

**Severity:** MEDIUM
**Component:** `airlock/engine/orchestrator.py`, `airlock/schemas/handshake.py`
**Affects:** Data protection compliance, agent trust

**Finding:**

The protocol defines three privacy modes (`airlock/schemas/handshake.py:35-46`):

- `ANY`: Full pipeline, data may be stored in registry
- `LOCAL_ONLY`: No data leaves gateway instance, no registry sync
- `NO_CHALLENGE`: Skip semantic challenge entirely

The implementation partially enforces these in the orchestrator but has gaps:

1. **LOCAL_ONLY does not prevent all data leakage.** The orchestrator skips reputation writes for `local_only` sessions (lines 432-434, 519-521), but:
   - Audit trail entries are still written (line 67-71 in handlers.py, `_audit_bg()` fires regardless of privacy mode).
   - The session is still stored in the session manager and can be retrieved via `/session/{id}`.
   - Metrics counters still increment, leaking activity patterns.
   - If `AIRLOCK_DEFAULT_REGISTRY_URL` is configured, the resolve phase may still query the upstream registry.

2. **NO_CHALLENGE maps to DEFERRED, not VERIFIED.** When an agent requests `no_challenge`, the orchestrator sets the verdict to `DEFERRED` (line 809) and marks `_local_only=True` (line 811). This means the agent cannot reach VERIFIED status while preserving privacy, creating a perverse incentive against privacy.

3. **Privacy mode is not signed separately.** The privacy mode is inside the `HandshakeRequest` body which is signed, but it could be stripped or modified by middleware before signature verification. The spec should clarify that privacy mode MUST be verified as part of the signed payload.

4. **No privacy mode in challenge/response messages.** Once the handshake is accepted, subsequent messages (ChallengeResponse, feedback) do not carry the privacy mode. The orchestrator must look it up from session state, creating a temporal gap.

5. **The spec does not define privacy mode.** Neither `PROTOCOL_SPEC.md` nor the IETF draft mentions `privacy_mode` at all. It exists only in the implementation.

**Recommendation:**

1. Add `privacy_mode` to the protocol specification as a normative field.
2. For LOCAL_ONLY: suppress audit trail writes, suppress metrics labels that include DID, suppress upstream registry queries.
3. For NO_CHALLENGE: consider allowing VERIFIED at a lower trust tier (e.g., TIER_0 ceiling) instead of DEFERRED, to avoid penalizing privacy-conscious agents.
4. Carry `privacy_mode` in all subsequent protocol messages, not just the handshake.
5. Add conformance tests for privacy mode enforcement.

**References:**
- `airlock/schemas/handshake.py:35-46` (PrivacyMode enum)
- `airlock/engine/orchestrator.py:290,388-398,432-434,519-521,803-817` (enforcement points)
- `airlock/gateway/handlers.py:67-71` (_audit_bg -- not privacy-aware)
- `docs/PROTOCOL_SPEC.md` (no mention of privacy_mode)
- `docs/draft-airlock-agent-trust-00.md` (no mention of privacy_mode)

---

## Appendix A: Files Examined

| File | Purpose |
|------|---------|
| `airlock/crypto/signing.py` | Canonicalization and Ed25519 signing |
| `airlock/schemas/verdict.py` | Attestation and verdict models |
| `airlock/schemas/handshake.py` | Handshake request/response models, privacy mode |
| `airlock/schemas/envelope.py` | Message envelope, TransportAck/Nack |
| `airlock/schemas/trust_tier.py` | Trust tier definitions and ceilings |
| `airlock/config.py` | All configurable parameters |
| `airlock/semantic/challenge.py` | LLM challenge generation and evaluation |
| `airlock/semantic/fingerprint.py` | SimHash and SHA-256 answer fingerprinting |
| `airlock/engine/orchestrator.py` | State machine, privacy enforcement, attestation construction |
| `airlock/gateway/handlers.py` | HTTP handlers, audit trail |
| `airlock/gateway/handshake_precheck.py` | Transport-layer validation |
| `airlock/gateway/a2a_routes.py` | A2A protocol adapter routes |
| `docs/PROTOCOL_SPEC.md` | Protocol specification v0.1.0 |
| `docs/draft-airlock-agent-trust-00.md` | IETF Internet-Draft |

## Appendix B: Standards Referenced

| Standard | Relevance |
|----------|-----------|
| RFC 8785 | JSON Canonicalization Scheme -- claimed compliance, actual deviation (C-1) |
| RFC 8032 | Ed25519 signatures -- correctly implemented |
| RFC 3552 (BCP 72) | Security considerations guidelines -- incomplete coverage (C-3) |
| RFC 2026 | IETF standards process -- timeline implications (H-1) |
| RFC 7807 | Problem Details for HTTP APIs -- referenced but not implemented (M-4) |
| RFC 6838 | Media Type Specifications -- IANA registration needed (M-2) |
| RFC 8615 | Well-Known URIs -- registration needed (M-2) |
| RFC 5234 | ABNF -- should be used for type definitions (H-5) |
| RFC 8610 | CDDL -- alternative for type definitions (H-5) |
| RFC 7231 | HTTP Semantics -- /resolve should be GET (M-1) |
| RFC 8949 | CBOR -- future consideration for binary encoding (M-1) |
| W3C DID Core | DID identity -- correctly used |
| W3C VC Data Model 1.1 | Verifiable Credentials -- correctly referenced |
| BCP 78 | IETF copyright -- draft needs correction (H-1) |

## Appendix C: Priority Remediation Order

Recommended fix order based on impact and dependency:

1. **C-1** (Canonical JSON) -- Blocks all cross-language interoperability. Fix first.
2. **H-6** (Attestation signatures) -- Breaks the trust chain. Fix with C-1 since both touch signing.
3. **C-2** (LLM non-determinism) -- Restructure spec before adding more normative text.
4. **H-4** (Test vectors) -- Create after fixing C-1 so vectors use correct canonicalization.
5. **H-3** (Version negotiation) -- Add before the 0.2.0 release to avoid breaking changes later.
6. **M-4** (Error codes) -- Align spec and implementation before publishing vectors.
7. **C-3** (Security Considerations) -- Expand before IETF submission.
8. **H-5** (Python-isms) -- Requires spec rewrite; do alongside C-3.
9. **M-5** (Privacy enforcement) -- Add to spec and implementation.
10. **M-3** (Timing parameters) -- Add to spec.
11. **M-1** (Wire format) -- Add to spec.
12. **M-2** (IANA) -- Draft registrations.
13. **H-2** (Conformance suite) -- Build after vectors (H-4) are done.
14. **H-1** (IETF timeline) -- Ongoing planning adjustment.

---

*End of audit.*
