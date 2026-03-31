# Agentic Airlock Protocol Specification

**Version:** 0.1.0
**Status:** Draft
**Date:** April 2026
**Author:** Shivdeep Singh

---

## 1. Abstract

The Agentic Airlock protocol defines a decentralized, cryptographic trust verification framework for autonomous AI agents. As agent-to-agent communication protocols such as Google A2A and Anthropic MCP enable machines to interact without human mediation, no standard mechanism exists for verifying agent identity, authorization, or trustworthiness. Airlock addresses this gap through a five-phase verification pipeline -- Resolve, Handshake, Challenge, Verdict, Seal -- built on W3C Decentralized Identifiers, Ed25519 digital signatures, W3C Verifiable Credentials, a reputation scoring system with temporal decay, and optional LLM-backed semantic challenges. The protocol is designed to be transport-agnostic, computationally lightweight for trusted agents, and resistant to Sybil attacks and credential forgery.

---

## 2. Introduction

### 2.1 The Agent Trust Problem

AI agents are acquiring the ability to discover, communicate with, and delegate tasks to other agents autonomously. Protocols such as Google Agent-to-Agent (A2A) and Anthropic Model Context Protocol (MCP) provide the transport and capability-discovery layers, but they do not prescribe how an agent should verify the identity or trustworthiness of a counterparty. The current agent ecosystem is repeating the trajectory of early email: building communication infrastructure without authentication. Email required two decades to retrofit SPF, DKIM, and DMARC once spam reached crisis levels. Airlock is positioned to serve the role of "DMARC for AI agents" -- providing the authentication and reputation layer before the agent spam crisis arrives.

### 2.2 Relationship to Existing Standards

| Standard | Relationship |
|----------|-------------|
| W3C DID Core (did:key) | Airlock uses `did:key` as its identity method. Every agent and gateway possesses a DID derived from an Ed25519 public key. |
| W3C Verifiable Credentials Data Model 1.1 | Handshake requests carry a VC with an `Ed25519Signature2020` proof. The gateway validates issuer signature, expiry, and subject binding. |
| Google A2A | Airlock provides dedicated `/a2a/*` routes that accept A2A-formatted messages and agent cards. The `HandshakeRequest` schema is designed to wrap A2A message objects. |
| Anthropic MCP | An MCP stdio server (`airlock-mcp`) exposes gateway tools to MCP hosts, enabling LLM-driven agents to invoke Airlock verification natively. |
| RFC 8785 (JSON Canonicalization Scheme) | All signatures are computed over canonical JSON (sorted keys, no whitespace, UTF-8, `signature` field excluded). |
| RFC 7519 (JWT) | Trust tokens and session viewer tokens are HS256 JWTs conforming to RFC 7519. |

### 2.3 Design Goals

1. **Decentralized identity.** Agents self-generate Ed25519 key pairs and derive `did:key` identifiers without a central authority.
2. **Cryptographic verification at every hop.** Every protocol message (handshake, challenge, response, feedback, heartbeat) carries an Ed25519 signature over its canonical JSON form.
3. **Reputation-aware routing.** A scoring algorithm with temporal decay routes trusted agents through a fast path, unknown agents through a semantic challenge, and untrusted agents to immediate rejection.
4. **LLM-augmented challenge.** For agents in the unknown trust zone, the protocol issues a semantic challenge -- a capability-specific question evaluated by an LLM -- that is resistant to replay and impersonation.
5. **Transport-agnostic.** The protocol is defined at the message level. The reference implementation uses REST over HTTPS with optional WebSocket streaming, but the message formats are transport-independent.

---

## 3. Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in RFC 2119.

| Term | Definition |
|------|-----------|
| **Agent** | An autonomous software entity identified by a DID, capable of sending and receiving protocol messages. |
| **Gateway** | A server that implements the Airlock verification pipeline. The gateway receives handshake requests, runs the verification state machine, and issues verdicts and seals. A gateway possesses its own DID and signing key. |
| **DID (Decentralized Identifier)** | A globally unique identifier conforming to W3C DID Core. Airlock uses the `did:key` method exclusively, where the DID is deterministically derived from an Ed25519 public key. |
| **Verifiable Credential (VC)** | A tamper-evident credential conforming to the W3C VC Data Model. In Airlock, a VC asserts claims about an agent (e.g., capabilities, authorization) and is signed by an issuer's Ed25519 key. |
| **Trust Score** | A floating-point value in `[0.0, 1.0]` representing the gateway's confidence in an agent, maintained per agent DID with temporal decay. |
| **Handshake** | The initial protocol message in which an agent presents its identity, intent, credential, and signature to the gateway. |
| **Challenge** | A semantic question issued by the gateway to an agent whose trust score falls in the unknown zone. The challenge probes the agent's claimed capabilities. |
| **Verdict** | The gateway's decision after verification: `VERIFIED`, `REJECTED`, or `DEFERRED`. |
| **Seal** | A signed record containing the full verification trace, verdict, trust score, and attestation for a completed session. Provides an auditable receipt. |
| **Attestation** | A structured claim by the gateway asserting the outcome of a verification session, including which checks passed and the resulting trust score. |
| **Nonce** | A cryptographically random value (128-bit hex string) included in every message envelope to prevent replay attacks. |

---

## 4. Protocol Overview

### 4.1 The Five Phases

The Airlock protocol defines five sequential phases for verifying an agent's identity and trustworthiness:

```
Phase 1        Phase 2         Phase 3          Phase 4         Phase 5
RESOLVE   -->  HANDSHAKE  -->  CHALLENGE   -->  VERDICT   -->   SEAL
(discover)     (present)       (prove)          (decide)        (attest)
```

1. **Resolve.** The caller discovers the target agent's profile, capabilities, DID, and endpoint status through the gateway's agent registry.
2. **Handshake.** The initiating agent submits a signed `HandshakeRequest` containing its DID, intent, Verifiable Credential, and Ed25519 signature. The gateway validates schema, signature, and credential.
3. **Challenge.** If the agent's trust score falls in the unknown zone (0.15 < score < 0.75), the gateway issues a `ChallengeRequest` -- a semantic question about the agent's capabilities. Agents with high trust skip this phase entirely (fast-path). Agents with very low trust are rejected immediately (blacklist).
4. **Verdict.** The gateway evaluates the challenge response (or applies the fast-path/blacklist decision) and issues a `TrustVerdict`: `VERIFIED`, `REJECTED`, or `DEFERRED`.
5. **Seal.** Both parties receive a signed `SessionSeal` containing the full verification trace, attestation, and updated trust score.

### 4.2 Verification Flow

```
                        Agent A                    Gateway                    Agent B
                          |                           |                          |
                          |   POST /resolve           |                          |
                          |   {target_did}            |                          |
                          | ========================> |                          |
                          |   AgentProfile            |                          |
                          | <======================== |                          |
                          |                           |                          |
                          |   POST /handshake         |                          |
                          |   {HandshakeRequest}      |                          |
                          | ========================> |                          |
                          |                           |                          |
                          |   TransportAck/Nack       |                          |
                          | <======================== |                          |
                          |                           |                          |
                          |      [Gateway runs verification pipeline]            |
                          |      validate_schema --> verify_signature -->        |
                          |      validate_vc --> check_reputation                |
                          |                           |                          |
                          |                           |                          |
            .-------------+-----------.  .------------+-----------.              |
            | FAST PATH (score>=0.75) |  | CHALLENGE (0.15-0.75)  |              |
            | Skip to verdict         |  |                        |              |
            | VERIFIED immediately    |  | ChallengeRequest       |              |
            '-------------+-----------'  | <===================== |              |
                          |              |                        |              |
                          |              | ChallengeResponse      |              |
                          |              | =====================> |              |
                          |              | LLM evaluates          |              |
                          |              '------------+-----------'              |
                          |                           |                          |
            .-------------+-----------.               |                          |
            | BLACKLIST (score<=0.15) |               |                          |
            | REJECTED immediately    |               |                          |
            '-------------+-----------'               |                          |
                          |                           |                          |
                          |   TrustVerdict            |                          |
                          | <======================== |                          |
                          |   + AirlockAttestation    |                          |
                          |   + trust_token (JWT)     |                          |
                          |                           |                          |
                          |   SessionSeal             |   SessionSeal            |
                          | <======================== | ========================>|
                          |                           |                          |
```

### 4.3 Routing Paths

| Path | Condition | Behavior |
|------|-----------|----------|
| **Fast-path** | Trust score >= 0.75 | Phases 3-4 are skipped. The gateway issues `VERIFIED` immediately after Phase 2 completes. |
| **Challenge path** | 0.15 < Trust score < 0.75 | Full pipeline. An LLM-generated semantic challenge is issued and evaluated. |
| **Blacklist path** | Trust score <= 0.15 | The agent is rejected immediately after reputation check. No challenge is issued. |

---

## 5. Identity Layer

### 5.1 DID:key Method

Airlock uses the `did:key` method as defined by the W3C DID specification. Each agent identity is derived deterministically from an Ed25519 public key. No external DID registry is required.

**DID derivation procedure:**

1. Generate or load a 32-byte Ed25519 seed.
2. Derive the Ed25519 signing key and verify (public) key from the seed.
3. Prepend the multicodec prefix for Ed25519 public keys (`0xed01`) to the 32-byte raw public key, yielding a 34-byte payload.
4. Encode the payload using base58btc (Bitcoin alphabet).
5. Prepend the multibase prefix `z` (indicating base58btc encoding).
6. The DID is formed as: `did:key:z<base58btc-encoded-payload>`.

**Example:**

```
Seed (hex):    a1b2c3...  (32 bytes)
Public key:    <32-byte Ed25519 verify key>
Multicodec:    0xed01 + <32-byte public key> = 34 bytes
Base58btc:     z6Mkf5rGMoatrSj1f4CyvuHBeXJELe9RPdzo2PKGNCKVtZxP
DID:           did:key:z6Mkf5rGMoatrSj1f4CyvuHBeXJELe9RPdzo2PKGNCKVtZxP
```

### 5.2 Key Generation

Agents MUST generate their Ed25519 key pair using one of the following methods:

- **Random generation.** A cryptographically secure random 32-byte seed is used to derive the key pair.
- **Deterministic from seed.** A known 32-byte seed (provided as 64 hex characters via `AIRLOCK_AGENT_SEED_HEX` or `AIRLOCK_GATEWAY_SEED_HEX`) is used. The gateway MUST use a deterministic seed in production to ensure a stable DID across restarts.

Agents SHOULD persist their seed to maintain a stable identity. The reference implementation stores seeds at `.airlock/agent_seed.hex` by default.

### 5.3 DID Resolution

To extract the Ed25519 public key from a `did:key` string, a verifier MUST:

1. Strip the `did:key:` prefix.
2. Verify the multibase prefix is `z` (base58btc).
3. Base58btc-decode the remainder.
4. Verify the first two bytes are the Ed25519 multicodec prefix (`0xed01`).
5. Extract bytes 2-33 as the 32-byte raw Ed25519 public key.

Reference implementation: `airlock/crypto/keys.py :: resolve_public_key()`.

### 5.4 Verifiable Credential Format

Agents MUST present a W3C Verifiable Credential in their `HandshakeRequest`. The credential conforms to the W3C VC Data Model 1.1 with the following structure:

```json
{
  "@context": ["https://www.w3.org/2018/credentials/v1"],
  "id": "<issuer-did>#<uuid>",
  "type": ["VerifiableCredential", "<credential-type>"],
  "issuer": "<issuer-did:key>",
  "issuanceDate": "<ISO 8601 datetime>",
  "expirationDate": "<ISO 8601 datetime>",
  "credentialSubject": {
    "id": "<subject-did:key>",
    ...additional claims...
  },
  "proof": {
    "type": "Ed25519Signature2020",
    "created": "<ISO 8601 datetime>",
    "verificationMethod": "<issuer-did:key>",
    "proofPurpose": "assertionMethod",
    "proofValue": "<base64-encoded Ed25519 signature>"
  }
}
```

**Credential types** defined by the protocol:

| Type | Purpose |
|------|---------|
| `AgentAuthorization` | Authorizes the agent to act on behalf of an entity. |
| `CapabilityGrant` | Grants the agent specific capabilities. |
| `IdentityAssertion` | Asserts identity claims about the agent. |

The `proof.proofValue` is computed by signing the canonical JSON form of the credential (excluding the `proof` field) with the issuer's Ed25519 private key, then base64-encoding the 64-byte signature.

Reference implementation: `airlock/crypto/vc.py`.

---

## 6. Message Formats

All protocol messages use JSON encoding. Timestamps MUST be ISO 8601 format with UTC timezone. All messages that carry a `signature` field MUST have that signature computed over the canonical JSON form of the message with the `signature` field excluded.

### 6.1 MessageEnvelope

Every protocol message MUST include a `MessageEnvelope` as the `envelope` field:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `protocol_version` | string | REQUIRED | Protocol version. Current: `"0.1.0"`. |
| `timestamp` | datetime | REQUIRED | ISO 8601 UTC timestamp of message creation. |
| `sender_did` | string | REQUIRED | The `did:key` of the message sender. |
| `nonce` | string | REQUIRED | 128-bit cryptographically random hex string (32 hex characters). MUST be unique per message. |

### 6.2 HandshakeRequest

Sent by the initiating agent to the gateway to begin verification.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `envelope` | MessageEnvelope | REQUIRED | Message metadata. `envelope.sender_did` MUST equal `initiator.did`. |
| `session_id` | string | REQUIRED | Client-generated unique session identifier. |
| `initiator` | AgentDID | REQUIRED | The agent's DID and multibase-encoded public key. |
| `intent` | HandshakeIntent | REQUIRED | Describes the requested action. |
| `credential` | VerifiableCredential | REQUIRED | The agent's W3C VC. |
| `signature` | SignatureEnvelope | OPTIONAL | Ed25519 signature over the canonical form of this message. |

**AgentDID:**

| Field | Type | Description |
|-------|------|-------------|
| `did` | string | `did:key:z...` identifier. MUST use the `did:key` method. |
| `public_key_multibase` | string | Multibase-encoded Ed25519 public key (`z` prefix + base58btc). |

**HandshakeIntent:**

| Field | Type | Description |
|-------|------|-------------|
| `action` | string | The action the agent wishes to perform (e.g., `"delegate_task"`). |
| `description` | string | Human-readable description of the intent. |
| `target_did` | string | The DID of the target agent. |

**SignatureEnvelope:**

| Field | Type | Description |
|-------|------|-------------|
| `algorithm` | string | MUST be `"Ed25519"`. |
| `value` | string | Base64-encoded 64-byte Ed25519 signature. |
| `signed_at` | datetime | ISO 8601 UTC timestamp of when the signature was created. |

### 6.3 TransportAck / TransportNack

Returned synchronously by the gateway upon receiving a `HandshakeRequest`.

**TransportAck** (handshake accepted for processing):

| Field | Type | Description |
|-------|------|-------------|
| `status` | string | Literal `"ACCEPTED"`. |
| `session_id` | string | The session identifier. |
| `timestamp` | datetime | Server timestamp. |
| `envelope` | MessageEnvelope | Gateway envelope. |
| `session_view_token` | string (optional) | Short-lived JWT for polling session state and WebSocket subscription. |

**TransportNack** (handshake rejected at transport level):

| Field | Type | Description |
|-------|------|-------------|
| `status` | string | Literal `"REJECTED"`. |
| `session_id` | string (optional) | The session identifier, if one was assigned. |
| `reason` | string | Human-readable rejection reason. |
| `error_code` | string | Machine-readable error code (e.g., `"INVALID_SIGNATURE"`, `"REPLAY"`, `"RATE_LIMITED"`). |
| `timestamp` | datetime | Server timestamp. |
| `envelope` | MessageEnvelope | Gateway envelope. |

### 6.4 ChallengeRequest

Issued by the gateway when an agent's trust score is in the challenge zone.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `envelope` | MessageEnvelope | REQUIRED | Gateway envelope. |
| `session_id` | string | REQUIRED | The verification session identifier. |
| `challenge_id` | string | REQUIRED | Unique identifier for this challenge. |
| `challenge_type` | string | REQUIRED | `"semantic"` or `"capability_proof"`. |
| `question` | string | REQUIRED | The challenge question (LLM-generated). |
| `context` | string | REQUIRED | Context about what capabilities are being probed. |
| `expires_at` | datetime | REQUIRED | Deadline for the response. |
| `signature` | SignatureEnvelope | OPTIONAL | Gateway signature. |

### 6.5 ChallengeResponse

Submitted by the challenged agent.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `envelope` | MessageEnvelope | REQUIRED | Agent envelope. |
| `session_id` | string | REQUIRED | Must match the challenge's session_id. |
| `challenge_id` | string | REQUIRED | Must match the challenge's challenge_id. |
| `answer` | string | REQUIRED | The agent's response to the challenge question. |
| `confidence` | float | REQUIRED | Agent-reported confidence in its answer. Range: `[0.0, 1.0]`. |
| `signature` | SignatureEnvelope | OPTIONAL | Agent signature. |

### 6.6 SessionSeal

The terminal message for a completed verification session.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `envelope` | MessageEnvelope | REQUIRED | Gateway envelope. |
| `session_id` | string | REQUIRED | The verification session identifier. |
| `verdict` | TrustVerdict | REQUIRED | `"VERIFIED"`, `"REJECTED"`, or `"DEFERRED"`. |
| `checks_passed` | list[CheckResult] | REQUIRED | Ordered list of verification checks and their results. |
| `trust_score` | float | REQUIRED | The agent's trust score after this session. |
| `sealed_at` | datetime | REQUIRED | Timestamp of seal issuance. |
| `signature` | SignatureEnvelope | OPTIONAL | Gateway signature over the seal. |

---

## 7. Verification Pipeline

The verification pipeline is implemented as a LangGraph state machine with eight nodes and conditional routing edges. The pipeline runs asynchronously within the gateway.

Reference implementation: `airlock/engine/orchestrator.py`.

### 7.1 Phase 1: Schema Validation

**Node:** `validate_schema`

The gateway MUST validate that the incoming `HandshakeRequest` conforms to the protocol schema. In the reference implementation, Pydantic model parsing provides this validation at deserialization time.

**Check recorded:** `VerificationCheck.SCHEMA`

**Failure behavior:** If schema validation fails, the handshake is rejected at the transport layer with a `TransportNack` (error code `"INVALID_SCHEMA"`). The pipeline does not execute.

### 7.2 Phase 2: Signature Verification

**Node:** `verify_signature`

The gateway MUST verify the Ed25519 signature on the `HandshakeRequest`:

1. Extract the signer's DID from `initiator.did`.
2. Resolve the Ed25519 public key from the DID using the `did:key` resolution procedure (Section 5.3).
3. Reconstruct the canonical JSON form of the `HandshakeRequest` by serializing the model to JSON, removing the `signature` field, sorting keys, removing whitespace, and encoding as UTF-8.
4. Verify the base64-decoded `signature.value` against the canonical bytes using the resolved Ed25519 public key.

**Envelope alignment rule:** The gateway MUST verify that `envelope.sender_did` equals `initiator.did`. A mismatch results in a `TransportNack`.

**Check recorded:** `VerificationCheck.SIGNATURE`

**Failure behavior:** If signature verification fails, the pipeline sets `verdict = REJECTED`, marks the session as `FAILED`, and routes to the `failed` terminal node.

Reference implementation: `airlock/crypto/signing.py :: verify_model()`.

### 7.3 Phase 3: Verifiable Credential Validation

**Node:** `validate_vc`

The gateway MUST validate the Verifiable Credential attached to the handshake:

1. **Expiry check.** The VC's `expirationDate` MUST be in the future.
2. **Proof presence.** The VC MUST contain a `proof` field.
3. **Subject binding.** If the gateway enforces subject binding (RECOMMENDED), `credentialSubject.id` MUST equal `initiator.did`.
4. **Issuer signature.** Resolve the issuer's Ed25519 public key from `vc.issuer` (a `did:key`) and verify `proof.proofValue` against the canonical JSON of the VC (excluding the `proof` field).
5. **Issuer allowlist.** If `AIRLOCK_VC_ISSUER_ALLOWLIST` is configured, the VC's `issuer` DID MUST appear in the allowlist.

**Check recorded:** `VerificationCheck.CREDENTIAL`

**Failure behavior:** If any validation step fails, the pipeline sets `verdict = REJECTED`, marks the session as `FAILED`, and routes to the `failed` terminal node.

Reference implementation: `airlock/crypto/vc.py :: validate_credential()`.

### 7.4 Phase 4: Reputation Check

**Node:** `check_reputation`

The gateway MUST look up the initiator's trust score and determine the routing decision:

1. Retrieve the `TrustScore` record for `initiator_did` from the reputation store. If no record exists, use the default initial score of `0.5`.
2. Apply half-life decay (Section 8.3) to account for elapsed time since the last interaction.
3. Evaluate the routing decision based on the decayed score (Section 4.3):
   - Score >= 0.75: route to `fast_path` (skip challenge, issue `VERIFIED`).
   - Score <= 0.15: route to `blacklist` (issue `REJECTED` immediately).
   - Otherwise: route to `challenge`.

**Check recorded:** `VerificationCheck.REPUTATION`

**Failure behavior (blacklist):** The pipeline sets `verdict = REJECTED`, records an error ("Agent is blacklisted"), and routes to the `failed` terminal node.

Reference implementation: `airlock/reputation/scoring.py :: routing_decision()`.

### 7.5 Phase 5a: Semantic Challenge (Challenge Path)

**Node:** `semantic_challenge`

When the routing decision is `challenge`, the gateway MUST issue a semantic challenge:

1. Look up the agent's registered capabilities from the agent registry.
2. Generate an LLM-backed challenge question that probes the agent's stated capabilities. The question SHOULD be specific enough that an unauthorized agent cannot produce a plausible answer.
3. Send the `ChallengeRequest` to the agent (via callback URL, session polling, or WebSocket).
4. The pipeline suspends and awaits the agent's `ChallengeResponse`.

Upon receiving a `ChallengeResponse`:

5. Evaluate the response using an LLM, producing one of three outcomes: `PASS`, `FAIL`, or `AMBIGUOUS`.
6. Map the outcome to a `TrustVerdict`: `PASS` -> `VERIFIED`, `FAIL` -> `REJECTED`, `AMBIGUOUS` -> `DEFERRED`.
7. Update the agent's reputation score based on the verdict.

**Check recorded:** `VerificationCheck.SEMANTIC`

Reference implementation: `airlock/semantic/challenge.py`.

### 7.5b: Fast-Path (Score >= 0.75)

When the routing decision is `fast_path`, the pipeline skips the challenge node entirely and routes directly to `issue_verdict` with `verdict = VERIFIED`. The agent's reputation is updated with a `VERIFIED` delta.

### 7.5c: Blacklist (Score <= 0.15)

When the routing decision is `blacklist`, the pipeline routes to the `failed` node with `verdict = REJECTED`. No challenge is issued, and no reputation update occurs (the agent is already at minimum trust).

### 7.6 State Machine Transitions

```
  validate_schema
        |
        v
  verify_signature
        |
    [sig valid?]
    /          \
  YES           NO --> failed --> END
    |
    v
  validate_vc
        |
    [vc valid?]
    /          \
  YES           NO --> failed --> END
    |
    v
  check_reputation
        |
    [routing?]
    /     |      \
  fast  challenge  blacklist
    |     |            |
    v     v            v
  issue_verdict  semantic_challenge  failed --> END
    |                  |
    v                  v
  seal_session        END
    |            (suspends; resumes
    v             on ChallengeResponse)
   END
```

---

## 8. Trust Scoring

The trust scoring system maintains a per-agent reputation score that evolves over time based on verification outcomes and temporal decay.

Reference implementation: `airlock/reputation/scoring.py`.

### 8.1 Initial Score

New agents that have no prior interaction history start with a neutral score of **0.50**. This positions them in the challenge zone, requiring them to pass at least one semantic challenge before earning fast-path trust.

### 8.2 Verdict Deltas

When a verification session concludes, the agent's score is updated based on the verdict:

| Verdict | Delta Formula | Rationale |
|---------|--------------|-----------|
| `VERIFIED` | `+0.05 / (1 + interaction_count * 0.1)` | Positive signal with diminishing returns. Prevents trust inflation from volume alone. |
| `REJECTED` | `-0.15` (fixed) | Strong negative signal. A single rejection significantly impacts trust. |
| `DEFERRED` | `-0.02` (fixed) | Mild negative signal. Ambiguity is treated as a weak indicator of untrustworthiness. |

The asymmetric delta design reflects a security-first philosophy: trust is earned slowly and lost quickly.

### 8.3 Half-Life Decay

Agent scores decay toward the neutral point (0.50) over time using radioactive decay:

```
decayed_score = 0.50 + (current_score - 0.50) * 2^(-elapsed_days / 30)
```

**Parameters:**
- Half-life: **30 days**
- Neutral point: **0.50**

**Properties:**
- A trusted agent (score 0.90) that stops interacting decays to approximately 0.70 after 30 days, 0.60 after 60 days, and approaches 0.50 asymptotically.
- A distrusted agent (score 0.10) similarly drifts back toward 0.50 over time.
- Decay is applied on read (at the time of reputation lookup), not as a background process.

This design ensures that trust is time-sensitive: an agent must maintain ongoing positive interactions to retain fast-path status.

### 8.4 Routing Thresholds

| Threshold | Value | Routing Decision |
|-----------|-------|-----------------|
| `THRESHOLD_HIGH` | 0.75 | Score >= 0.75: fast-path to `VERIFIED`. |
| `THRESHOLD_BLACKLIST` | 0.15 | Score <= 0.15: immediate `REJECTED`. |
| Challenge zone | (0.15, 0.75) | Semantic challenge required. |

### 8.5 Score Bounds

Scores are clamped to the range `[0.0, 1.0]`. All arithmetic operations MUST clamp the result before persistence.

---

## 9. Trust Tokens

Upon a `VERIFIED` verdict, the gateway MAY issue a short-lived trust token as a JWT (RFC 7519). This token can be presented by the verified agent to downstream services as proof of recent Airlock verification.

### 9.1 Token Format

Trust tokens are signed using HS256 (HMAC-SHA256) with a gateway-configured secret (`AIRLOCK_TRUST_TOKEN_SECRET`).

**JWT Claims:**

| Claim | Type | Description |
|-------|------|-------------|
| `sub` | string | The verified agent's DID (`did:key:z...`). |
| `sid` | string | The verification session ID. |
| `ver` | string | The verdict. Always `"VERIFIED"` for trust tokens. |
| `ts` | float | The agent's trust score at time of issuance. |
| `iss` | string | The gateway's DID (`did:key:z...`). |
| `aud` | string | Token audience. Value: `"airlock-agent"`. |
| `iat` | number | Issued-at timestamp (Unix epoch seconds). |
| `exp` | number | Expiration timestamp (Unix epoch seconds). |

### 9.2 Token Lifetime

The token TTL is configured via `AIRLOCK_TRUST_TOKEN_TTL_SECONDS`:
- Default: **600 seconds** (10 minutes)
- Minimum: 60 seconds
- Maximum: 86,400 seconds (24 hours)

### 9.3 Token Introspection

The gateway exposes a `POST /token/introspect` endpoint that validates a trust token and returns its claims. This endpoint requires the `AIRLOCK_SERVICE_TOKEN` bearer when configured.

### 9.4 Session Viewer Tokens

Separately from trust tokens, the gateway MAY issue session viewer tokens (`session_view_token`) in the `TransportAck` response. These are HS256 JWTs that grant read access to a single verification session via `GET /session/{id}` and `WS /ws/session/{id}`. They use a distinct audience (`"airlock-session-view"`) and are signed with `AIRLOCK_SESSION_VIEW_SECRET`.

Reference implementation: `airlock/trust_jwt.py`.

---

## 10. Security Considerations

### 10.1 Nonce Replay Protection

Every `MessageEnvelope` contains a cryptographically random nonce (128-bit, hex-encoded). The gateway MUST maintain a nonce replay cache keyed by `(sender_did, nonce)`:

- If a `(sender_did, nonce)` pair has been seen within the TTL window (`AIRLOCK_NONCE_REPLAY_TTL_SECONDS`, default 600 seconds), the message MUST be rejected with a `TransportNack` (error code `"REPLAY"`).
- In multi-replica deployments, the nonce cache SHOULD be backed by shared storage (e.g., Redis via `AIRLOCK_REDIS_URL`) to prevent cross-replica replay.
- Nonce entries SHOULD be evicted after the TTL expires to bound memory usage.

### 10.2 Rate Limiting

The gateway MUST enforce rate limits to prevent abuse:

| Scope | Default Limit | Configuration |
|-------|---------------|---------------|
| Per-IP, all endpoints | 120 requests/minute | `AIRLOCK_RATE_LIMIT_PER_IP_PER_MINUTE` |
| Per-DID, `/handshake` | 30 requests/minute | `AIRLOCK_RATE_LIMIT_HANDSHAKE_PER_DID_PER_MINUTE` |
| Per-IP, `/register` | Hourly cap | `AIRLOCK_REGISTER_MAX_PER_IP_PER_HOUR` |

In multi-replica deployments, rate limit counters SHOULD be shared via Redis.

### 10.3 Signature Verification Before Processing

The gateway MUST verify the Ed25519 signature on a `HandshakeRequest` at the transport layer, before any event is published to the internal event bus. Invalid signatures MUST result in an immediate `TransportNack` without further processing. This prevents unsigned or forged messages from consuming gateway resources.

### 10.4 VC Issuer Allowlist

In production deployments, the gateway SHOULD configure `AIRLOCK_VC_ISSUER_ALLOWLIST` with a comma-separated list of trusted issuer DIDs. When configured, only VCs signed by an issuer on the allowlist will be accepted. This prevents agents from self-issuing credentials.

### 10.5 Subject Binding

The gateway SHOULD verify that `credentialSubject.id` in the presented VC matches the `initiator.did` in the handshake. This prevents credential theft -- an agent cannot present another agent's VC.

### 10.6 Sybil Protection

To prevent Sybil attacks (mass registration of fake agent identities), the gateway enforces per-IP registration caps:

- `AIRLOCK_REGISTER_MAX_PER_IP_PER_HOUR`: Maximum agent registrations per IP address per rolling hour (0 = unlimited).
- The per-minute rate limit on `/register` provides a second layer of defense.

### 10.7 Canonical JSON Signing

All signatures MUST be computed over a canonical JSON representation of the message:

1. Serialize the message to a JSON dictionary.
2. Remove the `signature` field if present.
3. Sort all keys recursively.
4. Use compact separators (no whitespace): `(",", ":")`.
5. Encode as UTF-8 bytes.
6. Sign the resulting byte string with the sender's Ed25519 private key.

This procedure follows principles from RFC 8785 (JSON Canonicalization Scheme).

Reference implementation: `airlock/crypto/signing.py :: canonicalize()`.

### 10.8 Session TTL

Verification sessions expire after `AIRLOCK_SESSION_TTL` seconds (default: 180). Expired sessions MUST NOT accept challenge responses and SHOULD be cleaned up.

---

## 11. Transport

### 11.1 REST API over HTTPS

The primary transport is a REST API served over HTTPS. In production deployments, the gateway MUST be fronted by TLS termination.

**Core endpoints:**

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/resolve` | Look up an agent by DID. Returns `AgentProfile`. |
| `POST` | `/handshake` | Submit a signed `HandshakeRequest`. Returns `TransportAck` or `TransportNack`. |
| `POST` | `/challenge-response` | Submit a `ChallengeResponse` to a pending challenge. |
| `POST` | `/register` | Register an `AgentProfile` with the gateway. |
| `POST` | `/feedback` | Submit a signed `SignedFeedbackReport` for reputation adjustment. |
| `POST` | `/heartbeat` | Signed heartbeat for liveness. |
| `GET` | `/reputation/{did}` | Retrieve the current trust score for an agent DID. |
| `GET` | `/session/{session_id}` | Poll session state. Requires `session_view_token` or service token in production. |
| `POST` | `/token/introspect` | Validate a trust JWT. Requires service token in production. |
| `GET` | `/health` | Gateway health with subsystem status. |
| `GET` | `/live` | Process liveness probe. |
| `GET` | `/ready` | Readiness probe (HTTP 503 if not ready). |
| `GET` | `/metrics` | Prometheus-format metrics. Requires service token in production. |

**Error format:** The gateway SHOULD return errors conforming to RFC 7807 (Problem Details for HTTP APIs).

### 11.2 A2A-Native Routes

For interoperability with the Google A2A protocol, the gateway exposes a parallel set of routes under `/a2a/*`:

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/a2a/.well-known/agent.json` | A2A agent card (discovery). |
| `POST` | `/a2a/register` | Register an agent (A2A format). |
| `POST` | `/a2a/verify` | Submit a handshake for verification (A2A format). |

These routes accept A2A-formatted messages and translate them to the internal protocol representation via an adapter layer.

Reference implementation: `airlock/gateway/a2a_routes.py`.

### 11.3 WebSocket Session Streaming

The gateway supports real-time session state updates via WebSocket:

| Protocol | Path | Description |
|----------|------|-------------|
| `WS` | `/ws/session/{session_id}` | Push session updates as JSON frames. |

Authentication: The WebSocket connection requires either an `Authorization: Bearer <session_view_token>` header or a `?token=<session_view_token>` query parameter.

### 11.4 Remote Registry Delegation

When configured with `AIRLOCK_DEFAULT_REGISTRY_URL`, a gateway that cannot resolve an agent DID locally MUST delegate the lookup to the upstream registry via `POST {base}/resolve`. The response includes a `registry_source` field indicating whether the result came from `"local"` or `"remote"` resolution.

---

## 12. References

| Reference | Description |
|-----------|-------------|
| W3C DID Core 1.0 | https://www.w3.org/TR/did-core/ |
| W3C did:key Method | https://w3c-ccg.github.io/did-method-key/ |
| W3C VC Data Model 1.1 | https://www.w3.org/TR/vc-data-model/ |
| Ed25519 (RFC 8032) | https://datatracker.ietf.org/doc/html/rfc8032 |
| RFC 7519 (JWT) | https://datatracker.ietf.org/doc/html/rfc7519 |
| RFC 8785 (JCS) | https://datatracker.ietf.org/doc/html/rfc8785 |
| RFC 2119 (Key Words) | https://datatracker.ietf.org/doc/html/rfc2119 |
| RFC 7807 (Problem Details) | https://datatracker.ietf.org/doc/html/rfc7807 |
| Google A2A Protocol | https://google.github.io/A2A/ |
| Anthropic MCP | https://modelcontextprotocol.io/ |
| Multibase (IETF Draft) | https://datatracker.ietf.org/doc/html/draft-multiformats-multibase |
| Multicodec | https://github.com/multiformats/multicodec |

---

## Appendix A: Configuration Reference

The following environment variables control gateway behavior. All use the `AIRLOCK_` prefix.

| Variable | Default | Description |
|----------|---------|-------------|
| `AIRLOCK_ENV` | `development` | `development` or `production`. Production enforces mandatory secrets. |
| `AIRLOCK_GATEWAY_SEED_HEX` | (demo seed) | 32-byte Ed25519 seed as 64 hex chars. REQUIRED in production. |
| `AIRLOCK_SERVICE_TOKEN` | (none) | Bearer token for `/metrics` and `/token/introspect`. REQUIRED in production. |
| `AIRLOCK_SESSION_VIEW_SECRET` | (none) | HS256 secret for session viewer JWTs. REQUIRED in production. |
| `AIRLOCK_TRUST_TOKEN_SECRET` | (none) | HS256 secret for trust JWTs. Omit to disable trust token minting. |
| `AIRLOCK_TRUST_TOKEN_TTL_SECONDS` | `600` | Trust token lifetime. Range: [60, 86400]. |
| `AIRLOCK_VC_ISSUER_ALLOWLIST` | (empty) | Comma-separated issuer DIDs. Empty = accept any issuer. |
| `AIRLOCK_NONCE_REPLAY_TTL_SECONDS` | `600` | How long nonces are remembered. |
| `AIRLOCK_RATE_LIMIT_PER_IP_PER_MINUTE` | `120` | Per-IP request rate limit. |
| `AIRLOCK_RATE_LIMIT_HANDSHAKE_PER_DID_PER_MINUTE` | `30` | Per-DID handshake rate limit. |
| `AIRLOCK_REGISTER_MAX_PER_IP_PER_HOUR` | `0` | Registration cap per IP per hour. 0 = unlimited. |
| `AIRLOCK_CORS_ORIGINS` | (none) | Comma-separated allowed origins, or `*`. |
| `AIRLOCK_REDIS_URL` | (none) | Redis URL for shared replay/rate limit state. |
| `AIRLOCK_DEFAULT_REGISTRY_URL` | (none) | Upstream gateway URL for federated resolution. |
| `AIRLOCK_SESSION_TTL` | `180` | Session expiry in seconds. |
| `AIRLOCK_LITELLM_MODEL` | `ollama/llama3` | LLM model for semantic challenges. |
| `AIRLOCK_LITELLM_API_BASE` | `http://localhost:11434` | LLM API endpoint. |

---

## Appendix B: Verification Check Types

| Check | Description |
|-------|-------------|
| `schema` | Pydantic schema validation of the incoming message. |
| `signature` | Ed25519 signature verification on the handshake request. |
| `credential` | W3C Verifiable Credential validation (expiry, proof, subject binding, issuer allowlist). |
| `reputation` | Trust score lookup and routing decision. |
| `semantic` | LLM-evaluated challenge-response assessment. |
| `liveness` | Agent liveness/heartbeat check (reserved for future use). |

---

## Appendix C: Session State Machine

A verification session transitions through the following states:

```
initiated --> resolving --> resolved --> handshake_received
                                              |
                                              v
                                       signature_verified
                                              |
                                              v
                                       credential_validated
                                              |
                                       [routing decision]
                                        /      |       \
                                       v       v        v
                              verdict_issued  challenge_issued  failed
                                   |              |
                                   v              v
                                sealed    challenge_responded
                                              |
                                              v
                                        verdict_issued
                                              |
                                              v
                                           sealed
```

Terminal states: `sealed`, `failed`.

---

*This document is a living specification. As the protocol evolves, this document will be updated to reflect changes in message formats, scoring parameters, and security requirements.*

*Copyright 2026 Shivdeep Singh. Licensed under Apache License 2.0.*
