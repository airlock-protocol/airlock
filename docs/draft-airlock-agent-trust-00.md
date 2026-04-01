




Network Working Group                                          S. Singh
Internet-Draft                                         The Airlock Project
Intended status: Informational                              1 April 2026
Expires: 3 October 2026


         The Airlock Agent Trust Verification Protocol
              draft-airlock-agent-trust-00

Abstract

   This document specifies the Airlock Agent Trust Verification
   Protocol, a decentralized framework for verifying the identity,
   authorization, and trustworthiness of autonomous AI agents.  The
   protocol defines a five-phase verification pipeline -- Resolve,
   Handshake, Challenge, Verdict, Seal -- built on W3C Decentralized
   Identifiers (DIDs), Ed25519 digital signatures [RFC8032], W3C
   Verifiable Credentials, a reputation scoring system with temporal
   decay, and optional LLM-backed semantic challenges.  The protocol
   is transport-agnostic and designed to integrate with existing
   agent communication frameworks such as Google Agent-to-Agent (A2A)
   and Anthropic Model Context Protocol (MCP).

Status of This Memo

   This Internet-Draft is submitted in full conformance with the
   provisions of BCP 78 and BCP 79.

   Internet-Drafts are working documents of the Internet Engineering
   Task Force (IETF).  Note that other groups may also distribute
   working documents as Internet-Drafts.

   Internet-Drafts are draft documents valid for a maximum of six
   months and may be updated, replaced, or obsoleted by other
   documents at any time.  It is inappropriate to use Internet-Drafts
   as reference material or to cite them other than as "work in
   progress."

   This Internet-Draft will expire on 3 October 2026.

Copyright Notice

   Copyright (c) 2026 Shivdeep Singh.  All rights reserved.

   This document is subject to BCP 78 and the IETF Trust's Legal
   Provisions Relating to IETF Documents
   (https://trustee.ietf.org/license-info) in effect on the date of
   publication of this document.

Table of Contents

   1.  Introduction  . . . . . . . . . . . . . . . . . . . . . .   2
   2.  Terminology . . . . . . . . . . . . . . . . . . . . . . .   3
   3.  Protocol Overview . . . . . . . . . . . . . . . . . . . .   4
   4.  Agent Identity  . . . . . . . . . . . . . . . . . . . . .   6
   5.  Message Formats . . . . . . . . . . . . . . . . . . . . .   8
   6.  Verification Pipeline . . . . . . . . . . . . . . . . . .  12
   7.  Trust Scoring Model . . . . . . . . . . . . . . . . . . .  16
   8.  Delegation  . . . . . . . . . . . . . . . . . . . . . . .  18
   9.  Revocation  . . . . . . . . . . . . . . . . . . . . . . .  19
  10.  Security Considerations . . . . . . . . . . . . . . . . .  20
  11.  IANA Considerations . . . . . . . . . . . . . . . . . . .  22
  12.  References  . . . . . . . . . . . . . . . . . . . . . . .  22
  13.  Acknowledgments . . . . . . . . . . . . . . . . . . . . .  23
       Author's Address  . . . . . . . . . . . . . . . . . . . .  23


1.  Introduction

   AI agents are acquiring the ability to discover, communicate with,
   and delegate tasks to other agents autonomously.  Protocols such
   as Google Agent-to-Agent (A2A) and Anthropic Model Context Protocol
   (MCP) provide the transport and capability-discovery layers, but
   they do not prescribe how an agent SHOULD verify the identity or
   trustworthiness of a counterparty.

   The current agent ecosystem is repeating the trajectory of early
   electronic mail: building communication infrastructure without
   authentication.  Email required two decades to retrofit SPF, DKIM,
   and DMARC once spam reached crisis levels.  Airlock is designed to
   serve the role of an authentication and reputation layer for AI
   agents before the analogous crisis arrives.

   This document specifies the Airlock protocol at the message level.
   The protocol is transport-agnostic; the reference implementation
   uses REST over HTTPS with optional WebSocket streaming, but any
   transport capable of delivering JSON messages MAY be used.

1.1.  Design Goals

   The protocol is guided by five design principles:

   1.  Decentralized identity: Agents self-generate Ed25519 key pairs
       and derive did:key identifiers without a central authority.

   2.  Cryptographic verification at every hop: Every protocol message
       carries an Ed25519 signature over its canonical JSON form.

   3.  Reputation-aware routing: A scoring algorithm with temporal
       decay routes trusted agents through a fast path, unknown agents
       through a semantic challenge, and untrusted agents to immediate
       rejection.

   4.  LLM-augmented challenge: For agents in the unknown trust zone,
       the protocol issues a semantic challenge -- a capability-
       specific question evaluated by a large language model -- that
       is resistant to replay and impersonation.

   5.  Transport-agnostic: The protocol is defined at the message
       level and does not mandate a specific transport binding.


2.  Terminology

   The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
   "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY",
   and "OPTIONAL" in this document are to be interpreted as described
   in BCP 14 [RFC2119] [RFC8174] when, and only when, they appear in
   all capitals, as shown here.

   Agent:  An autonomous software entity identified by a DID, capable
      of sending and receiving protocol messages.

   Gateway:  A server implementing the Airlock verification pipeline.
      The gateway receives handshake requests, runs the verification
      state machine, and issues verdicts and seals.  A gateway
      possesses its own DID and signing key.

   DID (Decentralized Identifier):  A globally unique identifier
      conforming to W3C DID Core [W3C.DID-CORE].  Airlock uses the
      did:key method exclusively, where the DID is deterministically
      derived from an Ed25519 public key.

   Verifiable Credential (VC):  A tamper-evident credential conforming
      to the W3C VC Data Model [W3C.VC-DATA-MODEL].  In Airlock, a VC
      asserts claims about an agent and is signed by an issuer's
      Ed25519 key.

   Trust Score:  A floating-point value in [0.0, 1.0] representing
      the gateway's confidence in an agent, maintained per agent DID
      with temporal decay.

   Handshake:  The initial protocol message in which an agent presents
      its identity, intent, credential, and signature to the gateway.

   Challenge:  A semantic question issued by the gateway to an agent
      whose trust score falls in the unknown zone.

   Verdict:  The gateway's decision after verification: VERIFIED,
      REJECTED, or DEFERRED.

   Seal:  A signed record containing the full verification trace,
      verdict, trust score, and attestation for a completed session.

   Attestation:  A structured claim by the gateway asserting the
      outcome of a verification session, including which checks
      passed and the resulting trust score.

   Nonce:  A cryptographically random value (128-bit, hex-encoded)
      included in every message envelope to prevent replay attacks.


3.  Protocol Overview

3.1.  The Five Phases

   The Airlock protocol defines five sequential phases:

     Phase 1     Phase 2      Phase 3       Phase 4      Phase 5
     RESOLVE --> HANDSHAKE -> CHALLENGE --> VERDICT  --> SEAL
     (discover)  (present)    (prove)       (decide)     (attest)

   1.  Resolve: The caller discovers the target agent's profile,
       capabilities, DID, and endpoint status.

   2.  Handshake: The initiating agent submits a signed
       HandshakeRequest containing its DID, intent, Verifiable
       Credential, and Ed25519 signature.  The gateway validates
       schema, signature, and credential.

   3.  Challenge: If the agent's trust score falls in the unknown
       zone (0.15 < score < 0.75), the gateway issues a
       ChallengeRequest.  High-trust agents skip this phase entirely
       (fast-path).  Very low-trust agents are rejected immediately
       (blacklist).

   4.  Verdict: The gateway evaluates the challenge response (or
       applies the fast-path/blacklist decision) and issues a
       TrustVerdict: VERIFIED, REJECTED, or DEFERRED.

   5.  Seal: Both parties receive a signed SessionSeal containing
       the full verification trace, attestation, and updated trust
       score.

3.2.  Protocol Flow

   The following diagram illustrates the message exchange between
   an initiating agent and the gateway:

     Agent                                Gateway
       |                                     |
       |  HandshakeRequest                   |
       |  (DID + VC + intent + signature)    |
       | ----------------------------------> |
       |                                     |
       |  TransportAck {session_id}          |
       | <---------------------------------- |
       |                                     |
       |     [Gateway runs pipeline]         |
       |     validate_schema                 |
       |     check_revocation                |
       |     verify_signature                |
       |     validate_vc                     |
       |     check_reputation                |
       |                                     |
       |    .------[routing decision]------.  |
       |    |            |                 |  |
       |  score>=0.75  0.15<s<0.75   score<=0.15
       |  (fast-path)  (challenge)    (blacklist)
       |    |            |                 |  |
       |    |  ChallengeRequest            |  |
       |    | <--------------------------- |  |
       |    |                              |  |
       |    |  ChallengeResponse           |  |
       |    | ---------------------------> |  |
       |    |                              |  |
       |    |  [LLM evaluates answer]      |  |
       |    |            |                 |  |
       |    '-------.----'---------.-------'  |
       |            |              |          |
       |  TrustVerdict + Attestation         |
       | <---------------------------------- |
       |                                     |
       |  SessionSeal                        |
       | <---------------------------------- |
       |                                     |

   Figure 1: Airlock Verification Protocol Sequence Diagram

3.3.  Routing Paths

   The following table summarizes the three routing paths:

   +-----------+------------------+-----------------------------------+
   | Path      | Condition        | Behavior                          |
   +-----------+------------------+-----------------------------------+
   | Fast-path | score >= 0.75    | Phases 3-4 skipped; gateway       |
   |           |                  | issues VERIFIED immediately.      |
   +-----------+------------------+-----------------------------------+
   | Challenge | 0.15 < s < 0.75  | Full pipeline with LLM-generated  |
   |           |                  | semantic challenge.               |
   +-----------+------------------+-----------------------------------+
   | Blacklist | score <= 0.15    | Agent rejected immediately; no    |
   |           |                  | challenge issued.                 |
   +-----------+------------------+-----------------------------------+

           Table 1: Routing Decision Summary


4.  Agent Identity

4.1.  DID:key Method

   Airlock uses the did:key method as defined by the W3C DID
   specification [W3C.DID-KEY].  Each agent identity is derived
   deterministically from an Ed25519 public key [RFC8032].  No
   external DID registry is required.

   The DID derivation procedure is as follows:

   1.  Generate or load a 32-byte Ed25519 seed using a
       cryptographically secure random number generator.

   2.  Derive the Ed25519 signing key and verify (public) key from
       the seed per [RFC8032] Section 5.1.5.

   3.  Prepend the multicodec prefix for Ed25519 public keys
       (0xed01) to the 32-byte raw public key, yielding a 34-byte
       payload.

   4.  Encode the payload using base58btc (Bitcoin alphabet).

   5.  Prepend the multibase prefix "z" (indicating base58btc).

   6.  The DID is formed as: did:key:z<base58btc-encoded-payload>.

   Example:

     Seed (hex):     a1b2c3...  (32 bytes)
     Public key:     <32-byte Ed25519 verify key>
     Multicodec:     0xed01 || <32-byte public key> = 34 bytes
     Base58btc:      z6Mkf5rGMoatrSj1f4CyvuHBeXJELe9RPdzo2PKGNCKVtZxP
     DID:            did:key:z6Mkf5rGMoatrSj1f4CyvuH...

4.2.  Key Generation Requirements

   Agents MUST generate their Ed25519 key pair using one of the
   following methods:

   o  Random generation: A cryptographically secure random 32-byte
      seed is used to derive the key pair.

   o  Deterministic from seed: A known 32-byte seed (provided as 64
      hex characters) is used.  Gateways MUST use a deterministic
      seed in production to ensure a stable DID across restarts.

   Agents SHOULD persist their seed to maintain a stable identity
   across sessions.

4.3.  DID Resolution

   To extract the Ed25519 public key from a did:key string, a
   verifier MUST perform the following steps:

   1.  Strip the "did:key:" prefix.

   2.  Verify the multibase prefix is "z" (base58btc).

   3.  Base58btc-decode the remainder.

   4.  Verify the first two bytes are the Ed25519 multicodec prefix
       (0xed01).

   5.  Extract bytes 2 through 33 as the 32-byte raw Ed25519 public
       key.

   Implementations MUST reject DIDs that do not use the Ed25519
   multicodec prefix.

4.4.  Verifiable Credential Format

   Agents MUST present a W3C Verifiable Credential in their
   HandshakeRequest.  The credential MUST conform to the W3C VC Data
   Model 1.1 [W3C.VC-DATA-MODEL] with an Ed25519Signature2020 proof.

   The following credential types are defined:

   o  AgentAuthorization: Authorizes the agent to act on behalf of
      an entity.

   o  CapabilityGrant: Grants the agent specific capabilities.

   o  IdentityAssertion: Asserts identity claims about the agent.

   The proof.proofValue MUST be computed by signing the canonical
   JSON form of the credential (excluding the proof field) with the
   issuer's Ed25519 private key, then base64-encoding the 64-byte
   signature.


5.  Message Formats

   All protocol messages use JSON encoding.  Timestamps MUST be ISO
   8601 format with UTC timezone.  All messages carrying a signature
   field MUST have that signature computed over the canonical JSON
   form of the message with the signature field excluded, per
   Section 10.5.

5.1.  MessageEnvelope

   Every protocol message MUST include a MessageEnvelope:

   +-------------------+----------+-----------------------------------+
   | Field             | Type     | Description                       |
   +-------------------+----------+-----------------------------------+
   | protocol_version  | string   | Protocol version.  MUST be        |
   |                   |          | "0.1.0" for this specification.   |
   +-------------------+----------+-----------------------------------+
   | timestamp         | datetime | ISO 8601 UTC timestamp of message |
   |                   |          | creation.                         |
   +-------------------+----------+-----------------------------------+
   | sender_did        | string   | The did:key of the message        |
   |                   |          | sender.                           |
   +-------------------+----------+-----------------------------------+
   | nonce             | string   | 128-bit cryptographically random  |
   |                   |          | hex string (32 hex characters).   |
   |                   |          | MUST be unique per message.       |
   +-------------------+----------+-----------------------------------+

          Table 2: MessageEnvelope Fields

5.2.  HandshakeRequest

   Sent by the initiating agent to the gateway to begin verification.

   +-------------------+------------------+---------------------------+
   | Field             | Type             | Description               |
   +-------------------+------------------+---------------------------+
   | envelope          | MessageEnvelope  | Message metadata.         |
   |                   |                  | envelope.sender_did MUST  |
   |                   |                  | equal initiator.did.      |
   +-------------------+------------------+---------------------------+
   | session_id        | string           | Client-generated unique   |
   |                   |                  | session identifier.       |
   +-------------------+------------------+---------------------------+
   | initiator         | AgentDID         | The agent's DID and       |
   |                   |                  | public key.               |
   +-------------------+------------------+---------------------------+
   | intent            | HandshakeIntent  | Describes the requested   |
   |                   |                  | action.                   |
   +-------------------+------------------+---------------------------+
   | credential        | VerifiableCred.  | The agent's W3C VC.       |
   +-------------------+------------------+---------------------------+
   | signature         | SignatureEnv.    | Ed25519 signature over    |
   |                   |                  | canonical form.           |
   +-------------------+------------------+---------------------------+

          Table 3: HandshakeRequest Fields

   AgentDID contains:

   o  did (string): did:key:z... identifier.

   o  public_key_multibase (string): Multibase-encoded Ed25519
      public key (z prefix + base58btc).

   HandshakeIntent contains:

   o  action (string): The action the agent wishes to perform (e.g.,
      "delegate_task").

   o  description (string): Human-readable description of intent.

   o  target_did (string): The DID of the target agent.

   SignatureEnvelope contains:

   o  algorithm (string): MUST be "Ed25519".

   o  value (string): Base64-encoded 64-byte Ed25519 signature.

   o  signed_at (datetime): ISO 8601 UTC timestamp.

5.3.  TransportAck and TransportNack

   Returned synchronously by the gateway upon receiving a
   HandshakeRequest.

   TransportAck (accepted for processing):

   o  status (string): Literal "ACCEPTED".

   o  session_id (string): The session identifier.

   o  timestamp (datetime): Server timestamp.

   o  envelope (MessageEnvelope): Gateway envelope.

   o  session_view_token (string, OPTIONAL): Short-lived JWT for
      polling session state.

   TransportNack (rejected at transport level):

   o  status (string): Literal "REJECTED".

   o  session_id (string, OPTIONAL): The session identifier.

   o  reason (string): Human-readable rejection reason.

   o  error_code (string): Machine-readable error code.  Defined
      values: INVALID_SIGNATURE, INVALID_SCHEMA, REPLAY,
      RATE_LIMITED, SENDER_MISMATCH.

   o  timestamp (datetime): Server timestamp.

   o  envelope (MessageEnvelope): Gateway envelope.

5.4.  ChallengeRequest

   Issued by the gateway when an agent's trust score is in the
   challenge zone.

   +-------------------+----------+-----------------------------------+
   | Field             | Type     | Description                       |
   +-------------------+----------+-----------------------------------+
   | envelope          | MsgEnv.  | Gateway envelope.                 |
   +-------------------+----------+-----------------------------------+
   | session_id        | string   | The verification session ID.      |
   +-------------------+----------+-----------------------------------+
   | challenge_id      | string   | Unique challenge identifier.      |
   +-------------------+----------+-----------------------------------+
   | challenge_type    | string   | "semantic" or                     |
   |                   |          | "capability_proof".               |
   +-------------------+----------+-----------------------------------+
   | question          | string   | The challenge question             |
   |                   |          | (LLM-generated).                  |
   +-------------------+----------+-----------------------------------+
   | context           | string   | Capabilities being probed.        |
   +-------------------+----------+-----------------------------------+
   | expires_at        | datetime | Response deadline.                |
   +-------------------+----------+-----------------------------------+
   | signature         | SigEnv.  | Gateway signature (OPTIONAL).     |
   +-------------------+----------+-----------------------------------+

          Table 4: ChallengeRequest Fields

5.5.  ChallengeResponse

   Submitted by the challenged agent.

   +-------------------+----------+-----------------------------------+
   | Field             | Type     | Description                       |
   +-------------------+----------+-----------------------------------+
   | envelope          | MsgEnv.  | Agent envelope.                   |
   +-------------------+----------+-----------------------------------+
   | session_id        | string   | MUST match challenge session_id.  |
   +-------------------+----------+-----------------------------------+
   | challenge_id      | string   | MUST match challenge challenge_id.|
   +-------------------+----------+-----------------------------------+
   | answer            | string   | The agent's response.             |
   +-------------------+----------+-----------------------------------+
   | confidence        | float    | Agent-reported confidence.        |
   |                   |          | Range: [0.0, 1.0].               |
   +-------------------+----------+-----------------------------------+
   | signature         | SigEnv.  | Agent signature (OPTIONAL).       |
   +-------------------+----------+-----------------------------------+

          Table 5: ChallengeResponse Fields

5.6.  SessionSeal

   The terminal message for a completed verification session.

   +-------------------+----------+-----------------------------------+
   | Field             | Type     | Description                       |
   +-------------------+----------+-----------------------------------+
   | envelope          | MsgEnv.  | Gateway envelope.                 |
   +-------------------+----------+-----------------------------------+
   | session_id        | string   | The verification session ID.      |
   +-------------------+----------+-----------------------------------+
   | verdict           | string   | "VERIFIED", "REJECTED", or        |
   |                   |          | "DEFERRED".                       |
   +-------------------+----------+-----------------------------------+
   | checks_passed     | list     | Ordered list of CheckResult       |
   |                   |          | objects.                          |
   +-------------------+----------+-----------------------------------+
   | trust_score       | float    | Agent's trust score after this    |
   |                   |          | session.  Range: [0.0, 1.0].     |
   +-------------------+----------+-----------------------------------+
   | sealed_at         | datetime | Timestamp of seal issuance.       |
   +-------------------+----------+-----------------------------------+
   | signature         | SigEnv.  | Gateway signature (OPTIONAL).     |
   +-------------------+----------+-----------------------------------+

          Table 6: SessionSeal Fields

5.7.  AirlockAttestation

   Included with the TrustVerdict delivery.

   +-------------------+----------+-----------------------------------+
   | Field             | Type     | Description                       |
   +-------------------+----------+-----------------------------------+
   | session_id        | string   | The verification session ID.      |
   +-------------------+----------+-----------------------------------+
   | verified_did      | string   | The DID of the verified agent.    |
   +-------------------+----------+-----------------------------------+
   | checks_passed     | list     | Verification checks that passed.  |
   +-------------------+----------+-----------------------------------+
   | trust_score       | float    | Agent's trust score at issuance.  |
   +-------------------+----------+-----------------------------------+
   | verdict           | string   | The verdict issued.               |
   +-------------------+----------+-----------------------------------+
   | issued_at         | datetime | Timestamp of attestation.         |
   +-------------------+----------+-----------------------------------+
   | trust_token       | string   | JWT trust token (OPTIONAL).       |
   |                   |          | Present only when verdict is      |
   |                   |          | VERIFIED and token minting is     |
   |                   |          | enabled.                          |
   +-------------------+----------+-----------------------------------+

          Table 7: AirlockAttestation Fields

5.8.  Trust Token (JWT)

   Upon a VERIFIED verdict, the gateway MAY issue a short-lived trust
   token as a JWT [RFC7519].  The token is signed using HS256
   (HMAC-SHA256).

   JWT Claims:

   o  sub: The verified agent's DID.

   o  sid: The verification session ID.

   o  ver: The verdict.  Always "VERIFIED".

   o  ts: The agent's trust score at issuance (float).

   o  iss: The gateway's DID.

   o  aud: "airlock-agent".

   o  iat: Issued-at timestamp (Unix epoch seconds).

   o  exp: Expiration timestamp (Unix epoch seconds).

   Default token lifetime is 600 seconds (10 minutes).


6.  Verification Pipeline

   The verification pipeline is implemented as a state machine with
   nine nodes and conditional routing edges.  This section specifies
   each phase normatively.

6.1.  Pipeline State Machine

   The following diagram illustrates the verification state machine:

     +------------------+
     | validate_schema  |
     +--------+---------+
              |
              v
     +------------------+
     | check_revocation |
     +--------+---------+
              |
         [revoked?]
         /        \
       NO          YES ---> +--------+
        |                   | failed | ---> END
        v                   +--------+
     +------------------+
     | verify_signature |
     +--------+---------+
              |
         [sig valid?]
         /        \
       YES         NO ----> +--------+
        |                   | failed | ---> END
        v                   +--------+
     +------------------+
     |   validate_vc    |
     +--------+---------+
              |
         [vc valid?]
         /        \
       YES         NO ----> +--------+
        |                   | failed | ---> END
        v                   +--------+
     +------------------+
     | check_reputation |
     +--------+---------+
              |
         [routing?]
        /    |     \
       /     |      \
      v      v       v
   fast   challenge  blacklist
   path      |          |
     |       v          v
     |  +-----------+ +--------+
     |  | semantic  | | failed | --> END
     |  | challenge | +--------+
     |  +-----+-----+
     |        |
     |       END (suspends; resumes on
     |            ChallengeResponse)
     v
   +---------------+
   | issue_verdict |
   +-------+-------+
           |
           v
   +---------------+
   | seal_session  |
   +-------+-------+
           |
           v
          END

   Figure 2: Verification Pipeline State Machine

6.2.  Phase 1: Schema Validation

   Node: validate_schema

   The gateway MUST validate that the incoming HandshakeRequest
   conforms to the protocol schema.  Schema validation SHOULD be
   performed at deserialization time.

   Check recorded: SCHEMA

   Failure behavior: If schema validation fails, the handshake MUST
   be rejected at the transport layer with a TransportNack (error
   code "INVALID_SCHEMA").  The pipeline MUST NOT execute.

6.3.  Phase 1b: Revocation Check

   Node: check_revocation

   The gateway MUST check whether the initiator DID has been
   revoked (see Section 9).  If the DID appears in the revocation
   store, the pipeline MUST set verdict = REJECTED, mark the
   session as FAILED, and route to the failed terminal node.

   Check recorded: REVOCATION

6.4.  Phase 2: Signature Verification

   Node: verify_signature

   The gateway MUST verify the Ed25519 signature on the
   HandshakeRequest:

   1.  Extract the signer's DID from initiator.did.

   2.  Resolve the Ed25519 public key from the DID using the
       did:key resolution procedure (Section 4.3).

   3.  Reconstruct the canonical JSON form of the HandshakeRequest
       (Section 10.5).

   4.  Verify the base64-decoded signature.value against the
       canonical bytes using the resolved Ed25519 public key per
       [RFC8032].

   Envelope alignment rule: The gateway MUST verify that
   envelope.sender_did equals initiator.did.  A mismatch MUST result
   in a TransportNack (error code "SENDER_MISMATCH").

   Check recorded: SIGNATURE

   Failure behavior: If verification fails, the pipeline MUST set
   verdict = REJECTED and route to the failed terminal node.

6.5.  Phase 3: Verifiable Credential Validation

   Node: validate_vc

   The gateway MUST validate the Verifiable Credential:

   1.  Expiry check: The VC's expirationDate MUST be in the future.

   2.  Proof presence: The VC MUST contain a proof field.

   3.  Subject binding: credentialSubject.id SHOULD equal
       initiator.did.  Implementations that enforce subject binding
       (RECOMMENDED) MUST reject mismatches.

   4.  Issuer signature: Resolve the issuer's Ed25519 public key
       from vc.issuer (a did:key) and verify proof.proofValue
       against the canonical JSON of the VC (excluding the proof
       field).

   5.  Issuer allowlist: If an issuer allowlist is configured, the
       VC's issuer DID MUST appear in the allowlist.

   Check recorded: CREDENTIAL

   Failure behavior: If any step fails, the pipeline MUST set
   verdict = REJECTED and route to the failed terminal node.

6.6.  Phase 4: Reputation Check and Routing

   Node: check_reputation

   The gateway MUST:

   1.  Retrieve the TrustScore record for initiator_did.  If no
       record exists, use the default initial score of 0.5.

   2.  Apply half-life decay (Section 7.3).

   3.  Evaluate the routing decision:

       -  Score >= 0.75: fast_path (skip challenge, issue VERIFIED).

       -  Score <= 0.15: blacklist (issue REJECTED immediately).

       -  Otherwise: challenge (issue semantic challenge).

   Check recorded: REPUTATION

6.7.  Phase 5: Semantic Challenge

   Node: semantic_challenge

   When the routing decision is "challenge", the gateway MUST:

   1.  Look up the agent's registered capabilities.

   2.  Generate an LLM-backed challenge question that probes the
       agent's stated capabilities.

   3.  Send the ChallengeRequest to the agent.

   4.  Suspend the pipeline and await the ChallengeResponse.

   Upon receiving a ChallengeResponse, the gateway MUST:

   5.  Evaluate the response using an LLM, producing one of:
       PASS, FAIL, or AMBIGUOUS.

   6.  Map the outcome to a TrustVerdict:

       -  PASS -> VERIFIED

       -  FAIL -> REJECTED

       -  AMBIGUOUS -> DEFERRED

   7.  Update the agent's reputation score per Section 7.2.

   Check recorded: SEMANTIC


7.  Trust Scoring Model

   The trust scoring system maintains a per-agent reputation score
   that evolves over time based on verification outcomes and temporal
   decay.

7.1.  Initial Score

   New agents with no prior interaction history MUST start with a
   neutral score of 0.50.  This positions them in the challenge zone,
   requiring at least one successful semantic challenge before earning
   fast-path trust.

7.2.  Verdict Deltas

   When a verification session concludes, the agent's score MUST be
   updated based on the verdict:

   +-----------+------------------------------------------+-----------+
   | Verdict   | Delta Formula                            | Rationale |
   +-----------+------------------------------------------+-----------+
   | VERIFIED  | +0.05 / (1 + interaction_count * 0.1)    | Positive  |
   |           |                                          | signal    |
   |           |                                          | with      |
   |           |                                          | diminish- |
   |           |                                          | ing       |
   |           |                                          | returns.  |
   +-----------+------------------------------------------+-----------+
   | REJECTED  | -0.15 (fixed)                            | Strong    |
   |           |                                          | negative  |
   |           |                                          | signal.   |
   +-----------+------------------------------------------+-----------+
   | DEFERRED  | -0.02 (fixed)                            | Mild      |
   |           |                                          | negative  |
   |           |                                          | signal.   |
   +-----------+------------------------------------------+-----------+

          Table 8: Verdict Score Deltas

   The asymmetric delta design reflects a security-first philosophy:
   trust is earned slowly and lost quickly.  The diminishing returns
   function for VERIFIED prevents trust inflation from volume alone;
   the gain at interaction count n is:

     delta = 0.05 / (1 + n * 0.1)

7.3.  Half-Life Decay

   Agent scores MUST decay toward the neutral point (0.50) over
   time using the following formula:

     decayed = 0.50 + (current - 0.50) * 2^(-elapsed_days / 30)

   Parameters:

   o  Half-life: 30 days

   o  Neutral point: 0.50

   Properties:

   o  A trusted agent (score 0.90) that stops interacting decays
      to approximately 0.70 after 30 days and 0.60 after 60 days,
      approaching 0.50 asymptotically.

   o  A distrusted agent (score 0.10) similarly drifts back toward
      0.50 over time.

   o  Decay MUST be applied at read time (during reputation lookup),
      not as a background process.

7.4.  Routing Thresholds

   +---------------------+-------+-----------------------------------+
   | Threshold           | Value | Decision                          |
   +---------------------+-------+-----------------------------------+
   | THRESHOLD_HIGH      | 0.75  | Score >= 0.75: fast-path to       |
   |                     |       | VERIFIED.                         |
   +---------------------+-------+-----------------------------------+
   | THRESHOLD_BLACKLIST | 0.15  | Score <= 0.15: immediate          |
   |                     |       | REJECTED.                         |
   +---------------------+-------+-----------------------------------+
   | Challenge zone      | --    | 0.15 < score < 0.75: semantic     |
   |                     |       | challenge required.               |
   +---------------------+-------+-----------------------------------+

          Table 9: Routing Thresholds

7.5.  Trust Score Routing Decision Tree

   The following diagram illustrates the routing decision logic:

                      +------------------+
                      | Read trust score |
                      | for agent DID    |
                      +--------+---------+
                               |
                      +--------+---------+
                      | Apply half-life  |
                      | decay            |
                      +--------+---------+
                               |
                      +--------+---------+
                      | score >= 0.75 ?  |
                      +---+-----------+--+
                          |           |
                         YES          NO
                          |           |
                    +-----+----+  +---+-------------+
                    |FAST PATH |  | score <= 0.15 ?  |
                    | VERIFIED |  +---+-----------+--+
                    +----------+      |           |
                                     YES          NO
                                      |           |
                                +-----+----+ +----+-------+
                                |BLACKLIST | |  CHALLENGE  |
                                | REJECTED | | (semantic)  |
                                +----------+ +----+--------+
                                                  |
                                          +-------+-------+
                                          | LLM evaluates |
                                          +---+---+---+---+
                                              |   |   |
                                           PASS AMBIG FAIL
                                              |   |   |
                                              v   v   v
                                            VER  DEF  REJ

   Figure 3: Trust Score Routing Decision Tree

7.6.  Score Bounds

   Scores MUST be clamped to the range [0.0, 1.0].  All arithmetic
   operations MUST clamp the result before persistence.


8.  Delegation

8.1.  One-Hop Delegation Model

   Airlock supports a constrained delegation model in which a
   verified agent (the delegator) MAY authorize another agent (the
   delegatee) to act on its behalf for a specific task.  Delegation
   is limited to one hop: a delegatee MUST NOT further delegate to
   a third agent.

8.2.  Delegation Mechanism

   Delegation is expressed through a Verifiable Credential of type
   "AgentAuthorization":

   1.  The delegator issues a VC with credentialSubject.id set to
       the delegatee's DID.

   2.  The VC's credentialSubject SHOULD include a "scope" claim
       describing the permitted actions.

   3.  The delegatee presents this VC in its HandshakeRequest when
       contacting the gateway.

   4.  The gateway validates the delegation VC using the standard
       credential validation procedure (Section 6.5).

8.3.  Delegation Constraints

   Implementations MUST enforce the following constraints:

   o  Single hop: The gateway MUST reject VCs where the issuer DID
      is itself a delegatee (i.e., the issuer's own credential was
      issued by a third party for delegation purposes).

   o  Temporal bounds: Delegation VCs MUST include an expirationDate.
      The gateway MUST reject expired delegation credentials.

   o  Scope limitation: Delegation VCs SHOULD specify an explicit
      scope.  Gateways MAY reject delegation VCs without a scope
      claim.


9.  Revocation

9.1.  DID Revocation

   The gateway MUST support revoking agent DIDs.  A revoked DID
   MUST be rejected at the revocation check phase (Section 6.3)
   before any cryptographic verification is performed.

9.2.  Revocation Store

   The gateway MUST maintain a revocation store that supports:

   o  Adding a DID to the revocation list.

   o  Checking whether a DID is revoked (synchronous lookup).

   o  Removing a DID from the revocation list (re-enabling).

   The revocation check MUST be performed early in the pipeline
   (after schema validation, before signature verification) to
   avoid wasting computational resources on revoked agents.

9.3.  Credential Revocation

   Individual Verifiable Credentials MAY be revoked independently
   of the agent DID.  Credential revocation is outside the scope of
   this specification but MAY be implemented using W3C VC status
   methods such as RevocationList2020.


10.  Security Considerations

10.1.  Nonce Replay Protection

   Every MessageEnvelope contains a cryptographically random nonce.
   The gateway MUST maintain a nonce replay cache keyed by
   (sender_did, nonce):

   o  If a (sender_did, nonce) pair has been seen within the TTL
      window (default 600 seconds), the message MUST be rejected
      with a TransportNack (error code "REPLAY").

   o  In multi-replica deployments, the nonce cache SHOULD be backed
      by shared storage to prevent cross-replica replay.

   o  Nonce entries SHOULD be evicted after the TTL expires to bound
      memory usage.

10.2.  Rate Limiting

   The gateway MUST enforce rate limits to prevent abuse:

   o  Per-IP: 120 requests per minute across all endpoints.

   o  Per-DID on handshake: 30 requests per minute.

   o  Per-IP on registration: Configurable hourly cap.

   In multi-replica deployments, rate limit counters SHOULD be
   shared via external storage.

10.3.  Signature-First Validation

   The gateway MUST verify the Ed25519 signature on a
   HandshakeRequest at the transport layer, before any internal
   event processing.  Invalid signatures MUST result in an immediate
   TransportNack without further resource consumption.

10.4.  VC Issuer Allowlist

   In production deployments, the gateway SHOULD configure an issuer
   allowlist.  When configured, only VCs signed by an issuer on the
   allowlist will be accepted.  This prevents agents from self-
   issuing credentials without organizational oversight.

10.5.  Canonical JSON Signing

   All signatures MUST be computed over a canonical JSON
   representation of the message:

   1.  Serialize the message to a JSON dictionary.

   2.  Remove the "signature" field if present.

   3.  Sort all keys recursively.

   4.  Use compact separators (no whitespace): (",", ":").

   5.  Encode as UTF-8 bytes.

   6.  Sign the resulting byte string with the sender's Ed25519
       private key per [RFC8032].

   This procedure follows principles from [RFC8785] (JSON
   Canonicalization Scheme).

10.6.  Subject Binding

   The gateway SHOULD verify that credentialSubject.id in the
   presented VC matches initiator.did in the handshake.  This
   prevents credential theft -- an agent MUST NOT be able to present
   another agent's VC successfully.

10.7.  Sybil Protection

   To prevent Sybil attacks (mass registration of fake agent
   identities), the gateway MUST enforce per-IP registration caps.
   The per-minute rate limit on registration provides a second layer
   of defense.

10.8.  Session TTL

   Verification sessions MUST expire after a configurable TTL
   (default 180 seconds).  Expired sessions MUST NOT accept
   challenge responses and SHOULD be cleaned up.

10.9.  SSRF Prevention

   Callback URLs provided in handshake requests MUST be validated
   against an allowlist of permitted schemes and hosts.  The gateway
   MUST NOT follow redirects to internal network addresses.

10.10.  Trust Token Security

   Trust tokens are bearer tokens and MUST be treated as sensitive.
   Implementations MUST:

   o  Use a strong, randomly generated secret for HS256 signing.

   o  Set short token lifetimes (default 600 seconds).

   o  Validate token expiration on every use.

   o  Never include trust tokens in URLs or query parameters.


11.  IANA Considerations

   This document has no IANA actions at this stage.

   Future versions of this specification MAY request:

   o  Registration of a media type for Airlock protocol messages.

   o  Registration of the "airlock" well-known URI suffix.

   o  Assignment of a DID method identifier if Airlock introduces
      a custom DID method beyond did:key.


12.  References

12.1.  Normative References

   [RFC2119]  Bradner, S., "Key words for use in RFCs to Indicate
              Requirement Levels", BCP 14, RFC 2119,
              DOI 10.17487/RFC2119, March 1997,
              <https://www.rfc-editor.org/info/rfc2119>.

   [RFC8032]  Josefsson, S. and I. Liusvaara, "Edwards-Curve Digital
              Signature Algorithm (EdDSA)", RFC 8032,
              DOI 10.17487/RFC8032, January 2017,
              <https://www.rfc-editor.org/info/rfc8032>.

   [RFC8174]  Leiba, B., "Ambiguity of Uppercase vs Lowercase in RFC
              2119 Key Words", BCP 14, RFC 8174,
              DOI 10.17487/RFC8174, May 2017,
              <https://www.rfc-editor.org/info/rfc8174>.

   [RFC8785]  Rundgren, A., Jordan, B., and S. Erdtman, "JSON
              Canonicalization Scheme (JCS)", RFC 8785,
              DOI 10.17487/RFC8785, June 2020,
              <https://www.rfc-editor.org/info/rfc8785>.

   [RFC7519]  Jones, M., Bradley, J., and N. Sakimura, "JSON Web
              Token (JWT)", RFC 7519, DOI 10.17487/RFC7519,
              May 2015,
              <https://www.rfc-editor.org/info/rfc7519>.

   [W3C.DID-CORE]
              Sporny, M., Longley, D., Sabadello, M., Reed, D.,
              Steele, O., and C. Allen, "Decentralized Identifiers
              (DIDs) v1.0", W3C Recommendation, July 2022,
              <https://www.w3.org/TR/did-core/>.

   [W3C.DID-KEY]
              Longley, D., Zagidulin, D., and M. Sporny, "did:key
              Method", W3C Community Group Report,
              <https://w3c-ccg.github.io/did-method-key/>.

   [W3C.VC-DATA-MODEL]
              Sporny, M., Noble, G., Longley, D., Burnett, D., and
              B. Zundel, "Verifiable Credentials Data Model v1.1",
              W3C Recommendation, March 2022,
              <https://www.w3.org/TR/vc-data-model/>.

12.2.  Informative References

   [A2A]      Google, "Agent-to-Agent (A2A) Protocol",
              <https://google.github.io/A2A/>.

   [MCP]      Anthropic, "Model Context Protocol",
              <https://modelcontextprotocol.io/>.

   [RFC7807]  Nottingham, M. and E. Wilde, "Problem Details for HTTP
              APIs", RFC 7807, DOI 10.17487/RFC7807, March 2016,
              <https://www.rfc-editor.org/info/rfc7807>.

   [MULTIBASE]
              Sporny, M. and D. Longley, "The Multibase Data Format",
              Internet-Draft, IETF,
              <https://datatracker.ietf.org/doc/html/
              draft-multiformats-multibase>.

   [MULTICODEC]
              Protocol Labs, "Multicodec - Self-describing codecs",
              <https://github.com/multiformats/multicodec>.


13.  Acknowledgments

   The author thanks the open-source communities behind the W3C DID
   and Verifiable Credentials standards, the LangGraph project for
   providing the state machine framework used in the reference
   implementation, and the Google A2A and Anthropic MCP teams for
   advancing agent interoperability.


Author's Address

   Shivdeep Singh
   The Airlock Project
   Email: shivdeep@airlock.dev
