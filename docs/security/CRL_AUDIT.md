# CRL Design Audit: Blindspots, Attack Vectors, and Missing Considerations

**Auditor:** Security Review
**Date:** 2026-04-05
**Scope:** Proposed pull-based CRL (`/crl` endpoint) for Airlock Protocol
**Protocol Version:** 0.1.0 (DID:key + Ed25519)

---

## Executive Summary

The proposed CRL design (signed JSON document, pull-based polling, `nextUpdate` caching) mirrors the earliest X.509 CRL model from the 1990s. Thirty years of WebPKI operational failure have proven this baseline insufficient. This audit identifies **23 findings** across 10 investigation areas, with **4 Critical**, **7 High**, **8 Medium**, and **4 Low** severity issues.

The most dangerous gap: the current `RevocationStore` (in-memory set or Redis `SADD`) has **no signed CRL document at all** -- relying parties cannot independently verify revocation state. The proposed `/crl` endpoint would be a signed JSON snapshot, but the design lacks answers for the revocation delay window, CRL size explosion, signing key compromise, and fail-open/fail-closed semantics that have caused real-world incidents in TLS/PKI.

---

## Table of Contents

1. [Revocation Delay Window](#1-revocation-delay-window)
2. [CRL Size Explosion](#2-crl-size-explosion)
3. [CRL Signing Key Compromise](#3-crl-signing-key-compromise)
4. [Offline / Stale Cache Risk](#4-offline--stale-cache-risk)
5. [CRL Distribution Under DDoS](#5-crl-distribution-under-ddos)
6. [Soft vs Hard Revocation](#6-soft-vs-hard-revocation)
7. [Revocation Reason Codes](#7-revocation-reason-codes)
8. [Privacy Concerns](#8-privacy-concerns)
9. [Cross-Registry Federation](#9-cross-registry-federation)
10. [VC_VERIFIED Tier-Differentiated Revocation](#10-vc_verified-tier-differentiated-revocation)
11. [Additional Findings from Codebase Analysis](#11-additional-findings-from-codebase-analysis)

---

## 1. Revocation Delay Window

### Finding 1.1: Unbounded revocation propagation delay

**Severity: CRITICAL**

Between `issued_at` and `nextUpdate`, a revoked DID:key still passes verification at any relying party using a cached CRL. The current codebase (`revocation.py`) operates only on in-memory or Redis sets -- there is no `nextUpdate` concept, no signed CRL document, and no propagation mechanism to relying parties at all.

**What WebPKI learned:**
- X.509 RFC 5280 allows CRL update intervals from 1 hour to 7+ days. In practice, most CAs published CRLs every 24 hours, meaning a revoked certificate could be trusted for up to 24 hours after compromise.
- OCSP reduced this to minutes but introduced the soft-fail disaster: browsers that cannot reach the OCSP responder simply accept the certificate anyway. Adam Langley (Google) described soft-fail OCSP as a safety belt that works except when you have an accident.
- Let's Encrypt's OCSP deprecation (completing August 2025) was driven by the realization that OCSP's real-time model was both a privacy leak and an availability liability.

**Airlock-specific analysis:**

AI agent interactions happen at machine speed. A compromised agent DID could execute hundreds of autonomous transactions in the minutes between revocation and CRL propagation. The damage window is proportional to:

```
damage = (transactions_per_second) * (nextUpdate_interval) * (value_per_transaction)
```

For AI agents making API calls, financial transactions, or data access requests, even 60 seconds of delay could mean thousands of unauthorized operations.

**Sweet spot for AI agents:**

| Interval | Suitability | Trade-off |
|----------|-------------|-----------|
| 1-5 seconds | Real-time push (WebSocket/SSE) | Infra cost, connection management |
| 30-60 seconds | Near-real-time polling | Good for most agent use cases |
| 5 minutes | Standard operational | Acceptable if combined with short-lived trust tokens |
| 1 hour | X.509 legacy | Unacceptable for agent-to-agent trust |
| 24 hours | Legacy CRL | Completely unacceptable |

**Recommendation:**
- Primary: 60-second `nextUpdate` interval for the CRL document
- Secondary: Real-time push channel (WebSocket/SSE) for immediate revocation notification to connected relying parties
- Tertiary: Short-lived trust tokens (already implemented as `trust_token_ttl_seconds` with max 600s) act as a natural revocation boundary -- a revoked agent's existing tokens expire within TTL
- Config: `crl_update_interval_seconds` with minimum 30, maximum 300, default 60

### Finding 1.2: Trust tokens outlive revocation

**Severity: HIGH**

The current `trust_token_ttl_seconds` (configurable 60-86400s, default 600s) means a `VERIFIED` trust JWT remains valid for up to 10 minutes after the DID is revoked. The `decode_trust_token` function in `trust_jwt.py` checks `exp` and `aud` but has no revocation check.

**Recommendation:**
- Add DID revocation check to `decode_trust_token` (requires passing the revocation store or adding a revoked-DIDs claim to the token)
- Reduce default `trust_token_ttl_seconds` to 120s (2 minutes)
- For high-value operations, require fresh verification rather than trusting cached tokens
- Consider adding a `jti` (JWT ID) claim that can be individually revoked

---

## 2. CRL Size Explosion

### Finding 2.1: Linear growth of full CRL document

**Severity: HIGH**

The `list_revoked()` method returns `sorted(self._revoked)` as a flat list of DID strings. A DID:key string is approximately 60 bytes (e.g., `did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK`). At 100K revoked DIDs, the raw JSON CRL payload would be approximately 7-8 MB before signing overhead.

**What WebPKI learned:**
- GlobalSign's CRL grew from 22KB to 4.7MB in a single day during the Heartbleed mass revocation event (2014). The bandwidth cost for CRL distribution during this event was estimated at $400,000.
- Google's CRLSets imposed a hard 250KB cap, which meant they could only cover a fraction of revoked certificates -- Chrome was blind to revocations from over 80% of trusted CAs.
- Mozilla's CRLite (deployed in Firefox 137, April 2025) compresses 300MB of revocation data to approximately 1MB using cascading Bloom filters (now Ribbon filter "Clubcards"), covering the entire WebPKI.

**Airlock-specific projections:**

| Revoked DIDs | Raw JSON size | With signatures | Bandwidth/hour (60s polling, 1000 RPs) |
|-------------|---------------|-----------------|---------------------------------------|
| 1,000 | ~70 KB | ~75 KB | ~4.5 GB |
| 10,000 | ~700 KB | ~710 KB | ~42 GB |
| 100,000 | ~7 MB | ~7.1 MB | ~426 GB |
| 1,000,000 | ~70 MB | ~70.1 MB | ~4.2 TB |

**Recommendation -- Phased approach:**

**Phase 1 (Now, <10K DIDs):** Full CRL with `ETag`/`If-None-Match` HTTP caching. Cheap, simple, works.

**Phase 2 (10K-100K DIDs):** Delta CRLs. RFC 5280 Section 5.2.4 defines this:
```json
{
  "version": 2,
  "type": "delta",
  "base_crl_number": 4271,
  "this_update": "2026-04-05T12:00:00Z",
  "next_update": "2026-04-05T12:01:00Z",
  "added": ["did:key:z6Mk...abc"],
  "removed": [],
  "signature": "..."
}
```

**Phase 3 (100K+ DIDs):** W3C Bitstring Status List. Each DID is assigned an index at registration time. Revocation state is a compressed bitstring (131,072 bits = 16KB uncompressed minimum per the W3C spec). This is what Microsoft Entra Verified ID and the W3C VC ecosystem are converging on.

**Phase 4 (1M+ DIDs, federated):** CRLite-style cascading Bloom/Ribbon filters. Overkill until federation, but the right long-term architecture.

### Finding 2.2: No CRL versioning or numbering

**Severity: MEDIUM**

The current design has no CRL sequence number. Without monotonic CRL numbering, relying parties cannot detect:
- Replay of old CRLs (attacker serves stale CRL missing recent revocations)
- Missing delta CRLs in a chain
- Fork attacks (two valid CRLs with the same timestamp but different contents)

**Recommendation:**
- Add monotonically increasing `crl_number` (uint64)
- Relying parties MUST reject any CRL with `crl_number <= last_seen_crl_number`
- Store `crl_number` in Redis for persistence across restarts

---

## 3. CRL Signing Key Compromise

### Finding 3.1: Single-key CRL signing with no key ceremony

**Severity: CRITICAL**

The gateway signing key (`gateway_seed_hex` in `config.py`) is used for both handshake signing and would presumably sign CRL documents. This key is:
- Stored as a hex string in an environment variable
- Generated from a deterministic seed (or random if not set)
- Has no rotation mechanism
- Has no multi-party control

If this key is compromised, an attacker can:
1. Issue fake CRLs that remove legitimate revocations (un-revoke compromised agents)
2. Issue fake CRLs that add false revocations (DoS legitimate agents)
3. Sign fake handshake messages impersonating the registry

**What WebPKI learned:**
- Certificate Authority root key ceremonies require physically secured vaults, multiple custodians with smart cards in M-of-N quorum configurations (e.g., 3-of-5), and hardware security modules (HSMs) with tamper-evident seals
- DigiNotar's compromise (2011) demonstrated that a single compromised CA signing key could forge certificates for any domain, leading to the CA's complete shutdown

**Recommendation:**
- **Immediate:** Separate CRL signing key from the gateway handshake key. The CRL signer should be a dedicated key pair used only for CRL documents
- **Short-term:** Implement key rotation with overlap periods. Old key remains valid for verification of existing CRLs until their `nextUpdate` passes
- **Medium-term:** Multi-signature CRL signing. Require 2-of-3 registry operator keys to sign a CRL update. This prevents a single compromised operator from issuing fake CRLs
- **Long-term:** HSM-backed CRL signing key for production registry at `api.airlock.ing`. Cloud HSMs (AWS CloudHSM, Azure Dedicated HSM, GCP Cloud HSM) support Ed25519

### Finding 3.2: No CRL signing key pinning

**Severity: HIGH**

Relying parties have no way to know which key(s) are authorized to sign CRLs. If the registry rotates its signing key, or if an attacker presents a CRL signed by a different key, relying parties cannot distinguish legitimate rotation from compromise.

**Recommendation:**
- Publish the CRL signing public key in a well-known discovery document (`/.well-known/airlock-configuration`)
- Include key ID (`kid`) in CRL signatures
- Support a trust-on-first-use (TOFU) or pinned key model where relying parties remember the CRL signer's public key
- Publish key rotation events to a transparency log (see Finding 9)

---

## 4. Offline / Stale Cache Risk

### Finding 4.1: No maximum cache age enforcement

**Severity: HIGH**

If a relying party caches a CRL and then loses connectivity for 24 hours, it continues trusting the stale CRL. Any DIDs revoked in that 24-hour window pass verification. The design has no concept of a "must-refresh" deadline after which a cached CRL becomes invalid.

**What WebPKI learned:**
- OCSP responses include `nextUpdate` but browsers that cannot refresh simply accept the stale response (soft-fail)
- The OCSP Must-Staple extension (RFC 7633) was designed to solve this by requiring the server to present a fresh OCSP response, but adoption was minimal and Let's Encrypt dropped support in 2025

**Recommendation:**
- Define a `max_cache_age` field in the CRL document (separate from `nextUpdate`). `nextUpdate` is when the registry plans to publish. `max_cache_age` is the hard deadline after which the CRL MUST be considered expired
- Recommended values: `nextUpdate` = 60 seconds, `max_cache_age` = 300 seconds (5 minutes)
- After `max_cache_age`, relying parties MUST either refresh or fail-closed (see Finding 5)
- Include `Cache-Control: max-age=60, must-revalidate` HTTP headers on the `/crl` endpoint

### Finding 4.2: RedisRevocationStore local cache staleness

**Severity: MEDIUM**

The existing `RedisRevocationStore` already has this problem at a smaller scale. The `_local_cache` set is populated by `sync_cache()` at startup but only updated on local `revoke()`/`unrevoke()` calls. If another replica revokes a DID via Redis, this replica's `is_revoked_sync()` returns `False` until the next `sync_cache()`.

There is no periodic sync. The cache could be arbitrarily stale.

**Recommendation:**
- Add a periodic `sync_cache()` task (e.g., every 30 seconds) running in the background
- Use Redis Pub/Sub to push revocation events to all replicas immediately
- Add a `cache_synced_at` timestamp and reject `is_revoked_sync()` results older than a configurable threshold

---

## 5. CRL Distribution Under DDoS

### Finding 5.1: No fail-open / fail-closed policy

**Severity: CRITICAL**

The design does not specify what happens when a relying party cannot reach the `/crl` endpoint. This is the most consequential design decision in the entire CRL system.

**What WebPKI learned:**

| Strategy | Who uses it | Consequence |
|----------|-------------|-------------|
| Fail-open (soft-fail) | Chrome, Safari (OCSP) | Revocation is useless under network attack. An attacker who controls the network path can block CRL refresh and use revoked certificates indefinitely |
| Fail-closed (hard-fail) | Firefox (for stapled OCSP with Must-Staple) | Any CRL distribution outage becomes a total service outage. Legitimate agents cannot verify |
| Degraded mode | None widely | Accept cached CRL past `nextUpdate` but flag the verification as "stale-cached" with reduced trust |

**Airlock-specific risk:**

If the Airlock registry at `api.airlock.ing` is DDoSed:
- **Fail-open:** All revoked agents can operate freely. An attacker who compromises an agent AND DDoSes the registry has unlimited access
- **Fail-closed:** All agent-to-agent communication stops. A cheap DDoS becomes a protocol-wide killswitch

**Recommendation -- Tiered fail policy:**

```
if crl_age < nextUpdate:
    # Fresh CRL, normal operation
    mode = NORMAL

elif crl_age < max_cache_age:
    # Stale but within tolerance
    mode = DEGRADED
    # Reduce trust scores by 20%, flag in audit trail
    # Block new VC_VERIFIED promotions

elif crl_age < emergency_cache_age (e.g., 1 hour):
    # Emergency mode
    mode = EMERGENCY
    # Only allow interactions with previously-verified high-trust agents
    # Block all new registrations and first-time verifications
    # Aggressively retry CRL refresh

else:
    # CRL is unacceptably stale
    mode = FAIL_CLOSED
    # Reject all verifications
    # Alert operators
```

### Finding 5.2: No CDN or mirror architecture

**Severity: MEDIUM**

A single `/crl` endpoint on the gateway is a single point of failure. If 10,000 relying parties poll every 60 seconds, that is 167 requests/second just for CRL -- on top of normal verification traffic.

**Recommendation:**
- Serve CRL via CDN (Cloudflare, Fastly) with `Cache-Control` headers matching `nextUpdate`
- Support multiple CRL distribution points (CDPs) listed in agent profiles or the well-known configuration
- CRL document should be a static file regenerated on each update, not dynamically constructed per request
- Consider RFC 5765-style CRL distribution point partitioning for federated deployments

---

## 6. Soft vs Hard Revocation

### Finding 6.1: No suspension (temporary revocation) state

**Severity: MEDIUM**

The current `RevocationStore` has only two states: revoked (`_revoked.add`) and not-revoked (`_revoked.discard`). The `unrevoke` operation exists but has no semantic distinction from "was never revoked."

X.509 CRLs define `certificateHold` (CRL reason code 6) as a temporary suspension that can be lifted. This is useful for:
- Investigating a potential compromise (suspend first, investigate, then revoke or reinstate)
- Planned maintenance (temporarily disable an agent's credentials)
- Regulatory holds (e.g., a financial agent under audit)

The `AgentProfile.status` field already has `"suspended"` as a value, but this is not connected to the revocation system.

**Recommendation:**
- Add three states to the CRL: `active` (not listed), `suspended` (temporarily held, can be reactivated), `revoked` (permanent, cannot be reactivated)
- Connect `AgentProfile.status = "suspended"` to the CRL suspension state
- Suspended DIDs should fail verification but with a distinct error ("agent suspended") rather than the hard "agent revoked"
- Suspended DIDs can be reinstated; revoked DIDs cannot (irreversible for cryptographic hygiene)
- CRL entries: `{"did": "did:key:z6Mk...", "status": "suspended", "since": "...", "reason": "investigation"}`

### Finding 6.2: Unrevoke allows revocation reversal

**Severity: HIGH**

The `unrevoke()` method allows reversing a permanent revocation. If a DID's private key was compromised, unrevoking it re-trusts a potentially attacker-controlled key. This is a fundamental security violation.

In X.509 PKI, once a certificate is revoked with reason `keyCompromise`, it can never be un-revoked. The `certificateHold` reason is the only one that supports reversal.

**Recommendation:**
- `revoke()` should be irreversible (remove `unrevoke()` for permanent revocations)
- `suspend()` should be reversible (new `reinstate()` method)
- The admin API should distinguish between `POST /admin/suspend/{did}` and `POST /admin/revoke/{did}`
- Revocation audit trail entries must be immutable

---

## 7. Revocation Reason Codes

### Finding 7.1: No revocation reason metadata

**Severity: MEDIUM**

The current CRL design stores only the DID string. There is no metadata about why the revocation occurred. This information is essential for:
- **Risk assessment:** A DID revoked for "superseded" (key rotation) is less alarming than "keyCompromise"
- **Incident response:** When investigating a breach, knowing which agents were compromised vs. routinely rotated is critical
- **Compliance:** Financial regulators (RBI, NPCI in India's context) may require revocation reason reporting

**X.509 reason codes (RFC 5280 Section 5.3.1):**
- `unspecified` (0)
- `keyCompromise` (1)
- `cACompromise` (2) -- maps to "registry compromise" in Airlock
- `affiliationChanged` (3)
- `superseded` (4) -- key rotation
- `cessationOfOperation` (5)
- `certificateHold` (6) -- suspension

**Recommendation -- Airlock-specific reason codes:**

```python
class RevocationReason(StrEnum):
    KEY_COMPROMISE = "key_compromise"       # Private key leaked/stolen
    SUPERSEDED = "superseded"               # Key rotated, old key retired
    CEASED_OPERATION = "ceased_operation"    # Agent permanently decommissioned
    POLICY_VIOLATION = "policy_violation"    # Agent violated protocol rules
    SYBIL_DETECTED = "sybil_detected"       # Agent identified as part of Sybil cluster
    INVESTIGATION = "investigation"         # Suspended pending investigation (reversible)
    OWNER_REQUEST = "owner_request"         # Owner voluntarily revoked
```

- Include reason in CRL entries and audit trail
- `KEY_COMPROMISE` and `SYBIL_DETECTED` should trigger cascade revocation to all delegates
- `SUPERSEDED` entries can be pruned from the CRL after the old key's maximum possible trust token expiry

---

## 8. Privacy Concerns

### Finding 8.1: CRL leaks the full revoked agent roster

**Severity: MEDIUM**

A public `/crl` endpoint that lists all revoked DIDs reveals:
- **Which agents have been compromised** (competitive intelligence)
- **The rate of revocations** (operational health indicator for the registry)
- **Agent lifecycle patterns** (when agents are created and destroyed)
- **Sybil detection signals** (mass revocations from the same time window)

This is analogous to how OCSP requests reveal browsing patterns -- but worse, because the CRL is a complete list rather than individual queries.

**What W3C Bitstring Status List learned:**
The W3C specification mandates a minimum bitstring length of 131,072 entries (16KB) specifically to provide "group privacy" -- a single query cannot reveal whether a specific credential was checked. The specification also recommends CDN caching to prevent the issuer from correlating status checks with specific verifier activity.

**Recommendation:**
- **Short-term:** The CRL should use indexed positions rather than raw DIDs. Each DID is assigned a `revocation_index` at registration. The CRL is a bitstring where `bit[i] = 1` means the DID at index `i` is revoked. Relying parties need a separate (authenticated) lookup to map DID to index
- **Medium-term:** Adopt W3C Bitstring Status List format for interoperability with the broader VC ecosystem
- **Long-term:** Consider zero-knowledge proof of non-revocation (e.g., accumulator-based) where the agent proves their DID is not in the revoked set without revealing which DID they hold

### Finding 8.2: Admin revocation endpoints leak operational intent

**Severity: LOW**

The `POST /admin/revoke/{did}` endpoint returns `{"revoked": true, "did": "...", "changed": true}`. If an attacker can observe admin API traffic (even encrypted, via timing), they can detect when specific agents are revoked.

**Recommendation:**
- Ensure admin API is on a separate internal network/port, not exposed publicly
- Rate-limit admin API log access
- Consider batch revocation operations to reduce timing signal granularity

---

## 9. Cross-Registry Federation

### Finding 9.1: No cross-registry revocation propagation

**Severity: HIGH**

The current design assumes a single registry. The `default_registry_url` config allows upstream delegation for `/resolve`, but there is no mechanism for:
- Registry A revoking a DID that was originally registered at Registry B
- Registry B learning about revocations from Registry A
- A relying party trusting CRLs from multiple registries

In a federated model (multiple Airlock registries), a compromised agent could simply present itself to a registry that hasn't received the revocation.

**What Certificate Transparency learned:**
CT Logs solved a similar problem for X.509 -- any certificate issuance is publicly logged and auditable. This prevents a rogue CA from issuing certificates without detection.

**Recommendation:**
- **Phase 1:** Bilateral CRL sharing. Registries publish their CRL at a well-known URL. Other registries can poll and merge
- **Phase 2:** Revocation Transparency Log. A publicly auditable, append-only log of all revocation events across all registries. Modeled after Certificate Transparency (RFC 6962) but for DID revocations
- **Phase 3:** Gossip protocol. Registries gossip revocation events via a peer-to-peer mesh with configurable trust relationships
- Each registry MUST sign its own CRL; a merged CRL must include provenance (which registry originated each revocation)

### Finding 9.2: No revocation event immutability

**Severity: MEDIUM**

The existing `AuditTrail` has hash chain verification (`verify_chain()`), but revocation events (`AgentRevoked`, `AgentUnrevoked` in `schemas/events.py`) are not explicitly anchored into this chain. An operator could revoke an agent and then erase the audit record.

**Recommendation:**
- All revocation/suspension events MUST be appended to the audit trail before the revocation takes effect
- The CRL document should include a reference to the latest audit trail hash, creating a verifiable link between the CRL state and the audit history
- Consider anchoring periodic audit trail hashes to an external timestamp authority or blockchain for non-repudiation

---

## 10. VC_VERIFIED Tier-Differentiated Revocation

### Finding 10.1: High-trust agents use the same revocation as unknown agents

**Severity: MEDIUM**

A `VC_VERIFIED` agent (tier 3, score ceiling 1.0, 365-day decay half-life) goes through the same single-admin-token revocation process as an `UNKNOWN` agent (tier 0). The trust model gives VC_VERIFIED agents dramatically more privilege:
- Higher score ceilings
- Slower decay
- Decay floor protection after 10+ verifications

But the revocation process does not reflect this asymmetry. A single compromised admin token can revoke (or un-revoke) high-trust agents with no additional checks.

**Recommendation:**
- **VC_VERIFIED revocation** should require multi-party confirmation:
  - Admin token + confirmation from the VC issuer, OR
  - Admin token + time-delayed execution (24-hour grace period for the agent/owner to contest), OR
  - 2-of-3 admin keys
- **Emergency revocation** (reason: `key_compromise`) should bypass the grace period but still require audit trail entry with justification
- **VC_VERIFIED suspension** should notify the VC issuer and the agent's registered endpoint
- The CRL should include the trust tier at time of revocation so relying parties can assess severity

### Finding 10.2: No revocation notification to affected parties

**Severity: MEDIUM**

When an agent is revoked, there is no notification to:
- The agent itself (it may not know its key was compromised)
- Relying parties that recently verified the agent (they may need to rollback transactions)
- The VC issuer (they may need to revoke the credential independently)
- Delegates of the revoked agent (cascade revocation exists but is silent)

**Recommendation:**
- Emit revocation events to the EventBus (partially exists as `AgentRevoked` event type)
- Add webhook notification to the agent's `endpoint_url` on revocation
- For `KEY_COMPROMISE` revocations, notify all relying parties that verified the agent in the last `trust_token_ttl_seconds`
- Include a `revocation_notification_url` field in `AgentProfile` for out-of-band alerts

---

## 11. Additional Findings from Codebase Analysis

### Finding 11.1: Cascade revocation is incomplete

**Severity: HIGH**

The `RevocationStore.revoke()` method cascades to delegates, but:
- The `RedisRevocationStore` does NOT implement cascade revocation at all (it only does `SADD` of the single DID)
- Cascade only goes one level deep (delegates of delegates are not revoked)
- There is no way to discover the full delegation tree to cascade correctly
- The `_delegations` dict is in-memory only and lost on restart

**Recommendation:**
- Implement cascade revocation in `RedisRevocationStore` (store delegation graph in Redis)
- Support recursive cascade (multi-level delegation chains)
- Persist the delegation graph in Redis or LanceDB, not just in-memory
- Add a `GET /admin/delegations/{did}` endpoint to inspect the delegation tree before revoking

### Finding 11.2: No key rotation support in revocation

**Severity: HIGH**

The design specifies that old keys should be added to the CRL on key rotation, but there is no key rotation mechanism in the codebase. `KeyPair.generate()` creates a new key, but there is no way to:
- Associate a new DID:key with an existing agent profile
- Mark the old DID:key as `superseded` (not `compromised`)
- Transfer reputation score from old DID to new DID
- Maintain continuity of the agent's identity across key rotations

Without key rotation, agents must choose between:
1. Using the same key forever (no forward secrecy, growing compromise risk)
2. Registering as a new agent (losing all reputation history)

**Recommendation:**
- Add `POST /rotate-key` endpoint that accepts the old DID's signature + new DID's public key
- Old DID goes into CRL with reason `SUPERSEDED`
- New DID inherits the agent profile and reputation score
- Both old and new DID are linked in the registry for audit trail continuity
- Trust tokens issued under the old DID should be honored until expiry but new tokens issued under the new DID

### Finding 11.3: CRL endpoint authentication gap

**Severity: LOW**

The `/crl` endpoint must be unauthenticated (relying parties need it without prior relationship). But the current `list_revoked` is only on the admin API (requires `admin_token`). There is no public CRL endpoint.

**Recommendation:**
- Add `GET /crl` as a public, unauthenticated endpoint returning the signed CRL document
- Add `GET /.well-known/airlock-crl` as an alternative URL following well-known URI convention
- Rate-limit the public endpoint separately from admin endpoints
- Serve with appropriate `Cache-Control`, `ETag`, and `Last-Modified` headers

### Finding 11.4: No CRL signing in the current crypto module

**Severity: LOW**

The `sign_message()` and `sign_model()` functions in `crypto/signing.py` use RFC 8785-style canonical JSON, which is appropriate for CRL signing. However, there is no CRL-specific schema (Pydantic model) to sign.

**Recommendation:**
- Create `airlock/schemas/crl.py` with:

```python
class CRLEntry(BaseModel):
    did: str
    status: Literal["revoked", "suspended"]
    reason: RevocationReason
    revoked_at: datetime
    expires_from_crl: datetime | None = None  # For SUPERSEDED entries

class SignedCRL(BaseModel):
    version: int = 1
    crl_number: int
    issuer_did: str
    this_update: datetime
    next_update: datetime
    max_cache_age_seconds: int
    entries: list[CRLEntry]
    delta_base: int | None = None  # For delta CRLs
    signature: SignatureEnvelope | None = None
```

### Finding 11.5: No revocation for the registry itself

**Severity: LOW**

If the registry at `api.airlock.ing` is compromised, there is no mechanism for:
- Revoking the registry's own DID
- Notifying relying parties that the registry should no longer be trusted
- Transitioning to a new registry identity

This is analogous to the CA compromise problem in X.509 (e.g., DigiNotar).

**Recommendation:**
- Establish an out-of-band "registry trust anchor" (e.g., a multi-sig key stored offline) that can sign a "registry compromise" notice
- Publish the trust anchor public key in the protocol specification (not just the registry)
- Define a "registry migration" protocol for transitioning to a new registry DID

---

## Summary Matrix

| # | Finding | Severity | Category |
|---|---------|----------|----------|
| 1.1 | Unbounded revocation propagation delay | CRITICAL | Delay Window |
| 1.2 | Trust tokens outlive revocation | HIGH | Delay Window |
| 2.1 | Linear CRL size growth | HIGH | Scalability |
| 2.2 | No CRL versioning/numbering | MEDIUM | Scalability |
| 3.1 | Single-key CRL signing, no key ceremony | CRITICAL | Key Management |
| 3.2 | No CRL signing key pinning | HIGH | Key Management |
| 4.1 | No maximum cache age enforcement | HIGH | Caching |
| 4.2 | Redis local cache staleness | MEDIUM | Caching |
| 5.1 | No fail-open/fail-closed policy | CRITICAL | Availability |
| 5.2 | No CDN or mirror architecture | MEDIUM | Availability |
| 6.1 | No suspension state | MEDIUM | Revocation Model |
| 6.2 | Unrevoke allows reversing permanent revocation | HIGH | Revocation Model |
| 7.1 | No revocation reason codes | MEDIUM | Metadata |
| 8.1 | CRL leaks revoked agent roster | MEDIUM | Privacy |
| 8.2 | Admin endpoints leak operational intent | LOW | Privacy |
| 9.1 | No cross-registry revocation propagation | HIGH | Federation |
| 9.2 | No revocation event immutability | MEDIUM | Federation |
| 10.1 | VC_VERIFIED uses same revocation as UNKNOWN | MEDIUM | Trust Tiers |
| 10.2 | No revocation notification to affected parties | MEDIUM | Trust Tiers |
| 11.1 | Cascade revocation incomplete in Redis | HIGH | Implementation |
| 11.2 | No key rotation support | HIGH | Implementation |
| 11.3 | No public CRL endpoint | LOW | Implementation |
| 11.4 | No CRL Pydantic schema | LOW | Implementation |
| 11.5 | No registry self-revocation mechanism | LOW | Implementation |

**Critical: 3 | High: 7 | Medium: 9 | Low: 4**

---

## Recommended Implementation Priority

### Immediate (before v0.2 release)
1. Define fail-open/fail-closed policy (5.1) -- this is a design decision, not code
2. Make `revoke()` irreversible; add separate `suspend()`/`reinstate()` (6.2)
3. Add CRL sequence numbering (2.2)
4. Create `SignedCRL` Pydantic model and public `/crl` endpoint (11.3, 11.4)

### Short-term (v0.2)
5. Implement 60-second CRL update interval with `max_cache_age` (1.1, 4.1)
6. Add revocation reason codes (7.1)
7. Fix Redis cascade revocation (11.1)
8. Add DID revocation check to trust token validation (1.2)
9. Separate CRL signing key from gateway key (3.1)

### Medium-term (v0.3)
10. Key rotation mechanism (11.2)
11. Delta CRLs (2.1)
12. Real-time push channel for revocation events (1.1)
13. Periodic Redis cache sync (4.2)
14. VC_VERIFIED multi-party revocation (10.1)

### Long-term (v1.0)
15. W3C Bitstring Status List format (2.1, 8.1)
16. Cross-registry CRL federation (9.1)
17. Revocation Transparency Log (9.2)
18. Registry self-revocation protocol (11.5)

---

## References

- [RFC 5280: Internet X.509 PKI Certificate and CRL Profile](https://datatracker.ietf.org/doc/html/rfc5280)
- [W3C Bitstring Status List v1.0](https://www.w3.org/TR/vc-bitstring-status-list/)
- [CRLite: Mozilla Security Blog](https://blog.mozilla.org/security/2020/01/09/crlite-part-1-all-web-pki-revocations-compressed/)
- [CRLite End-to-End Design](https://blog.mozilla.org/security/2020/01/09/crlite-part-2-end-to-end-design/)
- [CRLite in Firefox 137](https://hacks.mozilla.org/2025/08/crlite-fast-private-and-comprehensive-certificate-revocation-checking-in-firefox/)
- [Google CRLSets](https://chromium.googlesource.com/playground/chromium-org-site/+/refs/heads/main/Home/chromium-security/crlsets.md)
- [GRC CRLSet Effectiveness Evaluation](https://www.grc.com/revocation/crlsets.htm)
- [Let's Encrypt: Ending OCSP Support in 2025](https://letsencrypt.org/2024/12/05/ending-ocsp)
- [Heartbleed CRL Infrastructure Impact](https://www.netcraft.com/blog/certificate-revocation-why-browsers-remain-affected-by-heartbleed/)
- [Heartbleed Revisited (Cloudflare)](https://blog.cloudflare.com/heartbleed-revisited/)
- [The Problem with OCSP Stapling and Must Staple](https://blog.hboeck.de/archives/886-The-Problem-with-OCSP-Stapling-and-Must-Staple-and-why-Certificate-Revocation-is-still-broken.html)
- [High-reliability OCSP stapling (Cloudflare)](https://blog.cloudflare.com/high-reliability-ocsp-stapling/)
- [W3C Verifiable Credentials Overview](https://w3c.github.io/vc-overview/)
- [HSM Key Ceremony Best Practices](https://www.encryptionconsulting.com/key-ceremony-why-it-matters/)
- [PKI Design: CRL Publishing Strategies (Microsoft)](https://learn.microsoft.com/en-us/archive/blogs/xdot509/pki-design-considerations-certificate-revocation-and-crl-publishing-strategies)
- [Scalable Privacy-Preserving Decentralized Identity (arXiv)](https://arxiv.org/pdf/2510.09715)
