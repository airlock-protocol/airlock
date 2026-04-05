# Key Rotation Security Audit -- Airlock Protocol

**Auditor:** Distributed Systems Security Review
**Date:** 2026-04-05
**Scope:** Key rotation design for DID:key-based agent identity in the Airlock Protocol
**Codebase version:** Commit `2486caf` (main branch)

---

## Executive Summary

The Airlock Protocol currently has **zero key rotation infrastructure**. No rotation message type, no rotation endpoint, no rotation schema, no DID alias/linking mechanism, no tombstone support, and no pre-commitment system exists anywhere in the codebase. The `did:key` method -- where the DID string IS the public key -- makes rotation fundamentally identity-breaking. Every reference to an old DID across the network (reputation scores in LanceDB, audit trail entries, verifiable credentials, attestations, registry profiles) becomes orphaned on rotation with no path to reconnection.

This audit identifies **18 findings** across the 11 attack surface areas specified, plus 7 additional findings discovered during codebase analysis.

---

## Finding 1: DID:key Identity Discontinuity on Rotation

**Severity: CRITICAL**

**Analysis:**

The `did:key` method encodes the Ed25519 public key directly into the DID string (`did:key:z6Mk...`). This is implemented in `airlock/crypto/keys.py` lines 21-27:

```python
self.did = f"did:key:{self.public_key_multibase}"
```

When an agent rotates keys, a new keypair produces an entirely new DID string. The following data stores become permanently orphaned:

| Store | Location | Keyed By | Impact |
|-------|----------|----------|--------|
| ReputationStore | `airlock/reputation/store.py` | `agent_did` (string) | All trust score history lost |
| AgentRegistryStore | `airlock/registry/agent_store.py` | `did` (string) | Agent profile unreachable |
| AuditTrail | `airlock/audit/trail.py` | `actor_did`, `subject_did` | Historical audit entries reference a dead identity |
| RevocationStore | `airlock/gateway/revocation.py` | `did` (string in set) | Revocation of old DID meaningless if agent has new DID |
| VerifiableCredentials | `airlock/schemas/identity.py` | `issuer`, `credential_subject.id` | All issued/received VCs reference dead DID |
| SessionManager | `airlock/engine/state.py` | `initiator_did` | Active sessions break mid-rotation |
| SignedFeedbackReports | `airlock/schemas/reputation.py` | `reporter_did`, `subject_did` | Feedback becomes unattributable |

There is no DID alias table, no `previous_did` field on any schema, and no linking mechanism between old and new DIDs.

**Recommendation:**

Implement a DID linking layer with one of these approaches (in order of preference):

1. **Adopt `did:web` or `did:peer` as the long-lived identifier**, with `did:key` used only for cryptographic operations. The DID document would contain the current key and can be updated on rotation without changing the DID itself. This is the W3C-recommended approach for long-lived identities.

2. **Implement a DID alias registry** -- a signed `DIDRotation` document maps `{old_did, new_did, rotation_chain_id}` with the old key's signature. All stores would need a secondary index on `rotation_chain_id` (a stable UUID assigned at inception).

3. **At minimum**, add a `previous_did: str | None` field to `AgentProfile`, `TrustScore`, and `AuditEntry` so that chain-walking is possible even if expensive.

**References:**
- [W3C DID Core Specification](https://www.w3.org/TR/did-core/)
- [The did:key Method v0.9](https://w3c-ccg.github.io/did-key-spec/) -- explicitly states did:key does not support key rotation
- [Peer DID Method Specification](https://identity.foundation/peer-did-method-spec/)

---

## Finding 2: Rotation Chain Reputation Laundering

**Severity: CRITICAL**

**Analysis:**

The design states "Old key signs a KeyRotation payload endorsing new key -> 1:1 trust transfer." This creates a reputation laundering vector:

1. Agent registers as DID_A, accumulates bad reputation (score 0.20, 15 failed verifications)
2. Agent rotates DID_A -> DID_B (1:1 trust transfer means score 0.20 carries over)
3. But the `failed_verifications` counter, `interaction_count`, and full history are tied to DID_A's `TrustScore` record in LanceDB
4. If the rotation transfer only carries the score float (0.20) but creates a new `TrustScore` record for DID_B, the negative history counters reset

Worse, if rapid rotation is permitted:
- DID_A (score 0.20) -> DID_B (transferred 0.20) -> immediately abandon DID_B -> create fresh DID_C (score 0.50, the default)
- The attacker has effectively laundered a bad reputation by simply generating a new keypair without going through rotation

The current `ReputationStore.get_or_default()` (line 111-129 of `store.py`) returns `INITIAL_SCORE = 0.5` for any unknown DID. There is no mechanism to detect that DID_C is the same agent as DID_A.

**Recommendation:**

1. Rotation MUST transfer the complete `TrustScore` record: `score`, `tier`, `interaction_count`, `successful_verifications`, `failed_verifications`, `created_at` (original), and `decay_rate`.
2. Implement a `rotation_chain_id` field -- a UUID assigned at first registration that persists across all rotations. The reputation store should index on both `agent_did` and `rotation_chain_id`.
3. Add a `rotation_count` field to `TrustScore`. Agents with high rotation counts relative to their age should be flagged.
4. Bind registration to proof-of-work with difficulty that scales with the number of new DIDs from the same source (the `pow_difficulty_new_did` config exists but is not linked to rotation).

**References:**
- [KERI Key Event Receipt Infrastructure](https://weboftrust.github.io/ietf-keri/draft-ssmith-keri.html) -- uses event logs to maintain full history across rotations
- Keybase sigchain model -- revocations don't erase history, old links remain valid

---

## Finding 3: Race Condition During Rotation Propagation

**Severity: HIGH**

**Analysis:**

The design says "Old DID added to CRL immediately upon rotation." The `RevocationStore` has two implementations:

1. **In-memory** (`RevocationStore` in `revocation.py`): Single-instance, no replication. Rotation is atomic within one process.
2. **Redis-backed** (`RedisRevocationStore`): Uses `SADD`/`SISMEMBER` with a local cache (`_local_cache`).

The Redis implementation has a stale cache problem (lines 86-100):

```python
def is_revoked_sync(self, did: str) -> bool:
    """Synchronous check against the local cache (fast path)."""
    return did in self._local_cache
```

The `sync_cache()` method must be called explicitly. Between rotation event and cache sync across replicas:

- **Window 1**: Old key is revoked in Redis, but Replica B's local cache still accepts it. An attacker with the old key can complete handshakes on Replica B.
- **Window 2**: New key is registered, but Replica A hasn't seen the registration. The legitimate agent is locked out on Replica A.
- **Window 3**: Both keys are in a liminal state -- the agent has no valid identity on some replicas.

The `expect_replicas` config (line 73 of `config.py`) requires Redis when > 1, but there is no cache invalidation subscription (no Redis Pub/Sub, no polling interval configured).

**Recommendation:**

1. Implement Redis Pub/Sub or Redis Streams for real-time revocation propagation. On rotation, publish to a `airlock:rotation_events` channel. All replicas subscribe and update their local cache immediately.
2. Add a `cache_sync_interval_seconds` config (default 5s) with a background task that calls `sync_cache()` periodically as a safety net.
3. For the rotation window specifically, use a two-phase approach:
   - Phase 1: Add new DID to registry (both old and new are valid)
   - Phase 2: After a configurable grace period (e.g., 30s), revoke old DID
   - This eliminates the window where neither key works.
4. Add a `rotation_grace_period_seconds` config (default 60).

**References:**
- [Split-Brain in Distributed Systems](https://dzone.com/articles/split-brain-in-distributed-systems)
- SSH certificate authority model -- uses overlapping validity periods during rotation

---

## Finding 4: Concurrent Rotation (Fork Attack)

**Severity: HIGH**

**Analysis:**

If an agent's private key is compromised, both the legitimate owner and the attacker can produce valid `KeyRotation` messages signed by the same old key, each endorsing a different new key:

- Legitimate owner: `{old: DID_A, new: DID_B, sig: sign(DID_A_privkey)}`
- Attacker: `{old: DID_A, new: DID_C, sig: sign(DID_A_privkey)}`

Both signatures are cryptographically valid. There is no mechanism in the current codebase to resolve this fork. The current `RevocationStore` is a simple set -- `revoke(did)` returns a boolean, with no concept of "who requested the revocation" or "which new DID should inherit."

Without a resolution mechanism, the system could end up in a state where:
- Some replicas accept DID_B as the successor
- Other replicas accept DID_C as the successor
- The audit trail has conflicting rotation entries

**Recommendation:**

1. **First-write-wins with lockout**: The first `KeyRotation` message for a given old DID is accepted; subsequent rotation attempts for the same old DID within a lockout window (e.g., 24h) are rejected. Use Redis `SET ... NX EX` for atomic first-write.
2. **Require pre-rotation commitment** (see Finding 6): If the next key is pre-committed, only the rotation matching the commitment is valid. This eliminates the fork entirely.
3. **Require secondary verification for rotation**: Domain verification, VC from a trusted issuer, or multi-sig from a quorum of the agent's delegators.
4. Add a `KeyRotationRequest` event type to `airlock/schemas/events.py` and handle fork detection in the orchestrator.

**References:**
- [KERI KID0005 - Next Key Commitment (Pre-Rotation)](https://identity.foundation/keri/kids/kid0005Comment.html) -- pre-commitment eliminates forks by design
- [Keybase's New Key Model](https://keybase.io/blog/keybase-new-key-model) -- device keys with a sigchain prevent fork attacks

---

## Finding 5: Rotation Replay Attack

**Severity: HIGH**

**Analysis:**

The design mentions "Need timestamp + nonce in the rotation payload" but no `KeyRotation` payload schema exists. Without it, a valid rotation message captured from the network can be replayed:

1. Agent rotates DID_A -> DID_B at time T1 (legitimate)
2. Agent later rotates DID_B -> DID_C at time T2 (legitimate)
3. Attacker replays the T1 message: DID_A -> DID_B
4. If the system doesn't track that DID_A has already been rotated, this could re-activate DID_B and de-link DID_C

The existing `MessageEnvelope` schema (`airlock/schemas/envelope.py`) does include `timestamp` and `nonce`, and the gateway has a `nonce_replay_ttl_seconds` config (default 600s). However:

- The nonce replay store only retains nonces for 10 minutes. A rotation message captured and replayed after 11 minutes would not be detected.
- There is no "rotation sequence number" -- no way to enforce monotonic ordering of rotation events.

**Recommendation:**

1. Define a `KeyRotationPayload` schema:
   ```python
   class KeyRotationPayload(BaseModel):
       old_did: str
       new_did: str
       new_public_key_multibase: str
       rotation_sequence: int  # monotonically increasing per rotation chain
       timestamp: datetime
       nonce: str
       pre_rotation_commitment: str | None = None  # hash of next-next key
       signature: SignatureEnvelope  # signed by old key
   ```
2. Store the rotation sequence number per `rotation_chain_id`. Reject any rotation with a sequence number <= the current stored sequence.
3. The replay protection window for rotation messages must be PERMANENT -- once a rotation is processed, the `(old_did, nonce)` pair must be stored indefinitely (or at least as long as the old DID exists in any record).
4. Add rotation events to the hash-chained `AuditTrail` for tamper-evident history.

**References:**
- [Signal Double Ratchet Algorithm](https://signal.org/docs/specifications/doubleratchet/) -- uses monotonic counters to prevent message replay
- KERI uses sequence numbers (sn) on all key events to enforce ordering

---

## Finding 6: No Pre-Rotation / Key Pre-Commitment

**Severity: HIGH**

**Analysis:**

KERI's pre-rotation mechanism solves the "lost key" problem by committing to the next key's hash before it is needed. The current key's inception or rotation event includes `H(next_public_key)`. When rotation occurs, the new public key is revealed and must match the prior commitment.

Airlock has no pre-commitment mechanism. The design's "lost key" path (re-verify via domain verification, tier drops one level) is:
1. **Weaker than necessary** -- if pre-rotation existed, a lost key would not require any trust penalty because the pre-committed key proves continuity of control.
2. **Vulnerable to permanent identity loss** -- if an agent loses their key and has no domain verification available, they reset to UNKNOWN with score 0.50. All accumulated trust is destroyed.
3. **Not post-quantum safe** -- a quantum adversary who can break Ed25519 in the future could derive any agent's private key from their public DID and forge rotation messages. Pre-rotation using hash commitments (SHA-256) is quantum-resistant because the next key is hidden behind a hash.

**Recommendation:**

1. Add a `next_key_commitment: str | None` field to `AgentProfile` and/or a new `KeyInceptionEvent` schema. The commitment is `SHA-256(multibase_encoded_next_public_key)`.
2. On rotation, the new key must match the prior commitment. If it does, full trust transfer. If no commitment exists (legacy agents), fall back to the current signed-rotation path.
3. Immediately after rotation, the agent should submit a new `next_key_commitment` for the subsequent rotation.
4. Store commitments in the registry alongside the agent profile.

**References:**
- [KERI KID0005 - Next Key Commitment](https://github.com/decentralized-identity/keri/blob/master/kids/kid0005.md)
- [KERI Protocol Specification](https://weboftrust.github.io/ietf-keri/draft-ssmith-keri.html)

---

## Finding 7: Multi-Device Agent Key Coordination

**Severity: HIGH**

**Analysis:**

The current design assumes a 1:1 mapping between an agent and a keypair. An agent running on multiple devices (e.g., a customer service AI running across 5 servers) shares the same `SigningKey` across all instances. This is operationally dangerous:

1. The private key must be copied to all devices, increasing the attack surface.
2. If one device rotates, the others continue signing with the old (now revoked) key and are immediately rejected by the revocation check (`_node_check_revocation` in `orchestrator.py` line 566-588).
3. There is no concept of "device keys" subordinate to an identity key.

The `KeyPair` class in `keys.py` has no device identifier, no key hierarchy, and no sub-key model.

**Recommendation:**

Adopt a device key model similar to Keybase:

1. **Identity key** (long-lived, stored in HSM or cold storage): This is the root of trust. Used only to sign device key additions/removals.
2. **Device keys** (per-instance, short-lived): Each agent instance generates its own `KeyPair`. The identity key signs a `DeviceKeyAuthorization` VC granting the device key permission to act on behalf of the identity.
3. **Rotation of device keys** is cheap and doesn't affect the identity. Only rotation of the identity key triggers the full rotation protocol.
4. Add `device_id: str | None` and `parent_did: str | None` fields to `AgentDID`.

**References:**
- [Keybase's New Key Model](https://keybase.io/blog/keybase-new-key-model) -- per-device NaCl keys with sigchain linkage
- [Keybase Sigchain Documentation](https://keybase.io/docs/sigchain)
- Signal Protocol's device-specific pre-keys

---

## Finding 8: No Rotation Frequency Limits

**Severity: MEDIUM**

**Analysis:**

The design asks whether there should be a cooldown between rotations. The current codebase has rate limits for handshakes (`rate_limit_handshake_per_did_per_minute: 30`) and IP-based limits (`rate_limit_per_ip_per_minute: 120`), but no rotation-specific throttling.

Without limits, an attacker with a compromised key can:
1. **Rotation spam**: Rapidly rotate through thousands of DIDs, creating confusion in the registry and audit trail.
2. **Trust score oscillation**: If rotation transfers trust, rapid rotation between two DIDs could exploit timing windows in reputation decay.
3. **Denial-of-service on the revocation store**: Each rotation adds an entry to `_revoked` set. The in-memory `RevocationStore` has no size limit. The Redis store has no TTL on revocation entries.

**Recommendation:**

1. Add `rotation_cooldown_seconds: int = 3600` to `AirlockConfig` -- minimum time between rotations for the same rotation chain.
2. Add `max_rotations_per_chain_per_day: int = 3` to prevent rotation spam.
3. Implement exponential backoff on rotation frequency: each successive rotation within a 24h window requires exponentially longer proof-of-work.
4. Add a `last_rotation_at: datetime | None` field to the agent profile or trust score record.

**References:**
- [SSH Key Rotation Best Practices](https://www.brandonchecketts.com/archives/ssh-ed25519-key-best-practices-for-2025) -- recommends minimum 90-day rotation intervals
- [SSH Key Management Best Practices](https://www.encryptionconsulting.com/designing-an-effective-ssh-key-rotation-policy/)

---

## Finding 9: Trust Vacuum During Rotation

**Severity: MEDIUM**

**Analysis:**

Between "old key revoked" and "new key verified," the agent has no valid identity. The design does not define the intermediate trust state.

Looking at the orchestrator flow (`orchestrator.py`), the `_node_check_revocation` (line 566) immediately rejects any revoked DID with `TrustVerdict.REJECTED`. If the old DID is revoked as part of rotation before the new DID's trust is established, the agent cannot complete any handshakes during the transition.

The `_node_check_reputation` (line 774) returns `INITIAL_SCORE = 0.5` for unknown DIDs, which routes to "challenge" path. So even with a successful rotation, the agent with a brand new DID would need to complete a semantic challenge on every handshake until their score exceeds 0.75 (the `fast_path` threshold).

For a high-trust agent (tier 3, score 0.95) rotating keys, this means:
- Old DID: revoked, all handshakes rejected
- New DID: unknown, score 0.50, must re-earn trust through multiple challenge rounds
- All pending sessions under the old DID: broken

**Recommendation:**

1. Implement a rotation grace period state: `VerificationState.ROTATION_PENDING`.
2. During the grace period, both old and new DIDs are valid. The old DID is marked as "rotating" (not "revoked") and still passes revocation checks but logs a warning.
3. Trust transfer should be atomic: when the new DID is registered via a valid `KeyRotation` message, the `TrustScore` record is duplicated to the new DID in the same database transaction.
4. The old DID moves to "revoked" status only after the grace period expires or the new DID's first successful handshake completes.

---

## Finding 10: Ed25519 to Post-Quantum Migration Path

**Severity: MEDIUM**

**Analysis:**

The entire codebase is hardcoded to Ed25519:

- `SignatureEnvelope.algorithm` is a `Literal["Ed25519"]` (line 30, `handshake.py`)
- `CredentialProof.type` is a `Literal["Ed25519Signature2020"]` (line 50, `identity.py`)
- `resolve_public_key()` in `keys.py` checks for `MULTICODEC_ED25519_PUB` prefix (line 58)
- `sign_message()` uses `SigningKey.sign()` from PyNaCl which is Ed25519-only

NIST finalized post-quantum signature standards in August 2024 (ML-DSA/Dilithium as FIPS 204, SLH-DSA/SPHINCS+ as FIPS 205). The current rotation design, if implemented as Ed25519-only, would be unable to support algorithm migration.

The `did:key` multicodec prefix approach does support different algorithms (each algorithm has its own multicodec identifier), so a `did:key` for Dilithium would use a different prefix than Ed25519. But the code explicitly rejects anything that is not `\xed\x01`.

**Recommendation:**

1. **Short-term**: Change `Literal["Ed25519"]` to `str` with validation against an allowed list: `{"Ed25519", "ML-DSA-65", "SLH-DSA-SHAKE-128s"}`. Same for `CredentialProof.type`.
2. **Medium-term**: Implement a `CryptoSuite` abstraction that handles signing, verification, and key encoding for multiple algorithms. Each suite implements `sign()`, `verify()`, `resolve_public_key()`, and `encode_did()`.
3. **Long-term**: Support hybrid signatures (Ed25519 + Dilithium) during the transition period, following the NIST hybrid approach. Both signatures must be present and valid.
4. Add `MULTICODEC_ML_DSA_65_PUB` and `MULTICODEC_SLH_DSA_PUB` constants to `keys.py` alongside the existing Ed25519 one.
5. The rotation mechanism must explicitly support cross-algorithm rotation: an Ed25519 key can sign a rotation to a Dilithium key.

**References:**
- [NIST Post-Quantum Cryptography Standards](https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards)
- [Post-Quantum Cryptography: What It Is & Why It Matters In 2026](https://www.articsledge.com/post/post-quantum-cryptography-pqc)
- [Hybrid Cryptography for the Post-Quantum Era](https://postquantum.com/post-quantum/hybrid-cryptography-pqc/)
- [Signal Protocol Post-Quantum Ratchets (SPQR)](https://signal.org/blog/spqr/)

---

## Finding 11: No Tombstone / Permanent Deactivation

**Severity: MEDIUM**

**Analysis:**

The current system has `revoke` and `unrevoke` operations (`admin_routes.py` lines 110-129). Revocation is reversible -- an admin can call `POST /admin/unrevoke/{did}` to restore a revoked DID. This conflates two fundamentally different operations:

1. **Temporary suspension** (agent misbehavior, investigation) -- should be reversible
2. **Permanent deactivation** (company shutdown, agent decommissioned, key compromised with no recovery) -- must be irreversible

There is no concept of a "tombstone" -- a permanent, irrevocable deactivation. An attacker who compromises an admin token could `unrevoke` a compromised DID. Similarly, a decommissioned agent's DID could be accidentally unrevoked and then impersonated.

**Recommendation:**

1. Add a `TombstoneMessage` schema:
   ```python
   class TombstoneMessage(BaseModel):
       did: str
       reason: str  # "decommissioned" | "compromised" | "organization_shutdown"
       tombstoned_at: datetime
       signature: SignatureEnvelope  # signed by old key if available, or admin key
       permanent: Literal[True] = True
   ```
2. In `RevocationStore`, add a separate `_tombstoned: set[str]` that is checked before `_revoked` and cannot be cleared by `unrevoke()`.
3. Add `POST /admin/tombstone/{did}` endpoint that requires a separate confirmation parameter (e.g., `?confirm=PERMANENT`).
4. Tombstoned DIDs must be preserved in the audit trail indefinitely.
5. Add tombstone propagation to the Redis Pub/Sub channel recommended in Finding 3.

**References:**
- [W3C DID Core -- Deactivation](https://www.w3.org/TR/did-core/#did-document-metadata) -- defines "deactivated" metadata property
- [KERI Protocol](https://weboftrust.github.io/ietf-keri/draft-ssmith-keri.html) -- distinguishes between rotation events and destruction events

---

## Finding 12: Revocation Store Has No Persistence Across Restarts

**Severity: HIGH**

**Analysis:**

The in-memory `RevocationStore` (`revocation.py` lines 11-49) stores revoked DIDs in a Python `set()`. On process restart, all revocations are lost. A revoked (or rotated-from) DID becomes valid again after a gateway restart.

The `RedisRevocationStore` persists to Redis, but the local cache (`_local_cache`) starts empty on restart. The `sync_cache()` method exists but is never called automatically on startup -- I see no lifecycle hook in `app.py` that calls it.

**Recommendation:**

1. For the in-memory store: persist revocations to a file or LanceDB table on every `revoke()` call, and reload on startup.
2. For the Redis store: call `sync_cache()` in the application startup handler (in `create_app()` lifecycle).
3. For rotation specifically: the revocation of old DIDs after rotation is part of the trust model's correctness guarantee. Loss of revocation state is equivalent to un-doing all rotations.

---

## Finding 13: Audit Trail Does Not Survive Rotation

**Severity: MEDIUM**

**Analysis:**

The `AuditTrail` (`audit/trail.py`) records `actor_did` and `subject_did` as strings. After rotation:
- Searching for an agent's full history requires knowing all their previous DIDs
- There is no `rotation_chain_id` or cross-reference field
- The hash-chained structure makes retroactive field updates impossible (as designed)

**Recommendation:**

1. Add `rotation_chain_id: str | None` to `AuditEntry.detail` for rotation-related events.
2. When a rotation occurs, append a special audit entry: `event_type="did_rotation"` with `detail={"old_did": "...", "new_did": "...", "rotation_chain_id": "..."}`.
3. Implement a query method `get_entries_by_chain(rotation_chain_id)` that returns all entries across all DIDs in a rotation chain.

---

## Finding 14: Verifiable Credentials Become Invalid After Rotation

**Severity: HIGH**

**Analysis:**

VCs issued by an agent (`airlock/crypto/vc.py`) have `issuer` set to the agent's DID and `credential_subject.id` set to the subject's DID. After either party rotates:

1. A VC issued by DID_A (now rotated to DID_B) has `issuer: "did:key:z6Mk_A_..."`. Verifiers will try to resolve DID_A's public key, but DID_A is now on the CRL.
2. The `validate_credential()` function (line 73-108) does not check whether the issuer DID has been rotated (as opposed to revoked for cause). It would reject a VC from a rotated-but-legitimate issuer.
3. VCs cannot be re-issued automatically because only the (old, now destroyed) key can sign them.

**Recommendation:**

1. Distinguish between "revoked for cause" and "rotated" in the revocation store. VCs from a rotated DID should still be valid if: (a) the VC was issued before the rotation, and (b) the rotation chain is intact.
2. Implement VC re-issuance as part of the rotation protocol: the new key signs new VCs with updated issuer DID, with a backreference to the original VC ID.
3. Add a `rotation_chain_id` to the VC metadata so verifiers can trace the issuer's lineage.

---

## Finding 15: No Rotation Event Type in Event System

**Severity: MEDIUM**

**Analysis:**

The event system (`airlock/schemas/events.py`) defines 11 event types but none for key rotation. The `AnyVerificationEvent` union type and the `handle_event()` dispatcher in the orchestrator have no rotation handling.

The closest events are `AgentRevoked` and `AgentUnrevoked`, but these are admin actions, not self-service rotation.

**Recommendation:**

Add to `events.py`:

```python
class KeyRotationRequested(VerificationEvent):
    event_type: Literal["key_rotation_requested"] = "key_rotation_requested"
    old_did: str
    new_did: str
    rotation_payload: KeyRotationPayload

class KeyRotationCompleted(VerificationEvent):
    event_type: Literal["key_rotation_completed"] = "key_rotation_completed"
    old_did: str
    new_did: str
    rotation_chain_id: str

class KeyRotationRejected(VerificationEvent):
    event_type: Literal["key_rotation_rejected"] = "key_rotation_rejected"
    old_did: str
    attempted_new_did: str
    reason: str
```

---

## Finding 16: Delegation Chain Breaks on Rotation

**Severity: HIGH**

**Analysis:**

The delegation system (`_node_validate_delegation` in `orchestrator.py`, lines 668-767) validates:
- Delegator is not revoked
- Delegator trust score >= 0.75
- Credential chain depth is within `max_depth`

The `RevocationStore` also has a cascade mechanism (`register_delegation`, `revoke` in `revocation.py` lines 18-36): revoking a delegator cascades to all delegates.

When a delegator rotates keys:
1. The old DID is revoked, which cascades to ALL delegates
2. The delegates (innocent agents with valid keys) are now revoked
3. The delegation registration uses the old DID, which is now invalid
4. There is no mechanism to re-register delegations under the new DID

**Recommendation:**

1. Rotation must NOT use the same revocation path as "revoked for cause." Implement a `rotation_revoke()` method that marks the old DID as rotated without cascading to delegates.
2. The rotation protocol should include a delegation transfer step: re-register all delegations under the new DID.
3. Add `revocation_reason: str` to the revocation store ("rotation" vs "admin" vs "compromised") to distinguish cascade behavior.

---

## Finding 17: LanceDB Queries Use String Interpolation for DID Lookups

**Severity: MEDIUM**

**Analysis:**

Both `ReputationStore` and `AgentRegistryStore` construct WHERE clauses via string interpolation:

```python
# reputation/store.py line 97
f"agent_did = '{_escape(agent_did)}'"

# registry/agent_store.py line 77
f"did = '{_escape(did)}'"
```

The `_escape()` function (line 204 in `store.py`, line 111 in `agent_store.py`) only escapes single quotes. A DID used as part of a rotation chain could be crafted with SQL-like injection characters. While LanceDB's SQL dialect is limited, this pattern is fragile.

This becomes a security concern during rotation: if rotation introduces a DID alias table with more complex queries, this pattern could become exploitable.

**Recommendation:**

1. Use parameterized queries if LanceDB supports them, or wrap DID values in a validated type that rejects non-alphanumeric characters beyond the `did:key:z6Mk` pattern.
2. The existing `field_validator("did")` on `AgentDID` only checks the prefix -- add a regex that validates the full DID format: `^did:key:z[1-9A-HJ-NP-Za-km-z]+$` (base58btc character set).

---

## Finding 18: No Rotation Endpoint on the Gateway

**Severity: MEDIUM**

**Analysis:**

The gateway routes (`gateway/routes.py`) expose endpoints for handshake, registration, resolve, feedback, revocation check, reputation check, and admin operations. There is no `POST /rotate` or `POST /key-rotation` endpoint.

The admin routes have `POST /admin/revoke/{did}` and `POST /admin/unrevoke/{did}`, but these are admin-initiated, not agent-initiated self-service rotation.

**Recommendation:**

Add the following endpoints:

1. `POST /rotate` -- agent-initiated, signed by old key:
   - Accepts `KeyRotationPayload`
   - Validates signature, sequence number, pre-commitment match
   - Transfers trust score, updates registry, adds old DID to rotation-CRL
   - Returns new DID confirmation with grace period info

2. `POST /rotate/lost-key` -- for lost key recovery:
   - Accepts domain verification proof (DNS TXT record or `.well-known/airlock-did.json`)
   - Drops tier by one level, sets score to new tier's floor
   - Returns new DID with degraded trust state

3. `GET /rotation-chain/{rotation_chain_id}` -- for verifiers:
   - Returns the full chain of DIDs in a rotation lineage
   - Allows relying parties to trace an agent's identity history

---

## Summary Table

| # | Finding | Severity | Status |
|---|---------|----------|--------|
| 1 | DID:key identity discontinuity on rotation | CRITICAL | No mitigation exists |
| 2 | Rotation chain reputation laundering | CRITICAL | No mitigation exists |
| 3 | Race condition during rotation propagation | HIGH | Partial (Redis exists, no Pub/Sub) |
| 4 | Concurrent rotation (fork attack) | HIGH | No mitigation exists |
| 5 | Rotation replay attack | HIGH | Partial (nonce TTL too short) |
| 6 | No pre-rotation / key pre-commitment | HIGH | No mitigation exists |
| 7 | Multi-device agent key coordination | HIGH | No mitigation exists |
| 8 | No rotation frequency limits | MEDIUM | No mitigation exists |
| 9 | Trust vacuum during rotation | MEDIUM | No mitigation exists |
| 10 | Ed25519 to post-quantum migration path | MEDIUM | No mitigation exists |
| 11 | No tombstone / permanent deactivation | MEDIUM | No mitigation exists |
| 12 | Revocation store has no persistence across restarts | HIGH | Partial (Redis option exists) |
| 13 | Audit trail does not survive rotation | MEDIUM | No mitigation exists |
| 14 | Verifiable credentials become invalid after rotation | HIGH | No mitigation exists |
| 15 | No rotation event type in event system | MEDIUM | No mitigation exists |
| 16 | Delegation chain breaks on rotation | HIGH | No mitigation exists |
| 17 | LanceDB queries use string interpolation | MEDIUM | Partial (basic escape exists) |
| 18 | No rotation endpoint on the gateway | MEDIUM | No mitigation exists |

---

## Priority Implementation Order

### Phase 1 -- Foundation (Must-have before any rotation)
1. **Design the `rotation_chain_id` concept** -- a stable UUID per agent identity that persists across all rotations. Add to `AgentProfile`, `TrustScore`, `AuditEntry`.
2. **Create `KeyRotationPayload` schema** with timestamp, nonce, sequence number.
3. **Separate "rotated" from "revoked for cause"** in `RevocationStore`.
4. **Add `POST /rotate` endpoint** with signed-rotation flow.

### Phase 2 -- Hardening
5. **Implement pre-rotation commitment** (KERI-style `next_key_commitment`).
6. **Add rotation frequency limits** and cooldown configuration.
7. **Implement grace period** for overlapping validity during rotation.
8. **Add rotation events** to the event system and audit trail.

### Phase 3 -- Future-Proofing
9. **Implement device key hierarchy** (identity key + device keys).
10. **Add post-quantum algorithm support** via `CryptoSuite` abstraction.
11. **Add tombstone support** as distinct from revocation.
12. **Evaluate `did:web` or `did:peer`** as alternative long-lived DID methods.

---

## Protocol Comparison Matrix

| Feature | Airlock (Current) | KERI | Signal | SSH CA | Keybase |
|---------|-------------------|------|--------|--------|---------|
| Pre-rotation commitment | None | Yes (core design) | N/A | N/A | No |
| Identity continuity across rotation | Broken | Yes (AID) | Yes (identity key) | Yes (CA trust) | Yes (sigchain) |
| Post-compromise recovery | None | Yes (pre-rotation) | Yes (double ratchet) | Yes (CA re-issue) | Yes (device revoke) |
| Multi-device support | None | Partial | Yes (device pre-keys) | Yes (cert per device) | Yes (device keys) |
| Algorithm agility | Ed25519 only | Multi-algo | Multi-algo | Multi-algo | Ed25519 + NaCl |
| Tombstone/deactivation | Reversible revocation | Destruction event | N/A | Cert expiry | Key revoke (permanent) |
| Rotation replay protection | 10min nonce TTL | Sequence numbers | Message counters | Cert validity period | Sigchain sequence |
| Fork resolution | None | First valid event | N/A | CA authority | Sigchain ordering |

---

## References

- [KERI Key Event Receipt Infrastructure (IETF Draft)](https://weboftrust.github.io/ietf-keri/draft-ssmith-keri.html)
- [KERI KID0005 - Next Key Commitment (Pre-Rotation)](https://identity.foundation/keri/kids/kid0005Comment.html)
- [W3C DID Core Specification](https://www.w3.org/TR/did-core/)
- [The did:key Method v0.9](https://w3c-ccg.github.io/did-key-spec/)
- [Peer DID Method Specification](https://identity.foundation/peer-did-method-spec/)
- [Signal Double Ratchet Algorithm](https://signal.org/docs/specifications/doubleratchet/)
- [Signal Post-Quantum Ratchets (SPQR)](https://signal.org/blog/spqr/)
- [Keybase Sigchain Documentation](https://keybase.io/docs/sigchain)
- [Keybase's New Key Model](https://keybase.io/blog/keybase-new-key-model)
- [SSH Key Best Practices for 2025](https://www.brandonchecketts.com/archives/ssh-ed25519-key-best-practices-for-2025)
- [SSH Key Rotation Best Practices](https://www.encryptionconsulting.com/designing-an-effective-ssh-key-rotation-policy/)
- [NIST Post-Quantum Cryptography Standards (FIPS 203/204/205)](https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards)
- [Hybrid Cryptography for the Post-Quantum Era](https://postquantum.com/post-quantum/hybrid-cryptography-pqc/)
- [NCC Group Keybase Protocol Security Review (2019)](https://keybase.io/docs-assets/blog/NCC_Group_Keybase_KB2018_Public_Report_2019-02-27_v1.3.pdf)
