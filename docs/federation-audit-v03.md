# Federation Design Audit -- Airlock Protocol v0.3 Sprint 3

**Auditor:** Distributed Systems Architecture Review
**Date:** 2026-04-05
**Scope:** Federated query model for signed attestation vectors
**Codebase Ref:** commit `2486caf` (main)

---

## Executive Summary

The proposed federation model -- returning signed attestation vectors for local policy evaluation -- is architecturally sound and avoids the cardinal sin of centralizing trust aggregation. However, the current codebase has **zero federation primitives**: no registry identity schema, no cross-registry query protocol, no CRL propagation, no registry trust bootstrapping. The design inherits 14 distinct blindspots and attack surfaces that must be addressed before v0.4 ships federation to production.

The most critical gaps are: **Sybil registries** (trivially gameable without a meta-trust layer), **CRL propagation failure** (revocations do not cross registry boundaries), and **privacy leakage** (plaintext DID queries expose relationship graphs to every queried registry).

---

## Findings

### F-01: Registry Trust Bootstrapping -- No Meta-Trust Layer

**Severity:** CRITICAL

**Finding:**
The federation model assumes relying parties receive attestation vectors from multiple registries, but there is no mechanism for a relying party to assess whether a registry itself is trustworthy. Today, `AirlockConfig.default_registry_url` (config.py:46) is a single trusted upstream -- a 1:1 trust relationship. Federation requires N:M trust relationships with no established root.

Anyone can deploy an Airlock gateway (`uvicorn airlock.gateway.app:create_app`), register agents via `POST /register` (handlers.py:332-363), and begin issuing attestations with `AirlockAttestation` objects (verdict.py:36-47). The attestation includes `airlock_signature` but no field identifying which registry issued it. There is no `registry_did` field, no registry-level verifiable credential, and no mechanism for a new registry to prove its legitimacy.

The `VerifiableCredential` model (identity.py:57-73) supports issuer DIDs and Ed25519 proofs, but this is used for agent-level VCs only. No equivalent exists at the registry level.

**Impact:**
A malicious operator stands up a registry, self-signs high-trust attestations, and injects them into federated query responses. Without meta-trust, the relying party has no basis to discount these attestations versus ones from a registry that has been operating for two years with 50,000 verified agents.

**Recommendation:**
1. Create a `RegistryIdentity` schema: registry DID (Ed25519), domain binding (DNS TXT record or HTTPS well-known), operator VC, creation timestamp, total agents verified (auditable counter).
2. Implement a registry-level VC that established registries can issue to new registries after a probationary period (similar to how `TrustTier` works for agents but applied at the registry layer).
3. Include `issuer_registry_did` in every `AirlockAttestation` and sign the attestation with the registry's Ed25519 key (not just the gateway instance key from `gateway_seed_hex`).
4. Consider a tiered approach: SEED registries (hardcoded in protocol spec, like DNS root servers) that bootstrap the trust graph.

**References:**
- DNS root server model: 13 root servers operated by independent organizations, hardcoded in resolver hints files
- Certificate Transparency: Google/Apple maintain curated lists of trusted CT logs
- RPKI: Five Regional Internet Registries serve as trust anchors for BGP route origin validation

---

### F-02: Sybil Registries -- Volume-Based Policy Engine Exploitation

**Severity:** CRITICAL

**Finding:**
The federation model returns attestation vectors where each entry is `(issuer_did, issuer_tier, trust_score, signature)`. The relying party's local policy engine weighs these. An attacker creates 100 registries at negligible cost (each is just an Airlock gateway instance), registers the same malicious agent at score 0.95 on all of them, and the attestation vector contains 100 high-confidence entries.

The current `ReputationStore` (store.py) uses LanceDB locally with no cross-registry coordination. Each registry's scoring is entirely independent -- `apply_half_life_decay` (scoring.py:55-97) and `compute_delta` (scoring.py:100-124) operate on local state only. There is nothing preventing an attacker from running `update_score` with synthetic `TrustVerdict.VERIFIED` events to inflate scores artificially on their own registry.

The `AirlockAttestation` model does include `checks_passed` (a list of `CheckResult`), but these are self-reported by each registry. A Sybil registry can claim all checks passed.

**Impact:**
Naive policy engines that count attestations or average scores will be trivially fooled. Even sophisticated engines may struggle to distinguish 100 independent-looking registries from a coordinated Sybil cluster.

**Recommendation:**
1. **Registry age and volume weighting:** Policy engines MUST weight attestations by registry age, total unique agents verified, and verification volume over time. A registry created yesterday with 3 agents should carry near-zero weight.
2. **Infrastructure diversity scoring:** Detect registries sharing IP subnets, ASNs, TLS certificates, or deployment patterns. Registries on the same `/24` subnet get correlated-source discounting.
3. **Stake or bond mechanism:** Require registries to put something at risk (economic bond, organizational identity, domain reputation) to participate in federation. This raises the cost of Sybil attacks from near-zero to non-trivial.
4. **Attestation uniqueness constraint:** Include a hash of the verification session's challenge-response (from `semantic/challenge.py`) in the attestation. A registry that never actually ran the verification pipeline cannot produce this evidence.
5. **Add `verification_evidence_hash` field to `AirlockAttestation`** -- a SHA-256 hash of `(challenge_question, agent_response, llm_evaluation)` proving the semantic challenge was actually executed.

**References:**
- Sybil resistance in peer-to-peer: Douceur (2002), "The Sybil Attack"
- Ethereum proof-of-stake: economic bonding to prevent validator Sybil attacks
- PGP Web of Trust: trust is path-based, not vote-based -- 100 unknown signers carry less weight than 2 well-connected ones

---

### F-03: Registry Collusion -- Mutual Score Inflation

**Severity:** HIGH

**Finding:**
Two registries agree: Registry A vouches for Registry B's agents, Registry B vouches for Registry A's agents. The `SignedFeedbackReport` (reputation.py:43-53) allows any DID to submit positive feedback for any other DID via `POST /feedback` (handlers.py:371-406). The only validation is signature verification -- there is no check that the reporter has ever actually interacted with the subject.

The `FeedbackReport.rating` field (reputation.py:34-39) accepts `"positive"`, `"neutral"`, or `"negative"` with no evidence requirement. A colluding pair of registries can automate cross-feedback to inflate each other's agent scores.

Current scoring uses diminishing returns (`compute_delta` with `diminishing_factor=0.1`), but this only slows inflation -- it does not prevent it. After enough synthetic positive verdicts, any agent reaches the tier ceiling (e.g., `CHALLENGE_VERIFIED` ceiling of 0.70).

**Impact:**
Collusion rings create artificially high-trust enclaves that are difficult to distinguish from legitimately high-trust ecosystems.

**Recommendation:**
1. **Graph analysis on attestation patterns:** Build a bipartite graph of (registry, attested_agent). Detect cliques where two registries exclusively attest each other's agents. Flag mutual-attestation ratios above a threshold (e.g., >80% reciprocal attestations).
2. **Require verification evidence:** Attestations must include proof that the 5-phase pipeline (schema, signature, VC, reputation, semantic) was actually executed -- not just a score. The `checks_passed` field exists but is self-reported. Include verifiable evidence (e.g., the challenge hash, LLM evaluation transcript hash).
3. **Independent auditor role:** Define a protocol role for third-party auditors who can request verification replays. If a registry cannot reproduce its attestation when challenged, its trust is reduced.
4. **Feedback provenance:** Extend `SignedFeedbackReport` to require a `session_id` that maps to a real verification session. The session must exist and be sealed before feedback is accepted. Currently, `session_id` is present but not validated against `SessionManager`.

**References:**
- PageRank (original Google): link farms detected by analyzing link reciprocity and structural anomalies
- EigenTrust (Kamvar et al., 2003): distributed reputation algorithm resistant to collusion through transitive trust normalization
- BGP route leak detection: MANRS initiative uses out-of-band validation to detect coordinated misannouncements

---

### F-04: CRL Propagation Failure Across Registries

**Severity:** CRITICAL

**Finding:**
The current revocation system is entirely local. `RevocationStore` (revocation.py:11-52) is an in-memory set. `RedisRevocationStore` (revocation.py:55-100) extends this to multi-replica deployments via Redis, but only within a single registry's infrastructure. There is no mechanism to propagate revocations across federated registries.

When the orchestrator checks revocation (`_node_check_revocation`, orchestrator.py:566-588), it queries `self._revocation.is_revoked_sync(initiator_did)` -- a purely local check. If Registry A revokes `did:key:z6MkMalicious` and Registry B has a cached attestation at score 0.85 for the same DID, a federated query returns conflicting data: Registry A says revoked, Registry B says trusted.

The `RevocationStore` supports cascade revocation for delegations (`register_delegation` + cascading in `revoke`), but this cascade is local only. A delegation chain crossing registry boundaries has no revocation propagation path.

**Impact:**
Revoked agents can continue operating by routing through registries that have not received the revocation. This is the federation equivalent of a CRL distribution point failure in PKI -- except there are no distribution points defined at all.

**Recommendation:**
1. **Federated CRL endpoint:** Each registry exposes `GET /crl` returning a signed, timestamped list of revoked DIDs. Other registries poll this periodically (e.g., every 5 minutes).
2. **Push-based revocation gossip:** When a registry revokes an agent, it pushes a signed `RevocationNotice` to all known federation peers. This is faster than polling but requires peer discovery.
3. **Attestation freshness field:** Add `max_age_seconds` to attestation vectors. A relying party should re-query if the attestation is older than this value. This bounds the window of stale data.
4. **Include revocation status in attestation:** Each attestation should include `revoked: bool` and `revocation_checked_at: datetime`. The relying party's policy engine can discount attestations where the revocation check is stale.
5. **OCSP-style real-time check:** For high-value interactions, the relying party can query the issuing registry in real-time: "Is DID X still valid as of right now?" This is what OCSP does for TLS certificates.

**References:**
- X.509 CRL Distribution Points (RFC 5280): defined distribution mechanism for certificate revocation
- OCSP (RFC 6960): real-time certificate status checking
- Certificate Transparency SCT: Signed Certificate Timestamps provide freshness guarantees
- Matrix federation: key revocation propagates via `/keys/query` endpoint with server-to-server push

---

### F-05: Federated Query Tail Latency

**Severity:** MEDIUM

**Finding:**
Querying N registries in parallel introduces tail latency proportional to the slowest responder. The current `registry/remote.py` uses `httpx.AsyncClient` with no explicit timeout (defaults to httpx's 5-second timeout). In a federated model querying 10+ registries, a single slow or unresponsive registry blocks the entire response.

The `resolve_remote_profile` function (remote.py:15-40) has basic error handling (`except httpx.HTTPError`) but no circuit breaker, no partial-result semantics, and no deadline propagation.

**Impact:**
P99 latency for federated queries will be dominated by the slowest registry. If federation targets 10 registries and one has 99th percentile latency of 3 seconds, the federated query P99 is 3 seconds regardless of the other 9 responding in 50ms.

**Recommendation:**
1. **Hard deadline with partial results:** Set a federated query deadline (e.g., 2 seconds). Return whatever attestations arrived by the deadline. Include `incomplete: true` and `missing_registries: [...]` in the response so the policy engine knows it has partial data.
2. **Circuit breaker per registry:** Track registry response times and error rates. After N consecutive failures or P95 > threshold, open the circuit breaker and skip that registry for a cooldown period. The existing `rate_limit.py` patterns can be adapted.
3. **Attestation caching with TTL:** Cache remote attestations locally with a configurable TTL (e.g., 5 minutes). Serve from cache when the remote registry is slow. Include `cached: true, cached_at: datetime` in the response.
4. **Priority-weighted fan-out:** Query the most trusted/relevant registries first with a short timeout. Only fan out to additional registries if the initial results are insufficient for the policy engine to make a decision.

**References:**
- "The Tail at Scale" (Dean & Barroso, 2013): hedged requests and tied requests for tail latency mitigation
- DNS resolution: recursive resolvers use aggressive timeouts (2s) and return partial results
- Envoy proxy circuit breaker: configurable outlier detection with automatic ejection and re-admission

---

### F-06: Schema Versioning Across Registries

**Severity:** MEDIUM

**Finding:**
The current protocol version is `"0.1.0"` (config.py:22) and is included in `MessageEnvelope.protocol_version`. However, there is no schema negotiation mechanism. If Registry A runs Airlock v0.3 and Registry B runs v0.4 with new attestation fields (e.g., `verification_evidence_hash`), the v0.3 registry cannot parse the v0.4 response and vice versa.

Pydantic v2 models with `model_config` settings could handle this with `extra="ignore"`, but the current schemas do not set this. A v0.4 attestation with new required fields would cause `ValidationError` on a v0.3 consumer.

The `VerifiableCredential` model (identity.py:57-73) follows W3C conventions with `@context` for extensibility, but `AirlockAttestation` and `TrustScore` do not have equivalent extensibility mechanisms.

**Impact:**
Schema mismatches during rolling upgrades across the federation will cause parsing failures, dropped attestations, and potentially incorrect trust decisions based on incomplete data.

**Recommendation:**
1. **Mandatory `schema_version` field in attestations:** Add `schema_version: str` to `AirlockAttestation`. This is separate from `protocol_version` -- the protocol version covers wire format, the schema version covers attestation structure.
2. **Additive-only schema evolution:** New fields must be optional with sensible defaults. Never remove or rename fields in minor versions. This follows protobuf's backward compatibility rules.
3. **Content negotiation on federated queries:** The querying registry sends `Accept-Schema-Version: 0.3` in the request. The responding registry either downconverts its response or returns `406 Not Acceptable` with its supported versions.
4. **Set `model_config = {"extra": "ignore"}` on all attestation schemas** so that unknown fields from newer versions are silently dropped rather than causing parse errors.
5. **Schema registry:** Publish versioned JSON Schema or Pydantic model definitions at a well-known URL (e.g., `/.well-known/airlock-schemas/v0.3.json`). Registries can discover what schema version a peer supports before querying.

**References:**
- Protocol Buffers: strict backward/forward compatibility rules (never reuse field numbers, new fields must be optional)
- JSON-LD `@context`: extensible schema with graceful degradation for unknown terms
- HTTP Content Negotiation (RFC 7231): `Accept` header for version negotiation
- ActivityPub: uses JSON-LD contexts for schema extensibility across federated instances

---

### F-07: Privacy Leakage in Federated Queries

**Severity:** HIGH

**Finding:**
When a relying party queries "what do you know about `did:key:z6MkAlice`?", every queried registry learns that the relying party is interested in Alice. Over time, this leaks a complete relationship graph: who is interacting with whom.

The current `PrivacyMode` enum (handshake.py:35-45) has `LOCAL_ONLY` and `NO_CHALLENGE` modes, but these control data handling within a single registry -- not cross-registry query privacy. The `handle_resolve` function (handlers.py:145-181) logs the `target_did` in the audit trail (`event_type="agent_resolved"`) for every query.

In federation, the privacy problem compounds: querying 10 registries about Alice means 10 independent parties now know about the interest in Alice.

**Impact:**
Federation becomes a surveillance tool. Registries can build dossiers of who is querying whom, sell this metadata, or use it for competitive intelligence. This is analogous to DNS query privacy before DoH/DoT -- every recursive resolver could observe the full query stream.

**Recommendation:**
1. **Private Information Retrieval (PIR):** Use computational PIR protocols where the registry cannot determine which DID was queried. This is expensive but feasible for small query sets.
2. **Batch/cover-traffic queries:** The relying party queries for K DIDs (K-1 random, 1 real) to provide k-anonymity. The registry cannot distinguish the real query from cover traffic.
3. **Blind attestation tokens:** The relying party sends a blinded DID hash. The registry returns attestations for all DIDs matching the hash prefix (like PIR with bucketing). The relying party unblinds locally.
4. **Query proxies / mix networks:** Route federated queries through an anonymizing proxy so the registry sees the proxy's identity, not the relying party's. This is the Tor model applied to federation queries.
5. **At minimum, do not log queried DIDs in the audit trail when the query comes from a federated peer.** Add a `federated: bool` flag to resolve requests and suppress detailed logging for federated queries.
6. **Differential privacy on query patterns:** Add noise to query timing and batching so that traffic analysis cannot reconstruct relationship graphs even if individual queries are observed.

**References:**
- DNS-over-HTTPS (RFC 8484): encrypts DNS queries to prevent eavesdropping by intermediaries
- Oblivious DNS-over-HTTPS (RFC 9230): separates query source from query content using proxy architecture
- Private Information Retrieval: Chor et al. (1995), computational PIR
- Tor onion routing: multi-hop encrypted relay to prevent traffic analysis

---

### F-08: Economic Incentives for Federation Participation

**Severity:** HIGH

**Finding:**
The current design has no economic model for federation. Running a registry has costs (infrastructure, LLM API calls for semantic challenges via `litellm`, storage). Answering federated queries adds load with no compensation. There is no `pricing` or `billing` concept anywhere in the codebase.

Without incentives, federation faces two failure modes:
1. **No participation:** Registries have no reason to respond to federated queries from peers. They bear the cost, peers get the benefit.
2. **Perverse incentives:** Registries charge per query, creating friction that undermines federation adoption. Or registries inflate scores to attract more agents (and thus more query traffic / revenue).

**Impact:**
Federation will not achieve critical mass without a sustainable economic model. This is the most common reason federated protocols fail -- the technology works but the economics do not.

**Recommendation:**
1. **Reciprocal query model:** Registries that answer federated queries earn "query credits" that they can spend querying other registries. This creates a balanced exchange without monetary transactions. Track credits via a lightweight ledger.
2. **Tiered federation membership:** Free tier gets basic attestation access. Premium tier gets real-time revocation feeds, detailed verification evidence, and priority query handling. This funds registry operators.
3. **Agent-funded model:** Agents pay their home registry a fee. The home registry uses this to fund federation participation. The agent benefits because federation makes their attestation more portable.
4. **Consortium model:** Major registry operators form a consortium with shared costs. This is the model used by credit card networks (Visa, Mastercard) -- competing entities cooperate on shared infrastructure.
5. **Do not build pay-per-query at the protocol level.** This creates a toll-booth federation that nobody will adopt. Instead, make federation participation a requirement for listing in the public registry directory.

**References:**
- Mastodon/ActivityPub: runs on donations and volunteer labor, resulting in uneven federation quality and frequent instance shutdowns
- Email federation: no payment mechanism, but spam economics (cheap to send, expensive to filter) created a tragedy of the commons
- BGP peering: settlement-free peering works because both parties benefit from reachability -- apply this mutual-benefit principle
- Matrix.org Foundation: funded by Element (commercial entity) providing hosting, while protocol remains open

---

### F-09: Split-Brain Scenarios and Convergence

**Severity:** MEDIUM

**Finding:**
Network partitions between registries cause each partition to evolve independently. Registry A and Registry B both verify the same agent during a partition. When they reconnect, they have divergent trust scores for the same DID.

The current `TrustScore` model (reputation.py:13-23) uses `updated_at` timestamps, but there is no vector clock, no CRDT structure, and no merge strategy defined. The `ReputationStore.upsert` (store.py:135-139) uses delete-then-add semantics -- last write wins, which silently discards the other partition's scoring history.

The `apply_half_life_decay` function (scoring.py:55-97) uses `datetime.now(UTC)` for decay calculations, which would produce different results on different registries depending on when they last observed the agent.

**Impact:**
After a partition heals, trust scores are inconsistent across the federation. A relying party querying both registries gets contradictory attestations with no way to determine which is more current or accurate.

**Recommendation:**
1. **Adopt CRDT-based trust scores:** Use a state-based CRDT (Conflict-free Replicated Data Type) for trust scores. Specifically, a G-Counter (grow-only counter) for `interaction_count`, `successful_verifications`, and `failed_verifications`, with the score derived from these counters. CRDTs merge deterministically regardless of partition history.
2. **Include a vector clock or Lamport timestamp** in each `TrustScore` update. When merging post-partition, use the causal ordering to determine which events happened before which.
3. **Additive-merge semantics:** Instead of "last write wins," define merge as: take the union of all verification events from both partitions, re-derive the score from the merged event history. The `AuditTrail` (audit/trail.py) already maintains a hash chain that could serve as the canonical event log for merge.
4. **Accept divergence as a feature:** In the "trust is subjective" model, different registries having different scores for the same agent is acceptable. The relying party's policy engine handles the divergence. Document this explicitly as a design principle.

**References:**
- CRDTs: Shapiro et al. (2011), "Conflict-Free Replicated Data Types"
- Amazon DynamoDB: uses vector clocks for conflict detection with application-level resolution
- Git: content-addressed DAG with three-way merge -- divergent histories are normal and resolved explicitly
- CAP theorem (Brewer, 2000): federation inherently chooses AP (availability + partition tolerance), accepting eventual consistency

---

### F-10: Governance Model for Federation Rules

**Severity:** HIGH

**Finding:**
There is no governance model defined for federation decisions: who can join, who gets removed, how rules change, how disputes are resolved. The current codebase has `admin_token` (config.py:61) for single-gateway administration and `vc_issuer_allowlist` (config.py:53) for VC issuer control, but these are per-instance settings with no federation-wide equivalent.

Key governance questions with no answers:
- Who decides the minimum schema version for federation?
- Who removes a compromised or malicious registry from the federation?
- How are disputes between registries resolved?
- Who updates the scoring parameters (`TIER_CEILINGS`, `HALF_LIFE_DAYS`, etc.) that affect federation-wide trust comparability?
- How are breaking protocol changes ratified?

**Impact:**
Without governance, federation devolves into either anarchy (anyone can join, rules are unenforceable) or centralization (Airlock Inc. makes all decisions, defeating the purpose of federation).

**Recommendation:**
1. **Multi-stakeholder governance body:** Form a Technical Steering Committee (TSC) with representatives from major registry operators, agent developers, and relying parties. Decisions require supermajority (e.g., 2/3).
2. **RFC-style protocol evolution:** All federation rule changes go through a public RFC process with a comment period. This is how IETF evolves internet standards and how Rust evolves its language.
3. **Automated enforcement via smart contracts or signed policy documents:** Federation rules are published as machine-readable policy documents signed by the governance body. Registries that violate the policy can be automatically flagged.
4. **Emergency revocation mechanism:** A quorum of N-of-M trusted registries can issue an emergency revocation of a rogue registry without waiting for a full governance vote. This is analogous to CA/Browser Forum's incident response process.
5. **Start simple:** For v0.4, use a curated allowlist of founding registries (maintained in the protocol spec). Formalize governance before the federation grows beyond the founding members.

**References:**
- IETF RFC process: rough consensus and running code, open participation, public review
- W3C governance: working groups with formal consensus process, royalty-free IP policy
- CA/Browser Forum: membership requires auditing, voting rules for policy changes
- Linux Foundation governance: Technical Advisory Board + corporate membership tiers
- Mastodon: no formal governance, leading to inconsistent moderation and instance-level policy fragmentation (cautionary tale)

---

### F-11: Missing Registry DID in Attestation Schema

**Severity:** HIGH

**Finding:**
The `AirlockAttestation` model (verdict.py:36-47) contains `verified_did` (the agent) and `airlock_signature` (the signing gateway's signature), but no field identifying which registry issued the attestation. The `trust_token` JWT (trust_jwt.py:11-33) includes `iss` (issuer DID) but this is the gateway instance DID from `gateway_seed_hex`, not a stable registry identity.

In federation, the relying party needs to know: "Registry X, operating at registry.example.com, with DID did:key:z6MkRegistry, attests that agent did:key:z6MkAgent has trust score 0.82." The current schema only conveys: "Some gateway instance attests that agent did:key:z6MkAgent has trust score 0.82."

**Impact:**
Without a registry identity in attestations, the relying party cannot implement registry-level trust weighting, cannot detect Sybil registries (F-02), and cannot route revocation queries back to the issuing registry (F-04).

**Recommendation:**
Add to `AirlockAttestation`:
```python
registry_did: str          # Stable DID of the issuing registry
registry_domain: str       # DNS domain of the registry (for domain binding)
registry_attestation_seq: int  # Monotonic sequence number (for ordering)
```
Sign the attestation with the registry's long-lived Ed25519 key (not the ephemeral gateway instance key). This allows relying parties to verify attestation provenance.

---

### F-12: Replay Attacks on Federated Attestations

**Severity:** MEDIUM

**Finding:**
The current nonce replay protection (envelope.py `generate_nonce()`, checked via `nonce_guard.check_and_remember` in handlers.py) operates per-gateway. Federated attestations, once signed and delivered, have no replay protection in the cross-registry context.

An attacker intercepts a legitimate attestation from Registry A for `did:key:z6MkAlice` at score 0.90 (captured at time T). Alice's score later drops to 0.40 on Registry A due to failed verifications. The attacker replays the old attestation from time T, which still has a valid signature.

The `AirlockAttestation` includes `issued_at: datetime` but relying parties may not enforce freshness. The `trust_token` JWT has `exp` (expiry) but the attestation itself does not have an explicit expiry.

**Impact:**
Stale attestations can be replayed to present outdated trust scores, undermining the integrity of federated trust decisions.

**Recommendation:**
1. Add `expires_at: datetime` to `AirlockAttestation` with a short TTL (e.g., 10 minutes for real-time queries, 1 hour for cached results).
2. Add a monotonically increasing `sequence_number` per (registry, agent) pair. Relying parties reject attestations with sequence numbers lower than the highest they have seen.
3. Include the querier's nonce in the attestation response (challenge-response freshness). The querier sends a random nonce, the registry includes it in the signed attestation, proving the attestation was generated for this specific query.

**References:**
- OCSP nonce (RFC 6960): querier includes nonce, responder signs it into the response
- Kerberos ticket expiry: tickets have bounded lifetime to prevent replay
- TLS session tickets: bound to connection parameters to prevent cross-connection replay

---

### F-13: No Discovery Protocol for Federation Peers

**Severity:** MEDIUM

**Finding:**
There is no mechanism for registries to discover each other. The current `default_registry_url` config (config.py:46) is a single hardcoded URL. Federation requires dynamic peer discovery: new registries joining, existing registries going offline, registry endpoints changing.

There is no `GET /.well-known/airlock-federation` endpoint, no DNS-SD service discovery, and no gossip protocol for peer advertisement.

**Impact:**
Without discovery, federation requires manual configuration of every peer URL on every registry. This does not scale beyond a handful of registries and makes the federation brittle to endpoint changes.

**Recommendation:**
1. **Well-known endpoint:** `GET /.well-known/airlock-registry.json` returns the registry's identity (DID, domain, supported schema versions, federation status, peer list).
2. **DNS-based discovery:** `_airlock._tcp.example.com` SRV records point to registry endpoints. TXT records contain the registry DID. This leverages existing DNS infrastructure.
3. **Gossip-based peer discovery:** Each registry maintains a peer list. When a registry learns about a new peer, it propagates this to its existing peers (with TTL to prevent infinite propagation). This is how BitTorrent DHT and Kademlia work.
4. **Central directory (bootstrapping only):** Maintain a signed, versioned registry directory at `api.airlock.ing/federation/peers`. New registries consult this to bootstrap, then switch to gossip for ongoing discovery. The directory is a convenience, not a single point of failure.

**References:**
- DNS-SD (RFC 6763): service discovery via DNS
- Matrix server discovery: `.well-known/matrix/server` for federation endpoint resolution
- ActivityPub WebFinger: `/.well-known/webfinger` for actor discovery across instances
- Consul/etcd: service registration and health-checked discovery in microservices

---

### F-14: Attestation Vector Size and DoS

**Severity:** LOW

**Finding:**
As federation grows, attestation vectors grow unbounded. If 500 registries exist and a relying party queries all of them, the attestation vector for a single agent could contain 500 signed entries. Each `AirlockAttestation` with `checks_passed` (list of `CheckResult`) could be several KB. At scale, this becomes a bandwidth and parsing concern.

A malicious registry could also return an inflated attestation with thousands of fabricated `CheckResult` entries in `checks_passed`, consuming relying party resources.

**Impact:**
Resource exhaustion on relying parties processing large attestation vectors. Potential for amplification attacks where a small query produces a large response.

**Recommendation:**
1. Set maximum limits: `max_attestations_per_query: int = 50`, `max_checks_per_attestation: int = 20`.
2. Registries paginate responses. The first page contains the most relevant (highest-confidence) attestations.
3. Relying parties set a response size limit (e.g., 1MB) and reject responses exceeding it.
4. Consider a summary mode: instead of full attestation vectors, return `(registry_did, score, issued_at, signature)` tuples. The relying party can request full attestation details for specific registries of interest.

---

### F-15: Time Synchronization Dependency

**Severity:** LOW

**Finding:**
The trust scoring system depends heavily on accurate timestamps. `apply_half_life_decay` (scoring.py:55-97) uses `datetime.now(UTC)` and computes `elapsed_days` from `score.last_interaction`. `VerifiableCredential.is_expired()` (identity.py:72-73) compares `expiration_date` against `datetime.now(UTC)`. Federated attestations include `issued_at`.

If a registry's clock is skewed, its decay calculations produce incorrect scores, its attestation timestamps are unreliable, and credential expiry checks may fail.

**Impact:**
Clock skew between registries leads to inconsistent trust scores and incorrect freshness assessments. An attacker with a clock-skewed registry could produce attestations with future timestamps that appear "fresher" than they should.

**Recommendation:**
1. Require NTP synchronization for all federation participants. Include a clock skew check in the federation health handshake.
2. Reject attestations with `issued_at` in the future (with a small tolerance, e.g., 30 seconds for NTP jitter).
3. Log clock skew warnings when processing attestations from registries whose timestamps consistently differ from the local clock.

---

## Lessons from Real-World Federation Models

| System | Model | Key Lesson for Airlock |
|--------|-------|----------------------|
| **DNS** | Hierarchical (root -> TLD -> authoritative) | Trust anchors (root servers) bootstrap the system. Caching with TTL handles latency. DNSSEC adds cryptographic verification. Airlock needs equivalent trust anchors (F-01) and caching (F-05). |
| **BGP** | Peer-to-peer, trust-on-first-use | BGP has no authentication by default, leading to route hijacks. RPKI adds cryptographic origin validation. Airlock must not repeat BGP's mistake of trusting unauthenticated announcements (F-02). |
| **Certificate Transparency** | Append-only public logs | CT logs are auditable -- anyone can verify that a CA is behaving honestly. Airlock's `AuditTrail` (audit/trail.py) has the right structure but is local-only. Federation needs cross-registry audit log verification (F-03). |
| **ActivityPub/Mastodon** | Open federation, instance-level moderation | Mastodon shows that open federation without governance leads to moderation nightmares. Instance blocklists are the only enforcement tool. Airlock needs stronger governance (F-10) and Sybil resistance (F-02). |
| **Matrix** | Federated messaging with DAG-based state resolution | Matrix uses a DAG (directed acyclic graph) for event ordering and state resolution across servers. This handles split-brain elegantly. Airlock should study Matrix's state resolution algorithm for trust score convergence (F-09). |
| **Email (SMTP)** | Open federation, reputation-based filtering | Email federation "works" but is dominated by a few large providers. Spam economics created a tragedy of the commons. Airlock must solve economic incentives (F-08) before federation reaches email-scale. |
| **RPKI** | Hierarchical trust anchored to RIRs | RPKI solves BGP's authentication problem by anchoring trust to Regional Internet Registries. Deployment is slow (~40% adoption after 10+ years). Airlock should plan for gradual federation adoption. |

---

## Priority Matrix

| Priority | Finding | Severity | Effort | Must-Have for v0.3 Schema |
|----------|---------|----------|--------|--------------------------|
| **P0** | F-01: Registry trust bootstrapping | CRITICAL | High | Yes -- `RegistryIdentity` schema |
| **P0** | F-02: Sybil registries | CRITICAL | High | Yes -- `verification_evidence_hash` in attestation |
| **P0** | F-04: CRL propagation | CRITICAL | Medium | Yes -- `revoked` + `revocation_checked_at` in attestation |
| **P0** | F-11: Missing registry DID | HIGH | Low | Yes -- `registry_did` + `registry_domain` in attestation |
| **P1** | F-03: Registry collusion | HIGH | High | Partial -- session_id validation on feedback |
| **P1** | F-07: Privacy leakage | HIGH | High | Partial -- `federated: bool` flag on queries |
| **P1** | F-08: Economic incentives | HIGH | Medium | No -- design doc needed before implementation |
| **P1** | F-10: Governance | HIGH | Medium | No -- TSC formation is organizational, not technical |
| **P1** | F-12: Attestation replay | MEDIUM | Low | Yes -- `expires_at` + `sequence_number` in attestation |
| **P2** | F-05: Tail latency | MEDIUM | Medium | No -- implementation concern, not schema |
| **P2** | F-06: Schema versioning | MEDIUM | Low | Yes -- `schema_version` in attestation |
| **P2** | F-09: Split-brain | MEDIUM | High | No -- CRDT design is complex, defer to v0.4 |
| **P2** | F-13: Peer discovery | MEDIUM | Medium | Partial -- `.well-known` endpoint spec |
| **P3** | F-14: Vector size / DoS | LOW | Low | Yes -- max limits in protocol spec |
| **P3** | F-15: Time synchronization | LOW | Low | Yes -- clock skew tolerance in spec |

---

## Recommended Schema Additions for v0.3 Sprint 3

Based on the audit, the following fields should be added to the attestation schema now to avoid breaking changes when federation ships in v0.4:

```python
class AirlockAttestation(BaseModel):
    # ... existing fields ...

    # Federation fields (v0.3 -- reserved, optional)
    schema_version: str = "0.3.0"
    registry_did: str | None = None           # F-11: Issuing registry identity
    registry_domain: str | None = None        # F-11: DNS-bound registry domain
    registry_attestation_seq: int | None = None  # F-11: Monotonic ordering
    expires_at: datetime | None = None        # F-12: Attestation expiry
    revoked: bool = False                     # F-04: Current revocation status
    revocation_checked_at: datetime | None = None  # F-04: Freshness of revocation check
    verification_evidence_hash: str | None = None  # F-02: SHA-256 of challenge evidence
```

```python
class RegistryIdentity(BaseModel):
    """Identity and metadata for a federated Airlock registry."""

    registry_did: str                         # F-01: Stable Ed25519 DID
    domain: str                               # F-01: DNS domain
    operator_name: str                        # F-01: Human-readable operator
    operator_vc: VerifiableCredential | None = None  # F-01: Operator credential
    created_at: datetime                      # F-02: Age for Sybil resistance
    total_agents_verified: int = 0            # F-02: Volume for weighting
    schema_versions_supported: list[str] = ["0.3.0"]  # F-06
    federation_endpoint: str | None = None    # F-13: Discovery
    crl_endpoint: str | None = None           # F-04: CRL distribution
    public_key_multibase: str                 # Crypto verification
```

These additions are all optional fields with defaults, maintaining backward compatibility with existing v0.2 clients.
