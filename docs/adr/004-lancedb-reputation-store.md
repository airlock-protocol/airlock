# ADR 004: LanceDB for Reputation Storage

**Status:** Accepted

**Date:** 2026-03-20

## Context

The protocol needs persistent storage for agent reputation data (trust scores,
interaction counts, timestamps). The store must support exact lookups by DID
and potential future vector similarity queries for agent behavior analysis.

Options considered:

- **SQLite** — embedded and mature, but no native vector support and limited
  analytical query performance.
- **PostgreSQL** — full-featured but requires external server infrastructure,
  connection pooling, and operational overhead.
- **Redis** — fast for key-value lookups but volatile by default; persistence
  modes add complexity.
- **LanceDB** — embedded columnar store with native vector support, zero
  infrastructure requirements.

## Decision

Use LanceDB (embedded mode) for reputation storage.

Reasons:

- Zero infrastructure: embedded and serverless, no connection pooling or
  external processes required.
- Lance columnar format provides fast analytical queries over trust score
  distributions and historical data.
- Native vector similarity support enables future use cases such as agent
  behavior embeddings and anomaly detection.
- No connection pooling overhead; direct file-based access.
- Migration path to LanceDB Cloud available for multi-node deployments.
- Apache 2.0 licensed, consistent with the project license.

## Consequences

**Positive:**
- The entire stack runs on a single machine with no external dependencies.
- Columnar format is efficient for the read-heavy, append-mostly reputation
  workload.
- Vector similarity is available without adding a separate vector database.

**Negative:**
- Single active writer limitation: only one process can write at a time
  (acceptable for v0.1.0 single-gateway deployments).
- No built-in replication; Redis is used for multi-replica coordination where
  needed.
- SQL dialect is limited to simple WHERE clauses; complex joins require
  application-level logic.
- Migration to PostgreSQL is documented as a contingency if query complexity
  or write concurrency demands increase.
