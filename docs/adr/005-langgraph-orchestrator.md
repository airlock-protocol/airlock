# ADR 005: LangGraph for Verification Orchestration

**Status:** Accepted

**Date:** 2026-03-25

## Context

The five-phase verification pipeline (ADR 002) requires a state machine with
conditional routing: trusted agents take the fast-path (skip Challenge), while
unknown agents go through the full flow. The orchestrator must handle async
execution, retries, and provide observability into verification state.

Options considered:

- **Manual state machine** — full control but requires implementing retry logic,
  state persistence, and visualization from scratch.
- **Temporal workflows** — production-grade but heavy infrastructure dependency
  (Temporal server + database) for a protocol that targets local-first
  deployment.
- **LangGraph** — lightweight graph-based state machine with built-in async
  support, conditional edges, and LangSmith integration.

## Decision

Use LangGraph with a multi-node verification graph.

Reasons:

- Built-in state management using TypedDict provides type-safe session state
  throughout the verification flow.
- Conditional edges enable clean fast-path routing: a single edge function
  checks the trust score and routes to either Challenge or Verdict.
- Built-in retry and error handling per node, with configurable backoff.
- Visual graph representation aids debugging and protocol documentation.
- LangSmith integration provides production observability (traces, latency
  breakdown per phase) without custom instrumentation.
- Same ecosystem as the LLM-backed semantic challenge (ADR 002, phase 3),
  reducing dependency count.
- Async-native: all nodes are async functions, matching the EventBus and
  FastAPI async architecture.

## Consequences

**Positive:**
- Verification flow is declarative and inspectable as a graph.
- Each node (phase) can be tested in isolation with mock state.
- LangSmith traces provide per-phase latency breakdown in production.
- Adding new verification checks requires adding a node and an edge, not
  restructuring control flow.

**Negative:**
- LangGraph is a runtime dependency that adds weight to the package.
- Graph topology is currently hardcoded; the planned plugin architecture
  (v0.2.0) will need to support dynamic node injection.
- Contributors unfamiliar with LangGraph face a learning curve.
- Graph traversal overhead is measurable but negligible (under 1ms per
  verification).
