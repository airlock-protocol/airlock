# ADR 002: Five-Phase Verification Pipeline

**Status:** Accepted

**Date:** 2026-03-15

## Context

The protocol needs a structured verification flow that is both thorough for
unknown agents and fast for trusted ones. The flow must map cleanly to a state
machine for implementation and observability.

Options considered:

- **Single-step verify** — simple but no separation of concerns; difficult to
  short-circuit for trusted agents.
- **Three-phase (identity / challenge / verdict)** — better, but conflates
  identity resolution with handshake and omits the cryptographic seal.
- **Five-phase (Resolve, Handshake, Challenge, Verdict, Seal)** — each phase
  has a single responsibility with well-defined inputs and outputs.

## Decision

Adopt five discrete verification phases: Resolve, Handshake, Challenge, Verdict,
Seal.

Reasons:

- **Resolve** separates identity lookup from verification logic. The gateway can
  cache resolution results independently.
- **Handshake** establishes a cryptographic channel with signature verification
  at transport time (invalid signatures are NACK'd before any further processing).
- **Challenge** is conditional: only fires for agents with trust scores in the
  unknown zone (0.15-0.75). Trusted agents skip it entirely.
- **Verdict** is the trust decision, isolated from transport and challenge logic.
- **Seal** produces the cryptographic receipt (SessionSeal) that both parties
  can independently verify.
- The fast-path (score >= 0.75) skips Challenge and proceeds directly from
  Handshake to Verdict, keeping latency under 1ms for known agents.
- Each phase maps to a LangGraph node, making the flow inspectable and testable.

## Consequences

**Positive:**
- Clear separation of concerns; each phase is independently testable.
- Fast-path makes 95%+ of repeat verifications sub-millisecond.
- Protocol phases map directly to audit log entries.
- Easy to extend individual phases without affecting others.

**Negative:**
- More protocol complexity than a simpler two- or three-phase model.
- Five network round-trips in the worst case (mitigated by fast-path).
- Contributors must understand the full pipeline to reason about edge cases.
