# ADR 003: Trust Scoring with Half-Life Decay

**Status:** Accepted

**Date:** 2026-03-20

## Context

The protocol requires a trust score that rewards consistent good behavior,
penalizes bad behavior asymmetrically, and naturally degrades stale trust.
The model must be simple enough to reason about yet resistant to gaming.

Options considered:

- **Binary trust (yes/no)** — too coarse; no gradation between first-time and
  long-established agents.
- **Linear scoring** — simple increments/decrements, but no natural decay and
  trivially farmable.
- **Exponential decay with diminishing returns** — continuous score with
  time-based decay and asymmetric penalties.

## Decision

Continuous trust score on [0.0, 1.0] with 30-day half-life decay.

- **Initial score:** 0.5 (neutral).
- **Verified:** +0.05 with diminishing returns: `+0.05 / (1 + count * 0.1)`.
- **Rejected:** -0.15 (fixed penalty).
- **Deferred:** -0.02 (small nudge; ambiguity is a weak negative signal).
- **Decay:** `score_effective = 0.5 + (score - 0.5) * 2^(-days_elapsed / 30)`.
- **Fast-path threshold:** 0.75 (agents above this skip semantic challenge).
- **Blacklist threshold:** 0.15 (agents below this are rejected immediately).

Reasons:

- Diminishing returns prevent trust farming: each successive verification yields
  less score gain, making it uneconomical to inflate trust artificially.
- Asymmetric penalties (rejection costs 3x a verification gain) make attacks
  expensive. A single rejection erases approximately three successful
  verifications.
- Half-life decay ensures dormant agents gradually return to "unknown" (0.5)
  rather than retaining stale trust indefinitely.
- The model mirrors real-world reputation: trust is hard to build, easy to lose,
  and fades without ongoing interaction.

## Consequences

**Positive:**
- Agents must maintain ongoing positive interactions to retain fast-path status.
- Attack cost is quantifiable: reaching 0.75 from 0.5 requires approximately
  8-10 consecutive verifications with no rejections.
- Recovery from a single rejection requires approximately 3 successful
  verifications, creating a meaningful deterrent.

**Negative:**
- Score can never reach exactly 1.0 due to diminishing returns.
- New agents always start at 0.5 regardless of external reputation.
- The 30-day half-life is a tuning parameter that may need adjustment for
  different deployment contexts.
