# Governance

## Overview

The Airlock Protocol project follows a **Benevolent Dictator For Life (BDFL)** governance
model. As the community grows, the project will transition toward consensus-based
decision-making with broader maintainer representation.

## Roles

### BDFL

The BDFL has final authority on all project decisions, including releases, protocol
changes, and maintainer appointments.

**Current BDFL:** Shivdeep Singh ([@shivdeep1](https://github.com/shivdeep1))

### Maintainer

- Full commit access to all repositories
- Release authority (tagging, publishing)
- Ability to merge pull requests
- Responsible for upholding code quality and project direction

### Reviewer

- Trusted community member with review rights
- Can approve pull requests (maintainer merge still required)
- Nominated by a maintainer, approved by the BDFL

### Contributor

- Anyone who submits a pull request, files an issue, or improves documentation
- All contributions are subject to the project's license and DCO requirements

## Decision Making

- **Minor changes** (bug fixes, small improvements): Lazy consensus. If no objections
  are raised within 72 hours of a PR being opened, a maintainer may merge.
- **Protocol changes** (wire format, cryptographic algorithms, trust model): Require an
  RFC filed as a GitHub issue, a minimum 14-day comment period, and maintainer approval.
- **Releases**: Require explicit maintainer approval and passing CI.

## Becoming a Maintainer

1. Demonstrate sustained, high-quality contributions over a meaningful period.
2. Be nominated by an existing maintainer.
3. Receive approval from the BDFL.

There is no fixed contribution count or timeline. Quality, consistency, and alignment
with project goals matter more than volume.

## Conflict Resolution

1. Discussion on the relevant GitHub issue or pull request.
2. If unresolved, maintainers vote (simple majority).
3. If tied, the BDFL casts the deciding vote.

## Code of Conduct

All participants are expected to follow the project's Code of Conduct.
See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) for details.

Enforcement actions are taken by maintainers and may be escalated to the BDFL.

## Amendments

This governance document may be amended through the same RFC process used for
protocol changes.
