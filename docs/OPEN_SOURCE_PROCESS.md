# Open-Source Readiness: Process, Standards, and Decisions

**Project:** Agentic Airlock — Agent Trust Verification Protocol
**Author:** Shivdeep Singh
**Date:** April 2026
**Version:** 0.1.0

---

## 1. Why This Document Exists

This document explains every governance, security, and quality measure applied to
the Airlock Protocol before public release. It serves as a reference for maintainers,
auditors, and potential adopters who need to understand what was done, why, and how
it aligns with industry standards.

Every item below follows practices established by Linux Foundation (LF), Cloud Native
Computing Foundation (CNCF), and OpenSSF (Open Source Security Foundation) projects.

---

## 2. Governance Framework

### 2.1 What Is Open-Source Governance?

Governance defines how decisions are made, who has authority, and how new contributors
gain trust. Without governance, open-source projects become personality-driven and
fragile. With governance, they become institutions.

### 2.2 Files We Created

| File | Purpose | Standard |
|------|---------|----------|
| `GOVERNANCE.md` | Decision-making process, roles, conflict resolution | LF requirement |
| `MAINTAINERS.md` | Who owns the project, their responsibilities | CNCF requirement |
| `.github/CODEOWNERS` | Auto-assigns code reviewers by directory | GitHub best practice |
| `CODE_OF_CONDUCT.md` | Behavioral expectations for all participants | LF/CNCF requirement |

### 2.3 Governance Model: BDFL

We adopted the **Benevolent Dictator For Life (BDFL)** model — the same model used by
Python (Guido van Rossum) and Linux (Linus Torvalds) in their early years. This means:

- One person (the project creator) has final decision authority
- Decisions use "lazy consensus" — if nobody objects within 72 hours, it passes
- Protocol-level changes require a formal RFC with 14-day comment period
- As the community grows, the model transitions to multi-maintainer consensus

**Why BDFL and not committee?** A v0.1.0 project with one maintainer doesn't need a
committee. Premature democracy creates bureaucracy without contributors. The governance
doc explicitly documents the transition path to consensus-based governance.

### 2.4 Developer Certificate of Origin (DCO)

Every commit to the project must include a `Signed-off-by` line:

```
Signed-off-by: Name <email@example.com>
```

This is a legal mechanism (not a code signing mechanism) that certifies the contributor
has the right to submit the code under the project's license. The Linux Foundation uses
DCO instead of Contributor License Agreements (CLAs) because:

- CLAs require legal review and create friction for contributors
- DCO is per-commit, lightweight, and self-certifying
- DCO is the standard for all LF/CNCF projects

**Enforcement:** A CI job checks every PR commit for the `Signed-off-by` line and
blocks merges if any commit is missing it.

---

## 3. Licensing

### 3.1 License Choice: Apache 2.0

The project uses the **Apache License 2.0**, which:

- Allows commercial use, modification, and distribution
- Includes a patent grant (contributors grant patent rights)
- Requires attribution but not copyleft (unlike GPL)
- Is compatible with most other open-source licenses
- Is the standard license for CNCF and LF AI projects

### 3.2 License Compliance Scanning

A CI workflow scans all Python dependencies and verifies none use licenses incompatible
with Apache 2.0. Specifically, it rejects:

- GPL-3.0 (copyleft, would require Airlock to also be GPL)
- AGPL-3.0 (network copyleft, even stricter)
- SSPL (Server Side Public License, not OSI-approved)

**Why this matters:** If a single dependency uses GPL, the entire project may be
legally required to relicense under GPL. Automated scanning prevents this.

---

## 4. CI/CD Pipeline

### 4.1 What CI/CD Means

**Continuous Integration (CI):** Every code change is automatically tested, linted,
type-checked, and security-scanned before it can be merged.

**Continuous Delivery (CD):** Releases are automated — tagging a version triggers
publishing to PyPI (Python), npm (JavaScript), and GHCR (Docker).

### 4.2 Pipeline Architecture

```
PR opened
  │
  ├── lint job ──────── ruff check (code style)
  │                     ruff format (formatting)
  │                     mypy (type safety)
  │
  ├── security job ──── bandit (Python security linter)
  │                     pip-audit (known vulnerability scan)
  │
  ├── test job ──────── pytest (306+ tests)
  │   (needs lint)      pytest-cov (coverage reporting)
  │
  ├── dco job ───────── Signed-off-by check on all commits
  │
  ├── codeql job ────── GitHub CodeQL SAST (Python + JavaScript)
  │
  ├── trivy job ─────── Container image vulnerability scan
  │
  ├── license job ───── Dependency license compatibility check
  │
  └── docker job ────── Docker image build validation
```

### 4.3 What Each Tool Does

| Tool | Category | What It Catches |
|------|----------|----------------|
| **ruff** | Linter | Code style violations, unused imports, Python anti-patterns |
| **ruff format** | Formatter | Inconsistent indentation, spacing, line length |
| **mypy** | Type checker | Type mismatches, missing return types, unsafe casts |
| **bandit** | Security linter | Hardcoded passwords, insecure crypto, SQL injection patterns |
| **pip-audit** | Vulnerability scanner | Known CVEs in Python dependencies |
| **CodeQL** | SAST | Deep code analysis — injection, XSS, auth bypass patterns |
| **Trivy** | Container scanner | OS-level vulnerabilities in Docker images |
| **pip-licenses** | License checker | GPL/AGPL dependencies incompatible with Apache 2.0 |
| **pytest-cov** | Coverage | Lines of code not exercised by tests |

### 4.4 Why Lint/Type Errors Now Block Merges

Previously, ruff and mypy ran with `continue-on-error: true` — they reported issues
but didn't prevent merging. This was changed because:

- Silent failures create tech debt
- Contributors assume passing CI means code is clean
- LF/CNCF projects require all quality gates to be blocking
- Any reviewer or auditor who sees `continue-on-error` will question seriousness

### 4.5 Token Permission Scoping

The CI workflow explicitly declares `permissions: contents: read` at the top level.
Without this, GitHub Actions defaults to full repository write access for every job.
Scoping permissions follows the **principle of least privilege** — a compromised CI
job cannot push code, create releases, or modify settings.

---

## 5. Security Measures

### 5.1 Static Application Security Testing (SAST)

**CodeQL** runs on every push to main and weekly on a schedule. It performs deep
semantic analysis of Python and JavaScript code, catching:

- SQL injection patterns
- Path traversal vulnerabilities
- Authentication bypass patterns
- Insecure deserialization
- Cross-site scripting (JavaScript SDK)

Results are uploaded to GitHub Security tab as SARIF reports.

### 5.2 Container Security

**Trivy** scans the Docker image for:

- OS-level vulnerabilities (Debian package CVEs)
- Application dependency vulnerabilities
- Misconfigurations (running as root, exposed secrets)

Only CRITICAL and HIGH severity findings are flagged. Results uploaded to GitHub
Security tab.

### 5.3 Software Bill of Materials (SBOM)

Every release automatically generates a **CycloneDX SBOM** — a machine-readable
inventory of every dependency, its version, and its license. SBOMs are attached to
GitHub releases.

**Why SBOM matters:**
- US Executive Order 14028 requires SBOMs for software sold to federal agencies
- NIST SSDF (Secure Software Development Framework) recommends SBOMs
- Enterprise customers increasingly require SBOMs for procurement
- Enables downstream vulnerability tracking (if a dependency has a CVE, every user
  of Airlock can check if they're affected)

### 5.4 Vulnerability Disclosure Process

Documented in `SECURITY.md`:

- **Report to:** security@airlock-protocol.dev
- **Acknowledgement:** within 48 hours
- **Triage:** within 7 days
- **Critical fix:** within 30 days
- **Disclosure:** coordinated, 90-day window
- **Good faith:** reporters who follow the process are protected

---

## 6. Testing Strategy

### 6.1 Test Suite Overview

| Category | Count | What It Covers |
|----------|-------|----------------|
| Unit tests | ~200 | Crypto, schemas, reputation scoring, rate limiting |
| Integration tests | ~80 | Full protocol flows, gateway HTTP, WebSocket, A2A |
| Security tests | ~25 | SSRF protection, DID validation, input sanitization |
| Property-based tests | ~10 | Hypothesis-driven: crypto roundtrips, serialization invariants |
| **Total** | **306+** | |

### 6.2 Property-Based Testing

Traditional tests check specific inputs. Property-based tests (using the Hypothesis
library) generate thousands of random inputs and verify that invariants always hold:

- **Deterministic keys:** Same seed always produces the same DID
- **Signature roundtrips:** Any signed payload verifies with the correct key
- **Wrong key rejection:** Signatures always fail with incorrect keys
- **Canonical serialization:** Dict key order doesn't affect signatures
- **DID format:** All generated DIDs match the `did:key:z...` pattern

**Why this matters:** Crypto bugs are often edge cases that manual tests miss.
Property tests explore the input space exhaustively.

### 6.3 Coverage Reporting

Every CI run generates a coverage report showing which lines of code are exercised
by tests. Coverage artifacts are uploaded and can be integrated with services like
Codecov for trend tracking.

---

## 7. Documentation Standards

### 7.1 Markdown (.md) Files — Why This Format?

All documentation uses Markdown because:

- GitHub renders it natively (no build step required)
- Every developer knows how to read and write it
- It's the universal standard for open-source projects
- LF/CNCF explicitly requires Markdown for governance docs
- It's diffable in git (unlike Word docs or PDFs)

### 7.2 Architecture Decision Records (ADRs)

ADRs document **why** significant technical decisions were made. They live in
`docs/adr/` and follow Michael Nygard's format:

| ADR | Decision | Rationale |
|-----|----------|-----------|
| 001 | Ed25519 for identity/signing | Fast, deterministic, small keys, no NIST curve concerns |
| 002 | Five-phase pipeline | Single responsibility per phase, enables fast-path |
| 003 | Trust scoring with half-life decay | Penalizes bad behavior 3x, prevents gaming, natural expiry |
| 004 | LanceDB for reputation | Zero infrastructure, embedded, future vector similarity |
| 005 | LangGraph orchestrator | State machine with conditional routing, async-native |

**Why ADRs matter:** When a new contributor asks "why Ed25519 and not RSA?" the
answer is documented. Without ADRs, institutional knowledge lives in one person's
head — a bus factor risk.

### 7.3 Protocol Specification

The protocol is formally specified in two documents:

- `docs/PROTOCOL_SPEC.md` — Technical specification
- `docs/draft-airlock-agent-trust-00.md` — IETF Internet-Draft format

The IETF draft follows RFC formatting conventions and can be submitted to
datatracker.ietf.org for standards-track consideration.

---

## 8. Release Process

### 8.1 Artifacts Published

| Artifact | Registry | Trigger |
|----------|----------|---------|
| `airlock-protocol` (Python) | PyPI | GitHub Release |
| `airlock-client` (TypeScript) | npm | GitHub Release |
| `airlock-gateway` (Docker) | GHCR | GitHub Release |
| SBOM (CycloneDX) | GitHub Release assets | GitHub Release |

### 8.2 Publishing Security

- **PyPI:** Uses OIDC trusted publishing — no long-lived API tokens stored in GitHub
- **GHCR:** Uses GITHUB_TOKEN with scoped permissions
- **npm:** Uses NPM_TOKEN secret (required by npm registry)

### 8.3 Versioning

The project follows **Semantic Versioning 2.0.0**:

- `0.x.y` — Pre-1.0, breaking changes allowed between minor versions
- `1.0.0` — Stable API, backward compatibility guaranteed
- Major bump = breaking change, Minor bump = new feature, Patch = bug fix

---

## 9. Community Infrastructure

### 9.1 Issue and PR Templates

Templates standardize how bugs are reported and code is submitted:

- **Bug report:** Steps to reproduce, expected vs actual, environment info
- **Feature request:** Problem statement, proposed solution, alternatives
- **PR checklist:** Tests, lint, type-check, changelog, DCO sign-off

### 9.2 Roadmap

A public `ROADMAP.md` communicates the project's direction. This:

- Sets expectations for contributors about what's planned
- Prevents duplicate work (someone builds what's already planned)
- Signals project health to potential adopters
- Provides a framework for prioritizing contributions

### 9.3 Adopters List

`ADOPTERS.md` tracks organizations using the protocol. This serves as:

- Social proof for new adopters ("if X uses it, it must be reliable")
- Leverage for LF submission ("Y organizations depend on this")
- Feedback channel for real-world deployment issues

---

## 10. Linux Foundation Readiness Assessment

### 10.1 Current Compliance

| Category | Items | Status |
|----------|-------|--------|
| Governance & Legal | 9/9 | Complete |
| CI/CD & Security | 17/17 | Complete |
| Code Quality | 22/23 | 96% (plugin architecture deferred) |
| Documentation | 8/8 | Complete |
| Community | 3/3 | Complete |
| **Overall** | **59/60** | **~97%** |

### 10.2 What Remains Before LF Submission

1. **Community traction** — Multiple external contributors, GitHub stars
2. **Production deployments** — At least one organization running in production
3. **Sponsorship** — At least one organization backing the project
4. **Formal security audit** — Third-party audit of cryptographic implementation

### 10.3 LF Submission Process

1. Identify the right LF sub-foundation (LF AI, OpenSSF, or CNCF)
2. Submit application with governance docs, adoption evidence, technical overview
3. Technical Advisory Committee reviews code, governance, community health
4. If accepted, enter **Sandbox** tier (lowest bar)
5. Graduate through Incubating → Graduated as community grows

---

## 11. What to Watch Out For

### 11.1 Common Mistakes in Open-Source Projects

| Mistake | How We Avoid It |
|---------|----------------|
| No governance → contributor confusion | GOVERNANCE.md with clear roles and process |
| Silent CI failures → tech debt | All quality gates block merges |
| GPL dependency → license contamination | Automated license compliance scanning |
| Secrets in code → breach risk | bandit scanning + env-var-only config |
| No DCO → legal exposure | DCO enforcement in CI |
| No SBOM → supply chain opacity | CycloneDX SBOM on every release |
| No vulnerability process → zero-day chaos | SECURITY.md with SLAs |
| Single maintainer → bus factor | GOVERNANCE.md documents succession path |

### 11.2 Things to Never Commit

| Item | Why |
|------|-----|
| `.env` files | Contains API keys, secrets |
| Internal strategy docs | Maintainer-private |
| Competitive analysis | Not relevant for open-source |
| Personal credentials | Security risk |
| Large binary files | Git is not for binaries |

All of these are in `.gitignore` and verified before every push.

---

## 12. Summary

The Airlock Protocol follows the same governance, security, and quality standards
used by projects like Kubernetes, Prometheus, and Envoy. Every decision is documented,
every quality gate is enforced, and every security measure is automated.

This is not cosmetic — it's the difference between a hobby project and a credible
open standard. When a reviewer at the Linux Foundation, an engineer at Google, or a
CISO at a bank evaluates this project, they will find institutional-grade infrastructure
from day one.

**Total infrastructure:**
- 10 governance/community files
- 8 CI/CD workflows
- 306+ automated tests (unit, integration, security, property-based)
- 5 architecture decision records
- IETF Internet-Draft specification
- Automated security scanning (SAST, container, dependency, license)
- SBOM generation on every release
- DCO enforcement on every contribution
