# Security Policy

The Airlock Protocol takes security seriously. This document outlines supported versions, how to report vulnerabilities, and our disclosure practices.

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | Yes                |
| < 0.1   | No                 |

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Please report vulnerabilities via email to **security@airlock-protocol.dev**.

### What to Include

- Description of the vulnerability and its potential impact
- Steps to reproduce or a proof-of-concept
- Affected version(s) and component(s)
- Any suggested mitigation or fix, if available
- Your preferred attribution name (if you wish to be credited)

### Response Timeline

| Action                          | Timeframe       |
| ------------------------------- | --------------- |
| Acknowledgement of report       | Within 48 hours |
| Initial triage and assessment   | Within 7 days   |
| Fix for critical vulnerabilities | Within 30 days  |

We will keep you informed of progress throughout the process.

## Disclosure Policy

We follow a **coordinated disclosure** model:

- Reporters are asked to allow up to **90 days** from the initial report before public disclosure.
- We will work with reporters to agree on a disclosure date once a fix is available.
- If a fix is released before the 90-day window, we may coordinate an earlier disclosure with the reporter's agreement.
- We will not pursue legal action against researchers who report vulnerabilities in good faith and follow this policy.

## Security Measures

The following security controls are currently implemented in the protocol and gateway:

- **Ed25519 digital signatures** via PyNaCl (libsodium) for all trust verification operations
- **Nonce-based replay protection** to prevent reuse of verification challenges
- **SSRF validation** on all callback URLs before outbound requests
- **LLM prompt injection mitigation** on agent-facing endpoints
- **Rate limiting** enforced per-IP and per-DID to prevent abuse
- **Input validation** on all API endpoints and protocol messages

## Scope

### In Scope

- Airlock protocol specification and cryptographic operations
- Gateway server implementation
- Official SDKs and client libraries
- Authentication and trust verification flows

### Out of Scope

- Third-party dependencies (report these to the respective maintainers)
- Deployment infrastructure and hosting configurations
- Vulnerabilities requiring physical access or social engineering
- Denial-of-service attacks against production deployments

## Recognition

We believe in recognizing the contributions of security researchers. With your permission, we will credit reporters in the release notes of the version containing the fix.

---

This policy is subject to change. Last updated: April 2026.
