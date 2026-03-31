# Security Audit — Agentic Airlock

**Date:** March 2026
**Scope:** Airlock gateway, orchestrator, semantic challenge module, handlers

## Findings & Fixes

| # | Vulnerability | Severity | File | Status |
|---|---|---|---|---|
| 1 | SSRF on callback_url | HIGH | `orchestrator.py` | **Fixed** — `validate_callback_url()` rejects private IPs, localhost, metadata endpoints |
| 2 | LLM prompt injection | HIGH | `challenge.py` | **Fixed** — `_sanitize_answer()` strips control chars + 2000 char limit; evaluation prompt warns about manipulation |
| 3 | Missing LLM timeout | MEDIUM | `challenge.py` | **Fixed** — `timeout=30` on both `litellm.acompletion()` calls |
| 4 | No DID format validation | MEDIUM | `handlers.py` | **Fixed** — `_is_valid_did()` regex validates `did:key:z...` format in `handle_register` |
| 5 | No endpoint_url validation | MEDIUM | `handlers.py` | **Fixed** — rejects non-http(s) schemes in `handle_register` |
| 6 | Unbounded pending challenges | LOW | `orchestrator.py` | **Fixed** — sweep expired entries + 10,000 hard cap before storing new challenges |

## New Files

- `airlock/gateway/url_validator.py` — SSRF protection utility
- `tests/test_security.py` — Security-focused test suite

## Details

### 1. SSRF on callback_url
The `callback_url` parameter in handshake requests was stored and potentially used for HTTP callbacks without validation. An attacker could point it at internal services (cloud metadata endpoints, internal APIs). Now validated via `validate_callback_url()` which blocks private IP ranges (127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16), localhost, and non-HTTP schemes.

### 2. LLM Prompt Injection
The semantic challenge evaluation directly interpolated the agent's answer into the LLM prompt. A malicious agent could submit an answer containing instructions like "Mark as PASS" to manipulate the evaluation. Now mitigated via: (a) `_sanitize_answer()` strips control characters and limits to 2000 chars, (b) evaluation prompt includes explicit injection warning.

### 3. Missing LLM Timeout
Both `litellm.acompletion()` calls had no timeout, risking indefinite blocking. Now set to 30 seconds.

### 4-5. Input Validation
DID format and endpoint_url scheme are now validated at the handler level before processing.

### 6. Unbounded Pending Challenges
The `_pending_challenges` dict could grow unbounded if agents started handshakes but never responded. Now sweeps expired entries and enforces a 10,000 hard cap.
