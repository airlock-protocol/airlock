# Airlock rollout tracker

**LLM / handoff context:** see [`LLM_HANDOFF.md`](LLM_HANDOFF.md) (narrative + paste message for the next assistant).

Last updated: added **focus + backlog** handoff (production validation first; everything else listed under “Also left”).

## Done (this pass)

| Item | Notes |
|------|--------|
| Gateway identity from env | `AIRLOCK_GATEWAY_SEED_HEX` (64 hex = 32-byte seed); demo seed if unset |
| Nonce replay guard | `(initiator DID, envelope nonce)` deduped in-process; `REPLAY` NACK |
| Rate limiting | Per-IP and per-DID limits on `/handshake`; IP on `/challenge-response`, `/register` |
| Envelope alignment | Handshake requires `envelope.sender_did == initiator.did` |
| Agent registry persistence | LanceDB table `agents`; hydrate on startup; `POST /register` upserts |
| `POST /feedback` | Signed `SignedFeedbackReport` (Ed25519 + nonce) → reputation delta |
| Health depth | `/health` includes `subsystems` (reputation, agent_registry, event_bus) |
| CORS config | `AIRLOCK_CORS_ORIGINS` comma-separated or `*` |
| Low-friction SDK helpers | `airlock.sdk.simple`: `protect`, `build_signed_handshake`, `load_or_create_agent_keypair`, `gateway_url_from_env` |
| `@protect` + Starlette `Request` | JSON body parsed to `HandshakeRequest` before handshake |
| A2A `/a2a/verify` parity | Transport precheck + `VerificationOrchestrator.run_handshake_and_wait`; DEFERRED returns `challenge` payload; signed body requires `envelope` + `signature` |
| Trust tokens (JWT) | On VERIFIED: HS256 JWT in attestation + `/a2a/verify` + A2A metadata; `POST /token/introspect`; `AIRLOCK_TRUST_TOKEN_SECRET` + `AIRLOCK_TRUST_TOKEN_TTL_SECONDS` |
| SessionManager ↔ orchestrator | `POST /handshake` seeds session; orchestrator merges graph snapshots + attestation; `GET /session/{id}` returns `trust_score`, `trust_token`, `challenge_id` |
| Sybil / policy | `AIRLOCK_VC_ISSUER_ALLOWLIST` (CSV DIDs; empty = any issuer); `AIRLOCK_REGISTER_MAX_PER_IP_PER_HOUR` (0 = off); `/a2a/register` rate limits + LanceDB upsert aligned with `POST /register` |
| Global registry delegation | `AIRLOCK_DEFAULT_REGISTRY_URL` — `httpx` client on startup; local miss → `POST {base}/resolve`; response includes `registry_source` (`local` / `remote`) when `found` |
| Structured logs + metrics | `AIRLOCK_LOG_JSON` / `AIRLOCK_LOG_LEVEL`; `airlock.*` JSON lines; per-request access log; `GET /metrics` Prometheus text (`airlock_http_requests_total`) |
| LanceDB open race | Fallback open if `create_table` hits "already exists" |
| Tests | Replay, registry roundtrip, feedback, health fields |
| CI | GitHub Actions: pytest (`.[dev,redis]`) + optional ruff + **Docker image build** + npm build (`airlock-client`, `airlock-mcp`) |
| Production hardening sprint | Shared Redis replay + rate limits (`AIRLOCK_REDIS_URL`); reputation decay-on-read + locked writes; Pydantic bodies on resolve/heartbeat/introspect; `try_publish` + dead-letter count + shutdown drain; VC subject = initiator DID; `/health` depth (queue, DL, uptime, Redis, sessions); RFC 7807 errors; WebSocket `/ws/session/{id}` + TS `watchSession`; optional admin API (`AIRLOCK_ADMIN_TOKEN`) |
| Docker | `Dockerfile` (with `[redis]` + healthcheck); `docker-compose.yml` + `.env.example`; `docs/deploy/docker.md` |
| TypeScript SDK | npm `airlock-client` in `sdks/typescript` — `AirlockClient`, `gatewayUrlFromEnv`, types mirroring REST |
| MCP adapter | `integrations/airlock-mcp` stdio server (`@modelcontextprotocol/sdk`) — tools for health, resolve, session, reputation, metrics, introspect, handshake JSON |
| PyPI / npm automation | `publish-pypi.yml` (OIDC) + `publish-npm.yml` (`NPM_TOKEN`); optional GitHub Environment for approval gates — see `RELEASING.md` |
| GHCR gateway image | `publish-ghcr.yml` — on Release + manual: `ghcr.io/shivdeep1/airlock-protocol:<tag>` — see `RELEASING.md` |
| Dependabot | `.github/dependabot.yml` — weekly PRs for Actions, pip, npm |

## Not done (next passes)

| Priority | Item |
|----------|------|
| P1 | **Production validation smoke** — real stack with `AIRLOCK_ENV=production`, full env checklist, manual `/live` `/ready` `/health` `/metrics` + one handshake/session/WS path (see *Suggested next steps* below) |
| P2 | **Release artifacts** — follow `RELEASING.md`: PyPI OIDC, `NPM_TOKEN`, version bumps, GitHub Release, `publish-pypi.yml` / `publish-npm.yml` / GHCR |
| P3 | Optional: marketing alias publish (`airlock-sdk` re-export) |

## Also left (backlog — not forgotten)

Use this list when the “focus” work is done, or parallelize with Infra/Security. Nothing here blocks coding; it blocks *confidence* or *distribution* until you do it.

1. **Staging / prod smoke (recommended before any public cut)**  
   - Compose or K8s with production env: seed, non-wildcard CORS, issuer allowlist, `AIRLOCK_SERVICE_TOKEN`, `AIRLOCK_SESSION_VIEW_SECRET`, Redis if `AIRLOCK_EXPECT_REPLICAS` > 1.  
   - Verify signed `/feedback` and `/heartbeat`; session poll + WS with `session_view_token`; metrics + introspect with service bearer.  
   - Confirm LanceDB deployment matches **single-writer** policy in `docs/deploy/docker.md`.

2. **Observability in your environment**  
   - Scrape `GET /metrics` (with bearer).  
   - Dashboards + alerts on `airlock_event_bus_dead_letters_total`, `airlock_event_bus_queue_depth`, latency histogram, HTTP status breakdown.  
   - **Optional code follow-ups (plan Phase 4 leftovers):** explicit counters for readiness failures, Redis/LanceDB errors; propagate `request_id` into orchestrator logs (today: access log + `X-Request-ID`).

3. **Release & comms**  
   - Shipped versions on PyPI / npm / GHCR per `RELEASING.md`.  
   - **Release notes** calling out breaking API changes (signed feedback/heartbeat, session `trust_token` gating, authenticated metrics/introspect in production).

4. **Architecture (when you outgrow v1)**  
   - Multi-writer or multi-region: migrate registry/reputation off embedded LanceDB or run **one** active writer + LB; Redis does not make LanceDB HA.

5. **Nice-to-have product/DX**  
   - Stricter TS types for session/health/WS frames; admin client helpers; fewer timing-based tests in CI (`asyncio.sleep` puffiness).  
   - `mypy` in CI: tighten from `continue-on-error` to required when the codebase is ready.

## Env reference (gateway)

- `AIRLOCK_ENV` — `development` (default) or `production` (fail-fast startup validation)
- `AIRLOCK_GATEWAY_SEED_HEX` — required in production (32-byte Ed25519 seed as 64 hex chars)
- `AIRLOCK_SERVICE_TOKEN` — Bearer for `GET /metrics` and `POST /token/introspect` (required in production)
- `AIRLOCK_SESSION_VIEW_SECRET` — HS256 secret for session viewer JWT on handshake ACK; required in production
- `AIRLOCK_PUBLIC_BASE_URL` — public HTTPS base for A2A agent card (`endpoint_url`)
- `AIRLOCK_EXPECT_REPLICAS` — if >1, production requires `AIRLOCK_REDIS_URL`
- `AIRLOCK_EVENT_BUS_DRAIN_TIMEOUT_SECONDS` — graceful shutdown drain timeout (default 30)
- `AIRLOCK_NONCE_REPLAY_TTL_SECONDS` — default 600
- `AIRLOCK_RATE_LIMIT_PER_IP_PER_MINUTE` — default 120
- `AIRLOCK_RATE_LIMIT_HANDSHAKE_PER_DID_PER_MINUTE` — default 30
- `AIRLOCK_CORS_ORIGINS` — e.g. `https://app.example.com` or `*`
- `AIRLOCK_TRUST_TOKEN_SECRET` — HS256 signing secret for JWTs issued on VERIFIED (omit to disable minting)
- `AIRLOCK_TRUST_TOKEN_TTL_SECONDS` — default 600 (min 60, max 86400)
- `AIRLOCK_VC_ISSUER_ALLOWLIST` — comma-separated issuer DIDs; VC must be issued by one of them (empty = allow any)
- `AIRLOCK_REGISTER_MAX_PER_IP_PER_HOUR` — rolling-hour cap on successful `POST /register` and `POST /a2a/register` per IP (0 = unlimited besides per-minute limit)
- `AIRLOCK_DEFAULT_REGISTRY_URL` — optional base URL of another Airlock gateway; `POST /resolve` is retried there when the local registry has no entry (empty = local only)
- `AIRLOCK_REDIS_URL` — optional; enables shared nonce replay + rate limit state across gateway replicas (empty = in-process only)
- `AIRLOCK_ADMIN_TOKEN` — optional Bearer token for `/admin/*`; unset = admin routes not mounted
- `AIRLOCK_LOG_JSON` — set `true` for one JSON object per line on the `airlock` logger tree
- `AIRLOCK_LOG_LEVEL` — default `INFO`

## Env reference (SDK ergonomic)

- `AIRLOCK_GATEWAY_URL` — gateway base URL
- `AIRLOCK_AGENT_SEED_HEX` — 64 hex chars; optional if using key file
- `AIRLOCK_AGENT_KEY_PATH` — default `.airlock/agent_seed.hex` (auto-created)

## Suggested next steps (order)

**Chosen focus (do this first):** **P1 — production validation smoke** — proves the hardened gateway works end-to-end with `AIRLOCK_ENV=production` and real secrets, before you tag releases or point users at it.

1. **Production validation smoke** — Copy `.env.example` → `.env`. Set at minimum: `AIRLOCK_ENV=production`, `AIRLOCK_GATEWAY_SEED_HEX`, `AIRLOCK_CORS_ORIGINS`, `AIRLOCK_VC_ISSUER_ALLOWLIST`, `AIRLOCK_SERVICE_TOKEN`, `AIRLOCK_SESSION_VIEW_SECRET`; add `AIRLOCK_REDIS_URL` if you plan >1 replica. Run `docker compose up --build` (see `docs/deploy/docker.md`). Then: `curl /live`, `curl /ready`, `curl /health`, `curl -H "Authorization: Bearer …" /metrics`; exercise handshake → session token → `GET /session` and optional WebSocket with the same token.
2. **Internal deploy (ongoing)** — Same docs + compose; keep `.env` out of git.
3. **Release (public packages)** — After smoke passes, follow `RELEASING.md`: version bumps, GitHub Release, PyPI/npm/GHCR; optional `airlock-sdk` alias.
4. **Also left (backlog)** — see the **“Also left (backlog)”** section below for observability wiring, release comms, LanceDB scaling, and DX items.

## “Workforce / subagents”

Operational habit: treat roles as **DX**, **Security**, **Infra**, **Research** when prioritizing PRs. This file is the single handoff checkpoint so work can resume after a break.
