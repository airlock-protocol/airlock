# Handoff for future LLM sessions (Agentic Airlock / The Intuition Protocol)

**Use this file when starting a new chat.** Tell the assistant: *“Read `LLM_HANDOFF.md` and `ROLL_OUT_STATUS.md` first.”*

---

## What this project is

**Agentic Airlock** — an open protocol / reference implementation for agent-to-agent **trust verification** (DIDs, Ed25519, VC, reputation, optional LLM challenge). Positioning: “DMARC for AI agents.” Monorepo: Python gateway (`airlock-protocol` on PyPI when published) + npm `airlock-client` + `airlock-mcp` (Model Context Protocol stdio server).

---

## Conversation / work history (high level)

Work happened across multiple Cursor sessions; approximate arc:

1. **Gateway hardening** — env-based gateway identity, nonce replay guard, rate limits, envelope rules, LanceDB agent registry + hydration, feedback, CORS, health subsystems.
2. **SDK & integration** — Python `AirlockClient`, `AirlockMiddleware`, `@protect` + Starlette `Request`, `airlock.sdk.simple` helpers.
3. **A2A** — `/a2a/verify` aligned with orchestrator; agent card, register, verify flows; adapter layer for Google A2A types.
4. **Trust & sessions** — HS256 **trust tokens** on VERIFIED; `POST /token/introspect`; session manager wired to orchestrator; `GET /session/{id}` enriched (`trust_score`, `trust_token`, `challenge_id`).
5. **Policy / sybil** — VC issuer allowlist, per-IP registration caps (hourly + minute limits), A2A register aligned with `POST /register`.
6. **Registry** — optional **`AIRLOCK_DEFAULT_REGISTRY_URL`**: local miss delegates to upstream `POST /resolve`; `registry_source` in response (`local` / `remote`). Implementation: `airlock/registry/remote.py`, wired in `handlers.handle_resolve`.
7. **Observability** — JSON logging for `airlock.*`, access logs, **`GET /metrics`** (Prometheus text), `HttpRequestMetrics` middleware.
8. **TypeScript + MCP** — `sdks/typescript` (`airlock-client`), `integrations/airlock-mcp` (stdio tools). Root `package.json` workspaces; CI builds JS.
9. **Release plumbing** — `RELEASING.md`, `publish-pypi.yml` (OIDC), `publish-npm.yml` (`NPM_TOKEN`).
10. **Planning** — User chose **multi-replica** target and **balanced** priority; a **production hardening** plan was drafted (Redis-backed replay/rate limits, decay-on-read, VC subject binding, event bus resilience, etc.). **The codebase has since incorporated a large “production hardening sprint”** (see `ROLL_OUT_STATUS.md` “Done” table — Redis, decay-on-read, Pydantic bodies, `try_publish`, VC subject binding, RFC 7807 errors, WebSocket session watch, optional admin API, Docker/compose, GHCR, dependabot, etc.). Treat **`ROLL_OUT_STATUS.md` as the source of truth** for what is actually merged today.

---

## What is done (canonical pointer)

**Do not duplicate here long term.** Open:

- **[ROLL_OUT_STATUS.md](ROLL_OUT_STATUS.md)** — full “Done” table, env reference, “Not done”, “Also left (backlog)”, suggested next steps.

High-level snapshot (may drift; trust the file above):

- Gateway REST + A2A routes, orchestrator (LangGraph-style pipeline), reputation (LanceDB), registry (LanceDB), trust JWTs, session APIs, policy knobs, remote resolve delegation, metrics/logs, TS client, MCP server, CI, Docker/compose, publish workflows, GHCR image workflow (per tracker).

---

## What to do next (in order)

Again: **`ROLL_OUT_STATUS.md` § “Suggested next steps”** is authoritative. As of last update of this handoff:

1. **P1 — Production validation smoke** — Real stack with `AIRLOCK_ENV=production`, secrets from `.env.example`, `docker compose`, then exercise `/live`, `/ready`, `/health`, authenticated `/metrics`, handshake → session (and WS if applicable). Details in tracker + `docs/deploy/docker.md`.
2. **P2 — Release artifacts** — `RELEASING.md`: PyPI trusted publishing, `NPM_TOKEN`, version bumps, GitHub Release, run publish workflows + GHCR.
3. **P3 / backlog** — Optional `airlock-sdk` alias; observability dashboards; LanceDB scaling notes; DX/mypy strictness; items under “Also left” in `ROLL_OUT_STATUS.md`.

---

## Key files for implementers

| Area | Paths |
|------|--------|
| Tracker & env | `ROLL_OUT_STATUS.md`, `.env.example` |
| Release | `RELEASING.md`, `.github/workflows/publish-*.yml` |
| Gateway app | `airlock/gateway/app.py`, `routes.py`, `a2a_routes.py`, `handlers.py` |
| Orchestrator | `airlock/engine/orchestrator.py` |
| Sessions | `airlock/engine/state.py` |
| Reputation | `airlock/reputation/store.py`, `scoring.py` |
| Registry | `airlock/registry/agent_store.py`, `remote.py` |
| Config | `airlock/config.py` |
| TS SDK | `sdks/typescript/` |
| MCP | `integrations/airlock-mcp/` |
| Deploy notes | `docs/deploy/docker.md`, `docker-compose.yml`, `Dockerfile` |

---

## Message you can paste to the next LLM

Copy everything inside the block:

```
You are continuing work on “The Intuition Protocol” / Agentic Airlock (Python FastAPI gateway + LanceDB + optional Redis for multi-replica).

Read these files first for ground truth:
1) LLM_HANDOFF.md (repo root) — narrative + pointers
2) ROLL_OUT_STATUS.md — what is done, not done, next steps, env vars

Then follow the user’s task. Prefer small, focused diffs; match existing style; run pytest after Python changes; run `npm run build:js` after TS/MCP changes when relevant.
```

---

## This file

- **Path:** `LLM_HANDOFF.md` (repository root, next to `README.md`).
- **Purpose:** Onboarding + continuity for AI assistants and humans between sessions.
- **Maintenance:** After major milestones, add one line to the “Conversation / work history” section and refresh the “What to do next” bullets only if `ROLL_OUT_STATUS.md` is not enough on its own.
