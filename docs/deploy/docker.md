# Docker Deployment (Docker Compose)

This guide covers Airlock deployment using Docker Compose (Kubernetes or VMs can mirror the same env vars and images).

## What you run

| Component | Role |
|-----------|------|
| **airlock** | FastAPI gateway (`airlock.gateway.app:create_app`) |
| **Redis** | Optional for single pod; **required** for honest multi-replica nonce + rate limits (`AIRLOCK_REDIS_URL`) |

LanceDB files live on a **persistent volume** (`AIRLOCK_LANCEDB_PATH`, default `/app/data/reputation.lance` in Compose).

**LanceDB and replicas (important):** embedded LanceDB is effectively **single-writer**. Do **not** mount the same LanceDB path read/write from multiple active gateway Pods (risk of corruption). For HA: one active Airlock instance with the volume, **or** separate LanceDB + federation via `AIRLOCK_DEFAULT_REGISTRY_URL`, **or** migrate registry/reputation to a remote store. Redis only shares nonce/rate-limit state; it does **not** make LanceDB multi-writer-safe.

## Quick start

```bash
cp .env.example .env
# Edit .env — set AIRLOCK_GATEWAY_SEED_HEX (64 hex characters).
docker compose up --build
```

Compose injects variables from a project **`.env`** file into the `airlock` service (via `${VAR:-defaults}` in `docker-compose.yml`). If `.env` is missing, defaults still run Redis + gateway; the gateway uses a **demo signing key** until you set `AIRLOCK_GATEWAY_SEED_HEX`.

Probes:

- **`GET /live`** — process up (Docker `HEALTHCHECK` uses this).
- **`GET /ready`** — dependencies OK; returns **503** when not safe to receive traffic (or during shutdown).
- **`GET /health`** — detailed JSON (HTTP 200 even when `status` is `degraded`; use for humans/debug).

Metrics: `GET http://localhost:8000/metrics` — when `AIRLOCK_SERVICE_TOKEN` is set, send `Authorization: Bearer <token>` (required for `AIRLOCK_ENV=production`).

## Multi-replica (HA)

1. Point every gateway instance at the **same** `AIRLOCK_REDIS_URL`.
2. Mount the **same** LanceDB storage for registry + reputation, **or** accept per-node registry and use `AIRLOCK_DEFAULT_REGISTRY_URL` for federation (your choice).
3. Put instances behind a TCP/HTTP **load balancer** with health checks on `/health`.

With Compose, **do not** rely on `docker compose --scale airlock=2` while publishing a single host port `8000:8000`: the second container will fail to bind the same host port. Use **one** replica per Compose file on a VM, or run multiple replicas on **Kubernetes / Swarm / ECS** (each task its own IP) or add a reverse proxy that maps to multiple backend ports.

For lab testing two processes on one machine, run a second stack with `AIRLOCK_PUBLISH_PORT=8001` in `.env` and a second project name, or remove `ports` and use an overlay network + LB.

## Environment checklist

| Variable | Deploy setting |
|----------|-----------------|
| `AIRLOCK_ENV` | `development` (default) or **`production`** (fail-fast validation) |
| `AIRLOCK_GATEWAY_SEED_HEX` | **Set** (production); never reuse demo seeds |
| `AIRLOCK_SERVICE_TOKEN` | **Set in production**; bearer for `/metrics` and `/token/introspect` |
| `AIRLOCK_SESSION_VIEW_SECRET` | **Set in production**; short-lived session viewer JWT on handshake ACK |
| `AIRLOCK_PUBLIC_BASE_URL` | HTTPS URL for published A2A agent card (optional; falls back to `AIRLOCK_DEFAULT_GATEWAY_URL`) |
| `AIRLOCK_REDIS_URL` | **Set** when `AIRLOCK_EXPECT_REPLICAS` > 1 in production |
| `AIRLOCK_TRUST_TOKEN_SECRET` | Set if clients need JWT attestations |
| `AIRLOCK_ADMIN_TOKEN` | Optional; enables `/admin/*` |
| `AIRLOCK_LANCEDB_PATH` | Persistent path (Compose volume `/app/data`) |
| `AIRLOCK_CORS_ORIGINS` | Your front-end origins, not `*` in production |
| `AIRLOCK_VC_ISSUER_ALLOWLIST` | **Non-empty in production** (comma-separated issuer DIDs) |
| `AIRLOCK_EXPECT_REPLICAS` | Intended replica count (default `1`) |
| `AIRLOCK_EVENT_BUS_DRAIN_TIMEOUT_SECONDS` | Shutdown drain (default `30`) |

### Alerting (suggested)

Watch **`GET /metrics`** (authenticated): `airlock_event_bus_dead_letters_total`, `airlock_event_bus_queue_depth`, HTTP error rates from `airlock_http_requests_total`. Pair with **`GET /ready`** for load balancer health.

## Image build

The root **Dockerfile** installs `airlock-protocol` with the **`redis`** extra so `AIRLOCK_REDIS_URL` works without another layer.

```bash
docker build -t airlock-gateway:local .
```

### Prebuilt image (GitHub Container Registry)

On a **GitHub Release**, workflow `publish-ghcr.yml` pushes `ghcr.io/<owner>/<repo>:<tag>` and `:latest`. Authenticate if the package is private:

```bash
echo "$GITHUB_TOKEN" | docker login ghcr.io -u USERNAME --password-stdin
docker pull ghcr.io/shivdeep1/airlock-protocol:v0.1.0
```

### Compose: use a GHCR image instead of `build`

Save as `docker-compose.override.yml` next to `docker-compose.yml` (Compose merges it automatically):

```yaml
services:
  airlock:
    image: ghcr.io/shivdeep1/airlock-protocol:${AIRLOCK_IMAGE_TAG:-latest}
    build: !reset null
```

`build: !reset null` (Compose [Compose Specification](https://docs.docker.com/reference/compose-file/build/#reset-value) reset) drops the `build:` section from the base file so Compose does not rebuild locally. Set `AIRLOCK_IMAGE_TAG=v0.1.0` in `.env` to pin a release.

## Verify after deploy

```bash
curl -sSf http://localhost:8000/live
curl -sSf http://localhost:8000/ready
curl -sSf http://localhost:8000/health | jq .
```

Confirm `subsystems.redis` is `true` when Redis is configured (field appears only when `AIRLOCK_REDIS_URL` is non-empty in process—see handler).

## Release artifacts (PyPI / npm)

Public packages are separate from this image: see **[RELEASING.md](../../RELEASING.md)** (PyPI OIDC, npm `NPM_TOKEN`, version bumps).
