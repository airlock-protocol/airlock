# airlock-mcp

[Model Context Protocol](https://modelcontextprotocol.io/) (stdio) server that wraps the Airlock gateway REST API. Use it from MCP-compatible hosts (Claude Desktop, Cursor, etc.).

## Tools

| Tool | Maps to |
|------|---------|
| `airlock_health` | `GET /health` (subsystems, queue depth, optional Redis, etc.) |
| `airlock_resolve` | `POST /resolve` |
| `airlock_reputation` | `GET /reputation/{did}` |
| `airlock_session` | `GET /session/{id}` (optional `session_view_token` from handshake ACK) |
| `airlock_feedback` | `POST /feedback` (signed JSON string from Python SDK) |
| `airlock_metrics` | `GET /metrics` (requires `AIRLOCK_SERVICE_TOKEN` when gateway enforces it) |
| `airlock_introspect_trust_token` | `POST /token/introspect` (same bearer as metrics when enforced) |
| `airlock_handshake` | `POST /handshake` (pass JSON string built/signed elsewhere) |

## Environment

- `AIRLOCK_GATEWAY_URL` — gateway base URL (default `http://127.0.0.1:8000`)
- `AIRLOCK_SERVICE_TOKEN` — Bearer for `airlock_metrics` and `airlock_introspect_trust_token` when the gateway has `AIRLOCK_SERVICE_TOKEN` set (always in production)

## Build

From repository root:

```bash
npm install
npm run build:mcp
```

Run locally:

```bash
node integrations/airlock-mcp/dist/index.js
```

## Cursor / Claude Desktop (example)

Add a stdio server entry pointing at `airlock-mcp` (or `node /absolute/path/to/integrations/airlock-mcp/dist/index.js`) with `AIRLOCK_GATEWAY_URL` in `env`.
