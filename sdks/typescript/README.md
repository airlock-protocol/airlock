# airlock-client (TypeScript)

HTTP client for the **Agentic Airlock** gateway. Aligns with the Python [`airlock.sdk.client.AirlockClient`](../../airlock/sdk/client.py): same REST surface (signed `/heartbeat` / `/feedback`, optional `serviceToken` for metrics + introspect, session viewer token on poll + WebSocket).

## Install

From this monorepo (workspace):

```bash
npm install ../sdks/typescript
```

When published to npm, the package name will be **`airlock-client`** (PyPI remains `airlock-protocol` for the Python stack).

## Usage

```typescript
import { AirlockClient, gatewayUrlFromEnv } from "airlock-client";

const client = new AirlockClient(gatewayUrlFromEnv());
const h = await client.health();
const r = await client.resolve("did:key:z6Mk...");
```

### Session updates (WebSocket)

`watchSession(sessionId, { sessionViewToken })` opens a **`WebSocket`** to `/ws/session/...?token=...` (or pass the handshake’s `session_view_token` when the gateway uses `AIRLOCK_SESSION_VIEW_SECRET`). Requires a **`WebSocket`** global (browsers; **Node.js 22+** includes it; older Node can use a polyfill or stick to polling `getSession` with the same bearer).

```typescript
for await (const msg of client.watchSession(sessionId)) {
  if (msg.type === "session") console.log(msg.payload);
}
```

### Handshakes and signing

Building and signing a `HandshakeRequest` must match the gateway’s canonical JSON (Pydantic `model_dump(mode="json")`). Until a native TS signer is proven byte-for-byte compatible, **use the Python SDK** to construct signed handshakes (`build_signed_handshake`), then POST the JSON with:

```typescript
const ack = await client.handshake(signedPayload as Record<string, unknown>);
```

## Environment

| Variable | Purpose |
|----------|---------|
| `AIRLOCK_GATEWAY_URL` | Gateway base URL (optional; default `http://127.0.0.1:8000`) |
| `AIRLOCK_DEFAULT_GATEWAY_URL` | Fallback if `AIRLOCK_GATEWAY_URL` is unset |
| `AIRLOCK_SERVICE_TOKEN` | Optional bearer for MCP / scripts calling `metrics()` + `introspectTrustToken()` when the gateway requires it |

## Requirements

- Node.js **18+** (global `fetch` / `AbortSignal.timeout`)
