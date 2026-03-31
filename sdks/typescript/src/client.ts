import type {
  ResolveResponse,
  TransportAck,
  TransportAckOrNack,
  TransportNack,
} from "./types.js";

function stripTrailingSlash(base: string): string {
  return base.replace(/\/+$/, "");
}

function parseTransport(data: unknown): TransportAckOrNack {
  if (typeof data !== "object" || data === null) {
    throw new Error("airlock: invalid transport JSON");
  }
  const d = data as Record<string, unknown>;
  if (d.status === "ACCEPTED") {
    return d as TransportAck;
  }
  if (d.status === "REJECTED") {
    return d as TransportNack;
  }
  throw new Error(`airlock: unknown transport status: ${String(d.status)}`);
}

export type AirlockClientOptions = {
  /** Request timeout in milliseconds (default 30s). */
  timeoutMs?: number;
  /** Optional extra headers on each request. */
  defaultHeaders?: Record<string, string>;
  /**
   * Bearer token for `GET /metrics` and `POST /token/introspect` when the gateway
   * requires `AIRLOCK_SERVICE_TOKEN` (always in production).
   */
  serviceToken?: string;
};

/**
 * Minimal async HTTP client for the Airlock FastAPI gateway.
 * Matches the Python `airlock.sdk.client.AirlockClient` surface (minus the bundled Ed25519 key).
 */
export class AirlockClient {
  private readonly baseUrl: string;
  private readonly timeoutMs: number;
  private readonly defaultHeaders: Record<string, string>;
  private readonly serviceToken?: string;

  constructor(baseUrl: string, options: AirlockClientOptions = {}) {
    this.baseUrl = stripTrailingSlash(baseUrl);
    this.timeoutMs = options.timeoutMs ?? 30_000;
    this.defaultHeaders = options.defaultHeaders ?? {};
    this.serviceToken = options.serviceToken;
  }

  private url(path: string): string {
    return `${this.baseUrl}${path.startsWith("/") ? path : `/${path}`}`;
  }

  private signal(): AbortSignal {
    return AbortSignal.timeout(this.timeoutMs);
  }

  private mergeHeaders(extra?: Record<string, string>): Headers {
    const h = new Headers(this.defaultHeaders);
    h.set("Content-Type", "application/json");
    if (extra) {
      for (const [k, v] of Object.entries(extra)) {
        h.set(k, v);
      }
    }
    return h;
  }

  private serviceAuthHeaders(): Record<string, string> {
    return this.serviceToken ? { Authorization: `Bearer ${this.serviceToken}` } : {};
  }

  async health(): Promise<Record<string, unknown>> {
    const r = await fetch(this.url("/health"), { method: "GET", signal: this.signal() });
    if (!r.ok) {
      throw new Error(`airlock: GET /health ${r.status}`);
    }
    return r.json() as Promise<Record<string, unknown>>;
  }

  async metrics(): Promise<string> {
    const r = await fetch(this.url("/metrics"), {
      method: "GET",
      headers: this.mergeHeaders(this.serviceAuthHeaders()),
      signal: this.signal(),
    });
    if (!r.ok) {
      throw new Error(`airlock: GET /metrics ${r.status}`);
    }
    return r.text();
  }

  async live(): Promise<Record<string, unknown>> {
    const r = await fetch(this.url("/live"), { method: "GET", signal: this.signal() });
    if (!r.ok) {
      throw new Error(`airlock: GET /live ${r.status}`);
    }
    return r.json() as Promise<Record<string, unknown>>;
  }

  async ready(): Promise<Record<string, unknown>> {
    const r = await fetch(this.url("/ready"), { method: "GET", signal: this.signal() });
    if (!r.ok) {
      throw new Error(`airlock: GET /ready ${r.status}`);
    }
    return r.json() as Promise<Record<string, unknown>>;
  }

  async resolve(targetDid: string): Promise<ResolveResponse> {
    const r = await fetch(this.url("/resolve"), {
      method: "POST",
      headers: this.mergeHeaders(),
      body: JSON.stringify({ target_did: targetDid }),
      signal: this.signal(),
    });
    if (!r.ok) {
      throw new Error(`airlock: POST /resolve ${r.status}`);
    }
    return r.json() as Promise<ResolveResponse>;
  }

  async register(profile: Record<string, unknown>): Promise<Record<string, unknown>> {
    const r = await fetch(this.url("/register"), {
      method: "POST",
      headers: this.mergeHeaders(),
      body: JSON.stringify(profile),
      signal: this.signal(),
    });
    if (!r.ok) {
      throw new Error(`airlock: POST /register ${r.status}`);
    }
    return r.json() as Promise<Record<string, unknown>>;
  }

  /**
   * Send a fully-formed `HandshakeRequest` (typically built and signed with the Python SDK).
   */
  async handshake(
    requestBody: Record<string, unknown>,
    callbackUrl?: string,
  ): Promise<TransportAckOrNack> {
    const headers: Record<string, string> = {};
    if (callbackUrl) {
      headers["X-Callback-Url"] = callbackUrl;
    }
    const r = await fetch(this.url("/handshake"), {
      method: "POST",
      headers: this.mergeHeaders(headers),
      body: JSON.stringify(requestBody),
      signal: this.signal(),
    });
    if (!r.ok) {
      throw new Error(`airlock: POST /handshake ${r.status}`);
    }
    return parseTransport(await r.json());
  }

  async submitChallengeResponse(
    body: Record<string, unknown>,
  ): Promise<TransportAckOrNack> {
    const r = await fetch(this.url("/challenge-response"), {
      method: "POST",
      headers: this.mergeHeaders(),
      body: JSON.stringify(body),
      signal: this.signal(),
    });
    if (!r.ok) {
      throw new Error(`airlock: POST /challenge-response ${r.status}`);
    }
    return parseTransport(await r.json());
  }

  /**
   * Signed heartbeat body (envelope + signature), typically built with the Python SDK.
   */
  async heartbeat(body: Record<string, unknown>): Promise<Record<string, unknown>> {
    const r = await fetch(this.url("/heartbeat"), {
      method: "POST",
      headers: this.mergeHeaders(),
      body: JSON.stringify(body),
      signal: this.signal(),
    });
    if (!r.ok) {
      throw new Error(`airlock: POST /heartbeat ${r.status}`);
    }
    return r.json() as Promise<Record<string, unknown>>;
  }

  async submitFeedback(body: Record<string, unknown>): Promise<Record<string, unknown>> {
    const r = await fetch(this.url("/feedback"), {
      method: "POST",
      headers: this.mergeHeaders(),
      body: JSON.stringify(body),
      signal: this.signal(),
    });
    if (!r.ok) {
      throw new Error(`airlock: POST /feedback ${r.status}`);
    }
    return r.json() as Promise<Record<string, unknown>>;
  }

  async getReputation(did: string): Promise<Record<string, unknown>> {
    const enc = encodeURIComponent(did);
    const r = await fetch(this.url(`/reputation/${enc}`), {
      method: "GET",
      signal: this.signal(),
    });
    if (!r.ok) {
      throw new Error(`airlock: GET /reputation ${r.status}`);
    }
    return r.json() as Promise<Record<string, unknown>>;
  }

  async getSession(
    sessionId: string,
    options: { sessionViewToken?: string; serviceToken?: string } = {},
  ): Promise<Record<string, unknown>> {
    const enc = encodeURIComponent(sessionId);
    const tok = options.sessionViewToken ?? options.serviceToken;
    const headers: Record<string, string> = {};
    if (tok) {
      headers.Authorization = `Bearer ${tok}`;
    }
    const r = await fetch(this.url(`/session/${enc}`), {
      method: "GET",
      headers: this.mergeHeaders(headers),
      signal: this.signal(),
    });
    if (!r.ok) {
      throw new Error(`airlock: GET /session ${r.status}`);
    }
    return r.json() as Promise<Record<string, unknown>>;
  }

  /**
   * Open a WebSocket to receive ``session`` payloads when the gateway updates the
   * verification session (alternative to polling ``getSession``).
   * Yields parsed JSON messages until the socket closes or an error occurs.
   */
  watchSession(
    sessionId: string,
    options: { signal?: AbortSignal; sessionViewToken?: string } = {},
  ): AsyncGenerator<Record<string, unknown>, void, undefined> {
    const enc = encodeURIComponent(sessionId);
    const wsUrl = this.wsSessionUrl(enc, options.sessionViewToken);
    const outerSignal = options.signal;
    const q: Array<{ done: boolean; value?: Record<string, unknown>; error?: Error }> = [];
    let notify: (() => void) | undefined;
    const wait = () =>
      new Promise<void>((resolve) => {
        notify = resolve;
      });

    const ws = new WebSocket(wsUrl);

    const abortOnOuter = () => {
      try {
        ws.close();
      } catch {
        /* ignore */
      }
    };
    if (outerSignal) {
      if (outerSignal.aborted) {
        abortOnOuter();
        return (async function* () {})();
      }
      outerSignal.addEventListener("abort", abortOnOuter, { once: true });
    }

    ws.onmessage = (ev) => {
      try {
        const data = JSON.parse(String(ev.data)) as Record<string, unknown>;
        q.push({ done: false, value: data });
      } catch (e) {
        q.push({
          done: false,
          error: e instanceof Error ? e : new Error(String(e)),
        });
      }
      notify?.();
    };
    ws.onerror = () => {
      q.push({ done: false, error: new Error("airlock: WebSocket error") });
      notify?.();
    };
    ws.onclose = () => {
      q.push({ done: true });
      notify?.();
    };

    return (async function* () {
      try {
        while (true) {
          while (q.length === 0 && ws.readyState !== WebSocket.CLOSED) {
            await wait();
          }
          if (q.length === 0) break;
          const item = q.shift()!;
          if (item.done) break;
          if (item.error) throw item.error;
          if (item.value) yield item.value;
        }
      } finally {
        if (outerSignal) outerSignal.removeEventListener("abort", abortOnOuter);
        try {
          ws.close();
        } catch {
          /* ignore */
        }
      }
    })();
  }

  private wsSessionUrl(encodedSessionId: string, sessionViewToken?: string): string {
    const base = stripTrailingSlash(this.baseUrl);
    const u = new URL(base);
    const isSecure = u.protocol === "https:" || u.protocol === "wss:";
    u.protocol = isSecure ? "wss:" : "ws:";
    u.pathname = `/ws/session/${encodedSessionId}`;
    u.search = "";
    u.hash = "";
    if (sessionViewToken) {
      u.searchParams.set("token", sessionViewToken);
    }
    return u.toString();
  }

  async introspectTrustToken(token: string): Promise<Record<string, unknown>> {
    const r = await fetch(this.url("/token/introspect"), {
      method: "POST",
      headers: this.mergeHeaders(this.serviceAuthHeaders()),
      body: JSON.stringify({ token }),
      signal: this.signal(),
    });
    if (!r.ok) {
      throw new Error(`airlock: POST /token/introspect ${r.status}`);
    }
    return r.json() as Promise<Record<string, unknown>>;
  }
}
