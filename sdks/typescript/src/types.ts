/** Transport ACK returned when the gateway accepts a signed envelope. */
export interface TransportAck {
  status: "ACCEPTED";
  session_id: string;
  timestamp: string;
  envelope: Record<string, unknown>;
  /** Present when `AIRLOCK_SESSION_VIEW_SECRET` is set; use as Bearer for `/session` and WebSocket. */
  session_view_token?: string;
  [k: string]: unknown;
}

/** Transport NACK when verification fails at the gateway boundary. */
export interface TransportNack {
  status: "REJECTED";
  session_id?: string | null;
  reason: string;
  error_code: string;
  timestamp: string;
  envelope: Record<string, unknown>;
  [k: string]: unknown;
}

export type TransportAckOrNack = TransportAck | TransportNack;

/** `POST /resolve` success shape (local or remote registry). */
export interface ResolveResponse {
  found: boolean;
  did?: string;
  profile?: Record<string, unknown>;
  registry_source?: "local" | "remote";
  [k: string]: unknown;
}

export function isTransportNack(x: TransportAckOrNack): x is TransportNack {
  return x.status === "REJECTED";
}

export function isTransportAck(x: TransportAckOrNack): x is TransportAck {
  return x.status === "ACCEPTED";
}
