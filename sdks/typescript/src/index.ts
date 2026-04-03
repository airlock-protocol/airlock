export { AirlockClient, type AirlockClientOptions } from "./client.js";
export {
  isTransportAck,
  isTransportNack,
  type ResolveResponse,
  type TransportAck,
  type TransportAckOrNack,
  type TransportNack,
} from "./types.js";

/** Resolve gateway base URL from environment (browser: not set; use explicit URL). */
export function gatewayUrlFromEnv(): string {
  const a = typeof process !== "undefined" && process.env ? process.env.AIRLOCK_GATEWAY_URL : "";
  const b = typeof process !== "undefined" && process.env ? process.env.AIRLOCK_DEFAULT_GATEWAY_URL : "";
  const v = (a || b || "").trim();
  return v || "https://api.airlock.ing";
}
