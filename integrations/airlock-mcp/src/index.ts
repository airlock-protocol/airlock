#!/usr/bin/env node
/**
 * Stdio MCP server: exposes read-mostly Airlock gateway operations as tools.
 * Configure `AIRLOCK_GATEWAY_URL`; run via `npx airlock-mcp` after build/publish.
 */
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { AirlockClient, gatewayUrlFromEnv } from "airlock-client";

function text(data: unknown): { content: Array<{ type: "text"; text: string }> } {
  return {
    content: [{ type: "text", text: JSON.stringify(data, null, 2) }],
  };
}

async function main(): Promise<void> {
  const base = (process.env.AIRLOCK_GATEWAY_URL || "").trim() || gatewayUrlFromEnv();
  const serviceToken = (process.env.AIRLOCK_SERVICE_TOKEN || "").trim() || undefined;
  const client = new AirlockClient(base, { serviceToken });

  const server = new McpServer({
    name: "airlock-mcp",
    version: "0.1.0",
  });

  server.tool(
    "airlock_health",
    "Get Airlock gateway health (status, protocol_version, airlock_did, subsystems).",
    {},
    async () => text(await client.health()),
  );

  server.tool(
    "airlock_resolve",
    "Resolve an agent DID (registry lookup). Returns found, profile, registry_source.",
    { target_did: z.string().describe("Target agent did:key") },
    async ({ target_did }) => text(await client.resolve(target_did)),
  );

  server.tool(
    "airlock_reputation",
    "Fetch stored reputation / trust score for a DID.",
    { did: z.string().describe("Agent did:key") },
    async ({ did }) => text(await client.getReputation(did)),
  );

  server.tool(
    "airlock_session",
    "Get verification session state. Pass session_view_token from handshake ACK when the gateway uses AIRLOCK_SESSION_VIEW_SECRET.",
    {
      session_id: z.string().min(1).describe("Session id from handshake ACK"),
      session_view_token: z
        .string()
        .optional()
        .describe("JWT from handshake ACK (Bearer for /session)"),
    },
    async ({ session_id, session_view_token }) =>
      text(await client.getSession(session_id, { sessionViewToken: session_view_token })),
  );

  server.tool(
    "airlock_feedback",
    "POST signed SignedFeedbackReport JSON (use Python SDK to sign). Same canonical JSON as gateway.",
    {
      feedback_json: z.string().describe("Full SignedFeedbackReport JSON object as string"),
    },
    async ({ feedback_json }) => {
      let body: Record<string, unknown>;
      try {
        body = JSON.parse(feedback_json) as Record<string, unknown>;
      } catch {
        return text({ error: "feedback_json must be valid JSON" });
      }
      return text(await client.submitFeedback(body));
    },
  );

  server.tool(
    "airlock_metrics",
    "Prometheus text exposition from GET /metrics (request counters).",
    {},
    async () => ({
      content: [{ type: "text", text: await client.metrics() }],
    }),
  );

  server.tool(
    "airlock_introspect_trust_token",
    "Validate a trust JWT with POST /token/introspect (requires gateway secret).",
    { token: z.string().describe("HS256 trust token from VERIFIED flow") },
    async ({ token }) => text(await client.introspectTrustToken(token)),
  );

  server.tool(
    "airlock_handshake",
    "POST a pre-built JSON HandshakeRequest (use Python SDK to sign). Body must be valid JSON.",
    {
      handshake_json: z.string().describe("Full HandshakeRequest JSON object as string"),
      callback_url: z.string().url().optional().describe("Optional X-Callback-Url header"),
    },
    async ({ handshake_json, callback_url }) => {
      let body: Record<string, unknown>;
      try {
        body = JSON.parse(handshake_json) as Record<string, unknown>;
      } catch {
        return text({ error: "handshake_json must be valid JSON" });
      }
      return text(await client.handshake(body, callback_url));
    },
  );

  const transport = new StdioServerTransport();
  await server.connect(transport);
}

main().catch((err: unknown) => {
  console.error(err);
  process.exit(1);
});
