# The Agentic Airlock

An open protocol for agent-to-agent trust verification in the agentic web.

## The Problem

AI agents are rapidly gaining the ability to communicate with each other autonomously
(via protocols like Google A2A and Anthropic MCP). However, there is no standard mechanism
for verifying agent identity, authorization, or trustworthiness. The agent ecosystem is
repeating the same mistake email made -- building communication without authentication.

Email took 20 years to bolt on SPF, DKIM, and DMARC after spam became an existential crisis.
The Agentic Airlock builds the trust layer *before* the agent spam crisis hits.

## What Is the Airlock?

The Airlock is a **5-phase verification protocol** for agent-to-agent communication:

1. **Resolve** -- discover a target agent's capabilities and status
2. **Handshake** -- assert identity with signed credentials (W3C DIDs + Verifiable Credentials)
3. **Challenge** -- behavioral verification via semantic traps (for unknown agents)
4. **Verdict** -- trust decision (VERIFIED / REJECTED / DEFERRED) with signed attestation
5. **Seal** -- both parties receive signed receipts for audit trail

The protocol is designed to be:
- **Crypto-first**: 95%+ of verifications use pure cryptography (microseconds, zero LLM cost)
- **A2A compatible**: wraps standard Google A2A JSON-RPC 2.0 messages
- **Local-first**: can run fully embedded with no external dependencies
- **Open**: protocol spec is free and open-source (Apache 2.0)

## Architecture

```
Layer 1: Open Protocol Spec     -- Pydantic schemas, crypto primitives, event definitions
Layer 2: Managed Service         -- FastAPI gateway + verification orchestrator + reputation store
Layer 3: Python SDK              -- 3-line integration for any agent framework
```

## Status

Early development. Protocol design and core implementation in progress.

## License

Apache License 2.0. See [LICENSE](LICENSE).

## Author

Shivdeep Singh ([@shivdeep1](https://github.com/shivdeep1))
