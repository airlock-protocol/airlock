# Getting Started with Airlock Protocol

Verify an AI agent's identity and trust in under 5 minutes.

## 1. Install

```bash
pip install airlock-protocol
```

## 2. Start the gateway

```bash
airlock serve
```

The gateway runs at `http://localhost:8000` by default. Check it is up:

```bash
curl http://localhost:8000/health
```

## 3. Verify your first agent

```python
from airlock import AirlockClient

client = AirlockClient()
result = client.verify("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK")

if result.verified:
    print(f"Trusted: {result.agent_name} (score: {result.trust_score})")
else:
    print(f"Not trusted: {result.verdict}")
```

That is 7 lines. Here is what each one does:

| Line | What happens |
|------|-------------|
| `AirlockClient()` | Connects to the local gateway |
| `client.verify(did)` | Resolves the agent, checks reputation, returns a verdict |
| `result.verified` | `True` if the agent passed verification |
| `result.trust_score` | Float 0.0 -- 1.0 representing cumulative trust |
| `result.verdict` | One of `VERIFIED`, `REJECTED`, or `DEFERRED` |

## 4. What just happened?

Airlock verifies agents through five phases:

1. **Identity** -- the agent presents a DID:key and signed envelope.
2. **Credential** -- a W3C Verifiable Credential is validated against allowed issuers.
3. **Reputation** -- the agent's historical trust score is fetched from LanceDB.
4. **Challenge** -- if the score is borderline, the gateway issues a semantic challenge that only a legitimate agent can answer.
5. **Verdict** -- the gateway issues `VERIFIED`, `REJECTED`, or `DEFERRED` with a signed attestation and optional trust token.

The `verify()` method in the SDK handles steps 1 -- 3 for quick lookups. Full handshake flows (steps 1 -- 5) are available through the gateway's `/handshake` endpoint.

## 5. Register an agent

```python
from airlock import AirlockClient

client = AirlockClient()
reg = client.register(
    name="My Research Agent",
    capabilities=[
        {"name": "summarize", "version": "1.0.0", "description": "Summarizes papers"}
    ],
)
print(f"Registered: {reg.did}")
```

## 6. Async support

Every method has an async twin prefixed with `a`:

```python
result = await client.averify("did:key:z6Mk...")
reg = await client.aregister("My Agent", capabilities=[...])
health = await client.ahealth()
```

## 7. Next steps

- **Full API reference** -- see `airlock/gateway/routes.py` for all endpoints
- **Examples** -- run `python examples/run_demo.py` for end-to-end verification scenarios
- **Configuration** -- set environment variables (`AIRLOCK_GATEWAY_SEED_HEX`, `AIRLOCK_TRUST_TOKEN_SECRET`, etc.) or pass an `AirlockConfig` to the gateway
- **Protocol spec** -- read `docs/` for the full five-phase protocol specification
