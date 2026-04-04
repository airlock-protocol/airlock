# Airlock Protocol — CLAUDE.md

## What is this project?
Airlock Protocol — "DMARC for AI Agents". An open trust verification protocol for autonomous AI agents.
Ed25519 cryptography, DID identifiers, 5-phase verification, live registry at api.airlock.ing.

## Tech Stack
- **Language:** Python 3.11+
- **Framework:** FastAPI + Uvicorn
- **Orchestration:** LangGraph
- **Crypto:** PyNaCl (Ed25519)
- **DB:** LanceDB (vector), optional Redis
- **LLM:** LiteLLM (multi-provider)
- **Tests:** pytest + pytest-asyncio + hypothesis

## Running Tests
```bash
pytest                          # run all tests
pytest tests/ -x                # stop on first failure
pytest tests/test_crypto.py     # single file
pytest -k "test_verify"         # by name pattern
pytest --cov=airlock            # with coverage
```

## Running the Gateway
```bash
uvicorn airlock.gateway.app:create_app --factory --port 8000 --reload
```

## Project Structure
```
airlock/
  a2a/          — Agent-to-Agent adapter
  audit/        — Audit trail
  crypto/       — Keys, signing, verifiable credentials
  engine/       — Orchestrator, event bus, state machine
  gateway/      — FastAPI routes and handlers
  integrations/ — Anthropic, LangChain, OpenAI SDKs
  registry/     — Agent registry and store
  reputation/   — Trust scoring and decay
  schemas/      — Pydantic models
  sdk/          — Client SDK and middleware
  semantic/     — Challenge evaluation + rule engine
tests/          — 27 test files, 198+ tests
```

## Conventions
- **Type hints:** Always use type hints. MyPy strict mode is enabled.
- **Linting:** Ruff. Run `ruff check .` before committing.
- **Async:** Use async/await for all I/O operations. pytest-asyncio with `asyncio_mode = "auto"`.
- **Pydantic:** Use Pydantic v2 models for all data schemas. No raw dicts for structured data.
- **Error handling:** All API errors must return structured JSON with `error`, `detail`, and `status_code` fields.
- **Tests:** Every new feature needs tests. Use `fakeredis` for Redis tests, `asgi-lifespan` for gateway tests.
- **Imports:** Use absolute imports (`from airlock.crypto.keys import ...`), never relative.
- **No print():** Use `logging` module. Never print() in library code.
- **DID format:** Always validate DID strings match `did:key:z6Mk...` pattern before processing.
- **Secrets:** Never log or expose private keys, challenge secrets, or JWT tokens.

## Common Mistakes to Avoid
- Don't use `json.dumps()` for Pydantic models — use `model.model_dump_json()`
- Don't forget `await` on async functions — this causes silent failures
- Don't hardcode ports — use config.py
- Don't skip input validation on DID strings — always validate format
- Don't use `datetime.now()` — use `datetime.utcnow()` or `datetime.now(UTC)` for consistency
- Don't create test files outside of `tests/` directory
- Don't import from `airlock.gateway` in core modules — gateway depends on core, not the reverse

## Architecture Rules
- Gateway layer → Engine layer → Crypto/Registry/Reputation layers
- No circular dependencies between modules
- All events go through the EventBus — no direct cross-module calls
- Orchestrator uses LangGraph state machine — don't bypass the graph
