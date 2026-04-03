"""Airlock Protocol CLI — verify agents, run the gateway, scaffold projects."""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from typing import Any

import click


def _run_async(coro: Any) -> Any:
    """Run an async coroutine from synchronous click context."""
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    return asyncio.run(coro)


# ---------------------------------------------------------------------------
# Root group
# ---------------------------------------------------------------------------


@click.group()
@click.version_option(version="0.1.0", prog_name="airlock")
def cli() -> None:
    """Airlock Protocol -- trust verification for AI agents.

    Verify agent identities, run the Airlock gateway, or scaffold a new project.
    """


# ---------------------------------------------------------------------------
# airlock verify
# ---------------------------------------------------------------------------


@cli.command()
@click.argument("did_or_url")
@click.option(
    "--gateway",
    default="http://127.0.0.1:8000",
    show_default=True,
    help="Airlock gateway URL to verify against.",
)
def verify(did_or_url: str, gateway: str) -> None:
    """Verify an agent's identity against a running Airlock gateway.

    DID_OR_URL is a DID string (did:key:z6Mk...) or an agent endpoint URL.
    The command registers a temporary agent, performs a signed handshake,
    and prints the verification result.
    """
    _run_async(_verify_agent(did_or_url, gateway))


async def _verify_agent(did_or_url: str, gateway_url: str) -> None:
    import httpx

    from airlock.crypto.keys import KeyPair
    from airlock.sdk.simple import build_signed_handshake, ensure_registered_profile

    gateway_url = gateway_url.rstrip("/")

    click.echo()
    click.echo(click.style("  Airlock Verify", fg="cyan", bold=True))
    click.echo(f"  Gateway: {gateway_url}")
    click.echo()

    # Step 1: Check gateway health
    click.echo("  [1/4] Checking gateway health...")
    async with httpx.AsyncClient(base_url=gateway_url, timeout=10.0) as client:
        try:
            resp = await client.get("/health")
            resp.raise_for_status()
            resp.json()  # confirm valid JSON response
            click.echo(click.style("        Gateway is healthy", fg="green"))
        except httpx.ConnectError:
            click.echo(click.style("        ERROR: Cannot connect to gateway", fg="red"))
            click.echo(f"        Is the gateway running at {gateway_url}?")
            click.echo("        Start it with: airlock serve")
            raise SystemExit(1)
        except Exception as exc:
            click.echo(click.style(f"        ERROR: {exc}", fg="red"))
            raise SystemExit(1)

        # Step 2: Generate a temporary keypair for the verification probe
        click.echo("  [2/4] Generating probe keypair...")
        probe_kp = KeyPair.generate()
        issuer_kp = KeyPair.generate()
        click.echo(f"        Probe DID: {_short_did(probe_kp.did)}")

        # Step 3: Register the probe agent
        click.echo("  [3/4] Registering probe agent...")
        profile = ensure_registered_profile(
            probe_kp,
            display_name="airlock-cli-probe",
            endpoint_url="http://localhost:0",
            capabilities=[("verify-probe", "0.1.0", "CLI verification probe")],
        )
        try:
            reg_resp = await client.post(
                "/register",
                content=profile.model_dump_json(),
                headers={"Content-Type": "application/json"},
            )
            if reg_resp.status_code == 200:
                click.echo(click.style("        Registered", fg="green"))
            else:
                click.echo(
                    click.style(f"        Registration: HTTP {reg_resp.status_code}", fg="yellow")
                )
        except Exception as exc:
            click.echo(click.style(f"        Registration failed: {exc}", fg="yellow"))

        # Step 4: Perform handshake against the target DID
        target_did = did_or_url
        click.echo(f"  [4/4] Verifying {_short_did(target_did)}...")

        handshake_req = build_signed_handshake(
            agent_kp=probe_kp,
            issuer_kp=issuer_kp,
            target_did=target_did,
            action="verify",
            description="CLI identity verification probe",
        )

        try:
            hs_resp = await client.post(
                "/handshake",
                content=handshake_req.model_dump_json(),
                headers={"Content-Type": "application/json"},
            )
            data = hs_resp.json()
        except Exception as exc:
            click.echo(click.style(f"        ERROR: Handshake failed: {exc}", fg="red"))
            raise SystemExit(1)

    # Print result
    click.echo()
    status = data.get("status", "UNKNOWN")
    verdict = data.get("verdict", status)

    if verdict == "VERIFIED" or status == "ACCEPTED":
        symbol = click.style("  VERIFIED", fg="green", bold=True)
    elif verdict in ("REJECTED", "NACK") or status == "REJECTED":
        symbol = click.style("  REJECTED", fg="red", bold=True)
    elif verdict == "DEFERRED":
        symbol = click.style("  DEFERRED", fg="yellow", bold=True)
    else:
        symbol = click.style(f"  {verdict}", fg="yellow")

    click.echo(f"  Result: {symbol}")

    # Print details
    if data.get("session_id"):
        click.echo(f"  Session: {data['session_id']}")
    if data.get("trust_score") is not None:
        click.echo(f"  Trust Score: {data['trust_score']}")

    checks = data.get("checks", [])
    if checks:
        click.echo("  Checks:")
        for chk in checks:
            passed = chk.get("passed", False)
            mark = click.style("pass", fg="green") if passed else click.style("fail", fg="red")
            click.echo(f"    [{mark}] {chk.get('check', '?')}: {chk.get('detail', '')}")

    if data.get("error_code"):
        click.echo(f"  Error: {data['error_code']}")
    if data.get("reason"):
        click.echo(f"  Reason: {data['reason']}")

    click.echo()


def _short_did(did: str, n: int = 24) -> str:
    if len(did) <= n + 12:
        return did
    return did[:20] + "..." + did[-8:]


# ---------------------------------------------------------------------------
# airlock serve
# ---------------------------------------------------------------------------


@cli.command()
@click.option("--host", default="0.0.0.0", show_default=True, help="Bind address.")
@click.option("--port", default=8000, show_default=True, type=int, help="Port number.")
@click.option("--reload", is_flag=True, default=False, help="Enable auto-reload for development.")
def serve(host: str, port: int, reload: bool) -> None:
    """Start the Airlock gateway server.

    Runs the FastAPI gateway using uvicorn. The server handles agent
    registration, handshake verification, reputation tracking, and
    all Airlock protocol endpoints.
    """
    import uvicorn

    click.echo()
    click.echo(click.style("  Airlock Gateway", fg="cyan", bold=True))
    click.echo(f"  Listening on {host}:{port}")
    if reload:
        click.echo(click.style("  Auto-reload enabled (development mode)", fg="yellow"))
    click.echo()

    uvicorn.run(
        "airlock.gateway.app:create_app",
        factory=True,
        host=host,
        port=port,
        reload=reload,
        log_level="info",
    )


# ---------------------------------------------------------------------------
# airlock init
# ---------------------------------------------------------------------------


@cli.command()
@click.option(
    "--dir",
    "directory",
    default=".",
    type=click.Path(),
    help="Target directory (default: current directory).",
)
def init(directory: str) -> None:
    """Scaffold a new Airlock-protected project.

    Creates an airlock.yaml config, an agent_card.json template,
    and a keys/ directory with a fresh Ed25519 keypair.
    """
    target = Path(directory).resolve()
    target.mkdir(parents=True, exist_ok=True)

    click.echo()
    click.echo(click.style("  Airlock Init", fg="cyan", bold=True))
    click.echo(f"  Directory: {target}")
    click.echo()

    created = []

    # 1. airlock.yaml
    config_path = target / "airlock.yaml"
    if config_path.exists():
        click.echo(click.style("  [skip] airlock.yaml already exists", fg="yellow"))
    else:
        config_path.write_text(
            _AIRLOCK_YAML_TEMPLATE,
            encoding="utf-8",
        )
        created.append("airlock.yaml")
        click.echo(click.style("  [created] airlock.yaml", fg="green"))

    # 2. agent_card.json
    card_path = target / "agent_card.json"
    if card_path.exists():
        click.echo(click.style("  [skip] agent_card.json already exists", fg="yellow"))
    else:
        from airlock.crypto.keys import KeyPair

        kp = KeyPair.generate()
        card = _build_agent_card(kp)
        card_path.write_text(
            json.dumps(card, indent=2) + "\n",
            encoding="utf-8",
        )
        created.append("agent_card.json")
        click.echo(click.style("  [created] agent_card.json", fg="green"))

        # 3. keys/ directory with the keypair
        keys_dir = target / "keys"
        keys_dir.mkdir(exist_ok=True)

        seed_path = keys_dir / "agent_seed.hex"
        seed_path.write_text(kp.signing_key.encode().hex(), encoding="utf-8")
        created.append("keys/agent_seed.hex")

        did_path = keys_dir / "agent_did.txt"
        did_path.write_text(kp.did + "\n", encoding="utf-8")
        created.append("keys/agent_did.txt")

        click.echo(click.style("  [created] keys/agent_seed.hex", fg="green"))
        click.echo(click.style("  [created] keys/agent_did.txt", fg="green"))

    # 4. .gitignore for keys
    gitignore_path = target / "keys" / ".gitignore"
    if (target / "keys").exists() and not gitignore_path.exists():
        gitignore_path.write_text("# Never commit private keys\nagent_seed.hex\n", encoding="utf-8")
        created.append("keys/.gitignore")
        click.echo(click.style("  [created] keys/.gitignore", fg="green"))

    click.echo()
    if created:
        click.echo(click.style("  Project scaffolded successfully!", fg="green", bold=True))
    else:
        click.echo("  All files already exist, nothing to create.")

    click.echo()
    click.echo("  Next steps:")
    click.echo("    1. Start the gateway:    airlock serve")
    click.echo("    2. Verify an agent:      airlock verify <did>")
    click.echo("    3. Read the docs:        https://github.com/shivdeep1/airlock-protocol")
    click.echo()


def _build_agent_card(kp: Any) -> dict[str, Any]:
    """Build a minimal A2A-compatible agent card."""
    return {
        "name": "My Airlock Agent",
        "description": "An AI agent protected by Airlock Protocol",
        "did": kp.did,
        "public_key_multibase": kp.public_key_multibase,
        "endpoint_url": "http://localhost:8000",
        "protocol_versions": ["0.1.0"],
        "capabilities": [
            {
                "name": "default",
                "version": "1.0",
                "description": "Default agent capability",
            }
        ],
    }


_AIRLOCK_YAML_TEMPLATE = """\
# Airlock Protocol configuration
# Docs: https://github.com/shivdeep1/airlock-protocol

gateway:
  url: "http://127.0.0.1:8000"

agent:
  # Path to your agent's Ed25519 seed file
  key_path: "keys/agent_seed.hex"

logging:
  level: "INFO"
  json: false

# Optional: LLM for semantic challenge evaluation
# llm:
#   model: "ollama/llama3"
#   api_base: "http://localhost:11434"
"""
