"""Airlock Protocol CLI — verify agents, run the gateway, scaffold projects."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import click

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
    default=None,
    show_default="https://api.airlock.ing",
    help="Airlock gateway URL. Defaults to central registry. Set AIRLOCK_GATEWAY_URL to override globally.",
)
def verify(did_or_url: str, gateway: str | None) -> None:
    """Verify an agent's identity against a running Airlock gateway.

    DID_OR_URL is a DID string (did:key:z6Mk...) or an agent endpoint URL.
    The command registers a temporary agent, performs a signed handshake,
    and prints the verification result using the full 5-phase protocol.
    """
    import os

    from airlock.client import AirlockClient, GatewayUnreachableError, VerificationFailedError

    resolved_gateway = gateway or os.environ.get("AIRLOCK_GATEWAY_URL", "https://api.airlock.ing")

    click.echo()
    click.echo(click.style("  Airlock Verify", fg="cyan", bold=True))
    click.echo(f"  Gateway: {resolved_gateway}")
    click.echo()

    client = AirlockClient(gateway_url=resolved_gateway, timeout=30.0)

    # Quick health check before the full flow
    click.echo("  [1/2] Checking gateway health...")
    try:
        client.health()
        click.echo(click.style("        Gateway is healthy", fg="green"))
    except GatewayUnreachableError:
        click.echo(click.style("        ERROR: Cannot connect to gateway", fg="red"))
        click.echo(f"        Is the gateway running at {resolved_gateway}?")
        click.echo("        Start it with: airlock serve")
        raise SystemExit(1)
    except Exception as exc:
        click.echo(click.style(f"        ERROR: {exc}", fg="red"))
        raise SystemExit(1)

    # Run full 5-phase verification via the SDK client
    click.echo(f"  [2/2] Running full verification for {_short_did(did_or_url)}...")
    try:
        result = client.full_verify(did_or_url, probe_name="airlock-cli-probe")
    except GatewayUnreachableError as exc:
        click.echo(click.style(f"        ERROR: Gateway unreachable: {exc}", fg="red"))
        raise SystemExit(1)
    except VerificationFailedError as exc:
        click.echo(click.style(f"        ERROR: Verification failed: {exc}", fg="red"))
        raise SystemExit(1)
    except Exception as exc:
        click.echo(click.style(f"        ERROR: {exc}", fg="red"))
        raise SystemExit(1)

    # Print result
    click.echo()
    verdict = result.verdict

    if verdict == "VERIFIED":
        symbol = click.style("  VERIFIED", fg="green", bold=True)
    elif verdict == "REJECTED":
        symbol = click.style("  REJECTED", fg="red", bold=True)
    elif verdict == "DEFERRED":
        symbol = click.style("  DEFERRED", fg="yellow", bold=True)
    else:
        symbol = click.style(f"  {verdict}", fg="yellow")

    click.echo(f"  Result: {symbol}")

    if result.session_id:
        click.echo(f"  Session: {result.session_id}")
    click.echo(f"  Trust Score: {result.trust_score}")

    if result.checks:
        click.echo("  Checks:")
        for chk in result.checks:
            passed = chk.get("passed", False)
            mark = click.style("pass", fg="green") if passed else click.style("fail", fg="red")
            click.echo(f"    [{mark}] {chk.get('check', '?')}: {chk.get('detail', '')}")

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
        "endpoint_url": "https://api.airlock.ing",
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
  url: "https://api.airlock.ing"

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
