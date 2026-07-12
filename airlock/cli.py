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
@click.version_option(version="0.4.0", prog_name="airlock")
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
# airlock evidence
# ---------------------------------------------------------------------------


@cli.group()
def evidence() -> None:
    """Compliance evidence pack commands."""


@evidence.command("export")
@click.option("--from", "from_iso", required=True, help="Window start (ISO 8601).")
@click.option("--to", "to_iso", required=True, help="Window end (ISO 8601).")
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["json", "markdown", "both"]),
    default="both",
    show_default=True,
    help="Output format.",
)
@click.option(
    "--out",
    "out_dir",
    default=".",
    show_default=True,
    type=click.Path(file_okay=False),
    help="Output directory.",
)
def evidence_export(from_iso: str, to_iso: str, fmt: str, out_dir: str) -> None:
    """Export a signed, auditor-ready evidence pack for a time window."""
    from airlock.compliance.evidence_pack import run_cli_export

    try:
        written = run_cli_export(from_iso=from_iso, to_iso=to_iso, fmt=fmt, out_dir=out_dir)
    except ValueError as exc:
        click.echo(click.style(f"  ERROR: {exc}", fg="red"))
        raise SystemExit(1)
    for path in written:
        click.echo(click.style(f"  [written] {path}", fg="green"))


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
    click.echo("    3. Read the docs:        https://github.com/airlock-protocol/airlock")
    click.echo()


# ---------------------------------------------------------------------------
# airlock passport
# ---------------------------------------------------------------------------


@cli.group()
def passport() -> None:
    """Web Bot Auth passport -- signed agent identity for bot walls.

    Generate an Ed25519 passport key, register it with an Airlock
    registry, and send RFC 9421 web-bot-auth signed requests that
    verifying bot walls (Cloudflare, AWS WAF, Vercel, Akamai) accept.
    """


def _default_registry(registry: str | None) -> str:
    import os

    return registry or os.environ.get("AIRLOCK_GATEWAY_URL", "https://api.airlock.ing")


def _load_passport_key(key_file: str | None) -> tuple[Any, Path, bool]:
    from airlock.passport.registration import DEFAULT_KEY_PATH, load_or_create_passport_key

    key_path = Path(key_file) if key_file else DEFAULT_KEY_PATH
    keypair, created = load_or_create_passport_key(key_path)
    return keypair, key_path, created


@passport.command("init")
@click.option("--registry", default=None, help="Airlock registry URL (default: api.airlock.ing).")
@click.option(
    "--key-file",
    "key_file",
    default=None,
    type=click.Path(dir_okay=False),
    help="Passport key seed file (default: ~/.airlock/passport.key).",
)
@click.option("--name", default="Airlock Passport Agent", help="Display name for the agent.")
def passport_init(registry: str | None, key_file: str | None, name: str) -> None:
    """Create a passport: generate/load a key and register it.

    Signs a directory assertion (proof of key possession) and uploads it
    with the registration. Idempotent -- re-running with the same key
    file re-uses the key and re-registers (the registry upserts).
    """
    import asyncio

    from airlock.passport.assertions import sign_assertion
    from airlock.passport.registration import (
        fetch_passport_status,
        register_passport,
        upload_assertion,
    )

    registry_url = _default_registry(registry)
    try:
        keypair, key_path, created = _load_passport_key(key_file)
    except ValueError as exc:
        click.echo(click.style(f"  ERROR: {exc}", fg="red"))
        raise SystemExit(1) from exc

    click.echo()
    click.echo(click.style("  Airlock Passport Init", fg="cyan", bold=True))
    click.echo(f"  Registry: {registry_url}")
    click.echo(f"  Key file: {key_path} ({'created' if created else 'loaded'})")

    assertion = sign_assertion(keypair, registry_url)
    try:
        result = asyncio.run(
            register_passport(keypair, registry_url, display_name=name, assertion=assertion)
        )
    except Exception as exc:
        click.echo(click.style(f"  ERROR: registration failed: {exc}", fg="red"))
        raise SystemExit(1) from exc

    click.echo(click.style("  Registered", fg="green", bold=True))
    click.echo(f"  DID:       {result.did}")
    click.echo(f"  Directory: {result.directory_url}")
    click.echo(f"  Assertion: bound to {assertion.payload.dir} until unix {assertion.payload.exp}")

    # When the registry serves per-tenant directory authorities, re-bind the
    # assertion to the agent's personal directory and print it — that URL is
    # what the agent should send as its Signature-Agent.
    status = asyncio.run(fetch_passport_status(registry_url, keypair.did))
    if status is not None and status.tenant_directory_url:
        tenant_assertion = sign_assertion(keypair, status.tenant_directory_url)
        try:
            asyncio.run(upload_assertion(keypair, registry_url, tenant_assertion))
            click.echo(f"  Assertion: re-bound to {tenant_assertion.payload.dir}")
        except Exception as exc:
            click.echo(click.style(f"  WARNING: tenant assertion upload failed: {exc}", fg="yellow"))
        click.echo(
            click.style(f"  Personal directory: {status.tenant_directory_url}", bold=True)
        )
    click.echo()


@passport.command("attest")
@click.option("--registry", default=None, help="Airlock registry URL (default: api.airlock.ing).")
@click.option(
    "--key-file",
    "key_file",
    default=None,
    type=click.Path(dir_okay=False),
    help="Passport key seed file (default: ~/.airlock/passport.key).",
)
@click.option("--days", default=7, show_default=True, type=int, help="Assertion validity in days.")
def passport_attest(registry: str | None, key_file: str | None, days: int) -> None:
    """Sign and upload a fresh directory assertion (possession proof).

    The assertion binds this passport key to the registry's directory
    for --days, and is published at the registry's well-known
    assertions endpoint. Requires a prior `airlock passport init`.
    """
    import asyncio
    from datetime import UTC, datetime

    from airlock.passport.assertions import sign_assertion
    from airlock.passport.registration import (
        DEFAULT_KEY_PATH,
        fetch_passport_status,
        upload_assertion,
    )

    key_path = Path(key_file) if key_file else DEFAULT_KEY_PATH
    if not key_path.exists():
        click.echo(click.style(f"  ERROR: no passport key at {key_path}", fg="red"))
        click.echo("  Run: airlock passport init")
        raise SystemExit(1)

    try:
        keypair, _, _ = _load_passport_key(key_file)
    except ValueError as exc:
        click.echo(click.style(f"  ERROR: {exc}", fg="red"))
        raise SystemExit(1) from exc
    if days < 1:
        click.echo(click.style("  ERROR: --days must be >= 1", fg="red"))
        raise SystemExit(1)

    registry_url = _default_registry(registry)

    # Bind to the agent's personal directory authority when the registry
    # advertises one (per-tenant directories); the flat registry origin
    # otherwise.
    status = asyncio.run(fetch_passport_status(registry_url, keypair.did))
    target_directory = registry_url
    if status is not None and status.tenant_directory_url:
        target_directory = status.tenant_directory_url
    assertion = sign_assertion(keypair, target_directory, validity_seconds=days * 86_400)

    click.echo()
    click.echo(click.style("  Airlock Passport Attest", fg="cyan", bold=True))
    click.echo(f"  Registry:   {registry_url}")
    click.echo(f"  Key:        {assertion.payload.sub}")
    click.echo(f"  Directory:  {assertion.payload.dir}")
    expires = datetime.fromtimestamp(assertion.payload.exp, tz=UTC).isoformat()
    click.echo(f"  Expires:    {expires}")

    try:
        asyncio.run(upload_assertion(keypair, registry_url, assertion))
    except Exception as exc:
        click.echo(click.style(f"  ERROR: assertion upload failed: {exc}", fg="red"))
        raise SystemExit(1) from exc

    click.echo(click.style("  Assertion uploaded", fg="green", bold=True))
    if status is not None and status.tenant_directory_url:
        click.echo(
            click.style(f"  Personal directory: {status.tenant_directory_url}", bold=True)
        )
    click.echo()


@passport.command("delegate")
@click.option("--scope", default=None, help="Opaque scope string embedded in the statement.")
@click.option(
    "--minutes", default=15, show_default=True, type=int, help="Delegation validity in minutes."
)
@click.option(
    "--key-file",
    "key_file",
    default=None,
    type=click.Path(dir_okay=False),
    help="Parent passport key seed file (default: ~/.airlock/passport.key).",
)
def passport_delegate(scope: str | None, minutes: int, key_file: str | None) -> None:
    """Mint a short-lived delegated child credential (EXPERIMENTAL).

    Prints JSON with the child's seed, DID and the Airlock-Delegation
    header value -- pipe it into a subprocess agent. The child signs the
    normal web-bot-auth profile with the parent's directory and dies
    with the delegation window; revoking the parent cuts it off early.
    """
    from datetime import UTC, datetime

    from airlock.passport.delegation import encode_delegation_header, mint_child
    from airlock.passport.registration import DEFAULT_KEY_PATH

    key_path = Path(key_file) if key_file else DEFAULT_KEY_PATH
    if not key_path.exists():
        click.echo(click.style(f"  ERROR: no passport key at {key_path}", fg="red"))
        click.echo("  Run: airlock passport init")
        raise SystemExit(1)
    if minutes < 1:
        click.echo(click.style("  ERROR: --minutes must be >= 1", fg="red"))
        raise SystemExit(1)

    try:
        keypair, _, _ = _load_passport_key(key_file)
    except ValueError as exc:
        click.echo(click.style(f"  ERROR: {exc}", fg="red"))
        raise SystemExit(1) from exc

    child, statement = mint_child(keypair, scope=scope, validity_seconds=minutes * 60)
    click.echo(
        json.dumps(
            {
                "child_seed_hex": child.signing_key.encode().hex(),
                "child_did": child.did,
                "child_thumbprint": statement.payload.child,
                "parent_thumbprint": statement.payload.parent,
                "scope": statement.payload.scope,
                "expires_at": datetime.fromtimestamp(
                    statement.payload.exp, tz=UTC
                ).isoformat(),
                "delegation_header": encode_delegation_header(statement),
            },
            indent=2,
        )
    )


@passport.command("request")
@click.argument("url")
@click.option("--method", default="GET", show_default=True, help="HTTP method.")
@click.option("--registry", default=None, help="Airlock registry URL (default: api.airlock.ing).")
@click.option(
    "--key-file",
    "key_file",
    default=None,
    type=click.Path(dir_okay=False),
    help="Passport key seed file (default: ~/.airlock/passport.key).",
)
def passport_request(url: str, method: str, registry: str | None, key_file: str | None) -> None:
    """Send one signed request to URL and print the status code."""
    import httpx

    from airlock.passport.httpx_auth import PassportAuth
    from airlock.passport.registration import DEFAULT_KEY_PATH, directory_url_for_registry
    from airlock.passport.signer import PassportSigner

    key_path = Path(key_file) if key_file else DEFAULT_KEY_PATH
    if not key_path.exists():
        click.echo(click.style(f"  ERROR: no passport key at {key_path}", fg="red"))
        click.echo("  Run: airlock passport init")
        raise SystemExit(1)

    try:
        keypair, _, _ = _load_passport_key(key_file)
    except ValueError as exc:
        click.echo(click.style(f"  ERROR: {exc}", fg="red"))
        raise SystemExit(1) from exc

    registry_url = _default_registry(registry)
    signer = PassportSigner(keypair, directory_url_for_registry(registry_url))
    try:
        with httpx.Client(auth=PassportAuth(signer), timeout=15.0) as client:
            response = client.request(method.upper(), url)
    except httpx.HTTPError as exc:
        click.echo(click.style(f"  ERROR: request failed: {exc}", fg="red"))
        raise SystemExit(1) from exc

    click.echo(f"{response.status_code}")


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
# Docs: https://github.com/airlock-protocol/airlock

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
