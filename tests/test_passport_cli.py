"""CLI tests: ``airlock passport init`` / ``airlock passport request``
against an in-process gateway (uvicorn on a loopback port, since the CLI
drives its own event loop and real HTTP stack)."""

from __future__ import annotations

import socket
import threading
import time
from collections.abc import Iterator
from pathlib import Path

import pytest
import uvicorn
from click.testing import CliRunner

from airlock.cli import cli
from airlock.config import AirlockConfig
from airlock.gateway.app import create_app


class _GatewayThread:
    def __init__(self, tmp_path: Path) -> None:
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            self.port = int(sock.getsockname()[1])
        app = create_app(
            AirlockConfig(lancedb_path=f"{tmp_path}/cli.lance", passport_enabled=True)
        )
        self._server = uvicorn.Server(
            uvicorn.Config(app, host="127.0.0.1", port=self.port, log_level="warning")
        )
        self._thread = threading.Thread(target=self._server.run, daemon=True)

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def start(self) -> None:
        self._thread.start()
        deadline = time.monotonic() + 30
        while not self._server.started:
            if time.monotonic() > deadline:
                raise RuntimeError("gateway did not start in time")
            time.sleep(0.05)

    def stop(self) -> None:
        self._server.should_exit = True
        self._thread.join(timeout=10)


@pytest.fixture
def gateway(tmp_path: Path) -> Iterator[_GatewayThread]:
    server = _GatewayThread(tmp_path)
    server.start()
    try:
        yield server
    finally:
        server.stop()


def test_passport_init_registers_and_is_idempotent(
    gateway: _GatewayThread, tmp_path: Path
) -> None:
    runner = CliRunner()
    key_file = tmp_path / "keys" / "passport.key"

    result = runner.invoke(
        cli,
        ["passport", "init", "--registry", gateway.url, "--key-file", str(key_file)],
    )
    assert result.exit_code == 0, result.output
    assert "Registered" in result.output
    assert "did:key:z6Mk" in result.output
    assert "/.well-known/http-message-signatures-directory" in result.output
    assert key_file.exists()
    seed_first = key_file.read_text(encoding="utf-8").strip()
    assert len(seed_first) == 64

    # Re-run: same key is reused, registration upserts, still exit 0.
    result2 = runner.invoke(
        cli,
        ["passport", "init", "--registry", gateway.url, "--key-file", str(key_file)],
    )
    assert result2.exit_code == 0, result2.output
    assert "(loaded)" in result2.output
    assert key_file.read_text(encoding="utf-8").strip() == seed_first


def test_passport_request_prints_status_code(
    gateway: _GatewayThread, tmp_path: Path
) -> None:
    runner = CliRunner()
    key_file = tmp_path / "passport.key"
    init = runner.invoke(
        cli,
        ["passport", "init", "--registry", gateway.url, "--key-file", str(key_file)],
    )
    assert init.exit_code == 0, init.output

    result = runner.invoke(
        cli,
        [
            "passport",
            "request",
            f"{gateway.url}/live",
            "--registry",
            gateway.url,
            "--key-file",
            str(key_file),
        ],
    )
    assert result.exit_code == 0, result.output
    assert result.output.strip().endswith("200")


def test_passport_request_without_key_fails_cleanly(tmp_path: Path) -> None:
    runner = CliRunner()
    result = runner.invoke(
        cli,
        [
            "passport",
            "request",
            "http://127.0.0.1:9/nothing",
            "--key-file",
            str(tmp_path / "missing.key"),
        ],
    )
    assert result.exit_code == 1
    assert "no passport key" in result.output
