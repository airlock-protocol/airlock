"""The CLI must report the installed package version, not a hardcoded one.

`airlock --version` previously carried its own literal, which drifted to
0.4.0 while the package was at 1.0.0 — so anyone checking which release
they had was told the wrong answer.
"""

from __future__ import annotations

from importlib.metadata import version

from click.testing import CliRunner

from airlock.cli import cli

PACKAGE_NAME = "airlock-protocol"


def test_cli_version_matches_installed_package() -> None:
    result = CliRunner().invoke(cli, ["--version"])

    assert result.exit_code == 0
    assert version(PACKAGE_NAME) in result.output


def test_cli_version_is_not_hardcoded_to_a_stale_release() -> None:
    """Guards the specific regression: a literal left behind by a bump."""
    installed = version(PACKAGE_NAME)
    result = CliRunner().invoke(cli, ["--version"])

    assert "0.4.0" not in result.output or installed == "0.4.0"
