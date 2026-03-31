"""Gateway policy helpers (allowlists, parsing)."""

from __future__ import annotations


def parse_did_allowlist(raw: str) -> frozenset[str] | None:
    """Parse comma-separated DIDs; empty / whitespace-only string → None (no restriction)."""
    items = tuple(x.strip() for x in (raw or "").split(",") if x.strip())
    return frozenset(items) if items else None
