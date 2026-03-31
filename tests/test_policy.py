from __future__ import annotations

from airlock.gateway.policy import parse_did_allowlist


def test_parse_did_allowlist_empty() -> None:
    assert parse_did_allowlist("") is None
    assert parse_did_allowlist("   ") is None


def test_parse_did_allowlist_csv() -> None:
    s = parse_did_allowlist(" did:key:a , did:key:b ")
    assert s == frozenset({"did:key:a", "did:key:b"})
