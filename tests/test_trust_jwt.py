from __future__ import annotations

import pytest
from jwt import PyJWTError

from airlock.trust_jwt import decode_trust_token, mint_verified_trust_token


def test_mint_and_decode_roundtrip() -> None:
    secret = "unit_test_hs256_secret_minimum_length_ok"
    tok = mint_verified_trust_token(
        subject_did="did:key:testsub",
        session_id="sess-1",
        trust_score=0.82,
        issuer_did="did:key:gw",
        secret=secret,
        ttl_seconds=120,
    )
    claims = decode_trust_token(tok, secret)
    assert claims["sub"] == "did:key:testsub"
    assert claims["sid"] == "sess-1"
    assert claims["ver"] == "VERIFIED"
    assert claims["ts"] == pytest.approx(0.82)
    assert claims["iss"] == "did:key:gw"


def test_decode_rejects_wrong_secret() -> None:
    tok = mint_verified_trust_token(
        subject_did="did:key:a",
        session_id="s",
        trust_score=0.5,
        issuer_did="did:key:gw",
        secret="unit_test_jwt_secret_one_32bytes_min__",
        ttl_seconds=60,
    )
    with pytest.raises(PyJWTError):
        decode_trust_token(tok, "unit_test_jwt_secret_two_32bytes_min__")
