"""Verifier nonce/replay cache tests (F3): the cache backends
(in-memory + Redis via fakeredis), PassportVerifier replay rejection and
``require_nonce``, wall middleware wiring, and a property test over
random nonce streams."""

from __future__ import annotations

import asyncio

import httpx
import pytest
from hypothesis import given
from hypothesis import strategies as st

from airlock.crypto.keys import KeyPair
from airlock.passport.base import DIRECTORY_MEDIA_TYPE
from airlock.passport.directory import build_directory
from airlock.passport.replay import InMemoryNonceCache, NonceCache, RedisNonceCache
from airlock.passport.signer import PassportSigner
from airlock.passport.verifier import PassportVerifier
from airlock.sdk.wall import PassportWallMiddleware

DIRECTORY_URL = "https://directory.test"
SITE_URL = "https://example.com/some/path?q=1"


@pytest.fixture
def keypair() -> KeyPair:
    return KeyPair.from_seed(b"replay_test_seed_000000000000000")


def make_verifier(kp: KeyPair, **kwargs: object) -> PassportVerifier:
    payload = build_directory([kp.verify_key]).model_dump_json(exclude_none=True)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200, content=payload, headers={"content-type": DIRECTORY_MEDIA_TYPE}
        )

    kwargs.setdefault("require_https", False)
    return PassportVerifier(transport=httpx.MockTransport(handler), **kwargs)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# InMemoryNonceCache
# ---------------------------------------------------------------------------


class TestInMemoryNonceCache:
    async def test_fresh_then_duplicate(self) -> None:
        cache = InMemoryNonceCache()
        assert await cache.add("kid", "n1", 60) is True
        assert await cache.add("kid", "n1", 60) is False
        assert await cache.add("kid", "n2", 60) is True

    async def test_keyids_are_independent(self) -> None:
        cache = InMemoryNonceCache()
        assert await cache.add("kid-a", "n", 60) is True
        assert await cache.add("kid-b", "n", 60) is True
        assert await cache.add("kid-a", "n", 60) is False

    async def test_entries_expire(self) -> None:
        clock = [1000.0]
        cache = InMemoryNonceCache(time_source=lambda: clock[0])
        assert await cache.add("kid", "n", 30) is True
        clock[0] += 29
        assert await cache.add("kid", "n", 30) is False
        clock[0] += 2  # past the original entry's expiry
        assert await cache.add("kid", "n", 30) is True

    async def test_max_entries_evicts_oldest(self) -> None:
        clock = [0.0]
        cache = InMemoryNonceCache(max_entries=2, time_source=lambda: clock[0])
        for i, nonce in enumerate(["a", "b", "c"]):
            clock[0] = float(i)
            assert await cache.add("kid", nonce, 1000) is True
        # "a" (oldest expiry) was evicted to hold the cap; it reads fresh.
        assert await cache.add("kid", "a", 1000) is True
        assert await cache.add("kid", "c", 1000) is False

    async def test_satisfies_protocol(self) -> None:
        assert isinstance(InMemoryNonceCache(), NonceCache)
        assert isinstance(RedisNonceCache(object()), NonceCache)


class TestRedisNonceCache:
    async def test_duplicate_detection_and_ttl(self) -> None:
        fakeredis = pytest.importorskip("fakeredis.aioredis")
        redis = fakeredis.FakeRedis(decode_responses=True)
        cache = RedisNonceCache(redis)
        assert await cache.add("kid", "n1", 0.4) is True  # sub-second ttl -> 1s floor
        assert await cache.add("kid", "n1", 60) is False
        assert await cache.add("other", "n1", 60) is True
        ttl = await redis.ttl("airlock:passport:nonce:kid:n1")
        assert ttl == 1
        await redis.aclose()


# ---------------------------------------------------------------------------
# Verifier integration
# ---------------------------------------------------------------------------


class TestVerifierReplay:
    async def test_identical_request_replay_rejected(self, keypair: KeyPair) -> None:
        signer = PassportSigner(keypair, DIRECTORY_URL)
        headers = signer.sign_request("GET", SITE_URL).as_headers()
        verifier = make_verifier(keypair, replay_cache=InMemoryNonceCache())

        first = await verifier.verify(method="GET", url=SITE_URL, headers=headers)
        assert first.valid is True
        second = await verifier.verify(method="GET", url=SITE_URL, headers=headers)
        assert second.valid is False
        assert second.failure_reason == "nonce replay detected"

    async def test_fresh_nonces_keep_passing(self, keypair: KeyPair) -> None:
        signer = PassportSigner(keypair, DIRECTORY_URL)
        verifier = make_verifier(keypair, replay_cache=InMemoryNonceCache())
        for _ in range(3):
            headers = signer.sign_request("GET", SITE_URL).as_headers()
            result = await verifier.verify(method="GET", url=SITE_URL, headers=headers)
            assert result.valid is True

    async def test_without_cache_replay_is_not_detected(self, keypair: KeyPair) -> None:
        """Unchanged default behavior: no cache, no replay rejection."""
        headers = PassportSigner(keypair, DIRECTORY_URL).sign_request("GET", SITE_URL)
        verifier = make_verifier(keypair)
        for _ in range(2):
            result = await verifier.verify(
                method="GET", url=SITE_URL, headers=headers.as_headers()
            )
            assert result.valid is True

    async def test_nonceless_signature_unchanged_without_require_nonce(
        self, keypair: KeyPair
    ) -> None:
        signer = PassportSigner(keypair, DIRECTORY_URL, include_nonce=False)
        headers = signer.sign_request("GET", SITE_URL).as_headers()
        verifier = make_verifier(keypair, replay_cache=InMemoryNonceCache())
        for _ in range(2):  # no nonce -> nothing to track, still valid
            result = await verifier.verify(method="GET", url=SITE_URL, headers=headers)
            assert result.valid is True

    async def test_require_nonce_rejects_nonceless(self, keypair: KeyPair) -> None:
        signer = PassportSigner(keypair, DIRECTORY_URL, include_nonce=False)
        headers = signer.sign_request("GET", SITE_URL).as_headers()
        verifier = make_verifier(keypair, require_nonce=True)
        result = await verifier.verify(method="GET", url=SITE_URL, headers=headers)
        assert result.valid is False
        assert result.failure_reason is not None
        assert "no nonce" in result.failure_reason

    async def test_invalid_signature_does_not_consume_nonce(
        self, keypair: KeyPair
    ) -> None:
        """A tampered request must not burn the nonce for the honest one."""
        signer = PassportSigner(keypair, DIRECTORY_URL)
        headers = signer.sign_request("GET", SITE_URL).as_headers()
        verifier = make_verifier(keypair, replay_cache=InMemoryNonceCache())

        tampered = await verifier.verify(
            method="GET", url="https://evil.example/", headers=headers
        )
        assert tampered.valid is False
        genuine = await verifier.verify(method="GET", url=SITE_URL, headers=headers)
        assert genuine.valid is True


# ---------------------------------------------------------------------------
# Property: replay detection over random nonce streams
# ---------------------------------------------------------------------------


@given(
    nonces=st.lists(
        st.text(alphabet="abcdefghijklmnopqrstuvwxyz0123456789+/=", min_size=1, max_size=16),
        min_size=1,
        max_size=25,
    )
)
def test_replay_cache_property(nonces: list[str]) -> None:
    """First sighting of each distinct nonce is fresh; every repeat is a
    replay, regardless of ordering."""

    async def scenario() -> None:
        cache = InMemoryNonceCache()
        seen: set[str] = set()
        for nonce in nonces:
            expected = nonce not in seen
            assert await cache.add("kid", nonce, 600) is expected
            seen.add(nonce)

    asyncio.run(scenario())


# ---------------------------------------------------------------------------
# Wall middleware wiring
# ---------------------------------------------------------------------------


class TestWallReplayWiring:
    async def test_middleware_rejects_replayed_request(self, keypair: KeyPair) -> None:
        from fastapi import FastAPI

        site = FastAPI()

        @site.get("/")
        async def home() -> dict[str, str]:
            return {"ok": "yes"}

        payload = build_directory([keypair.verify_key]).model_dump_json(exclude_none=True)

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200, content=payload, headers={"content-type": DIRECTORY_MEDIA_TYPE}
            )

        verifier = PassportVerifier(
            transport=httpx.MockTransport(handler),
            require_https=False,
            replay_cache=InMemoryNonceCache(),
        )
        site.add_middleware(PassportWallMiddleware, verifier=verifier)

        signed = PassportSigner(keypair, DIRECTORY_URL).sign_request(
            "GET", "http://protected.test/"
        )
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=site), base_url="http://protected.test"
        ) as client:
            first = await client.get("/", headers=signed.as_headers())
            second = await client.get("/", headers=signed.as_headers())

        assert first.status_code == 200
        assert second.status_code == 403
        body = second.json()
        assert body["error"] == "passport_invalid"
        assert "replay" in body["detail"]

    async def test_default_wall_constructs_replay_verifier(self, keypair: KeyPair) -> None:
        middleware = PassportWallMiddleware(
            lambda scope, receive, send: None,  # type: ignore[arg-type,return-value]
            replay_cache=InMemoryNonceCache(),
            require_nonce=True,
        )
        verifier = middleware._gate._verifier
        assert verifier._replay_cache is not None  # noqa: SLF001 - wiring check
        assert verifier._require_nonce is True  # noqa: SLF001

    async def test_custom_verifier_with_replay_args_is_an_error(
        self, keypair: KeyPair
    ) -> None:
        with pytest.raises(ValueError, match="replay"):
            PassportWallMiddleware(
                lambda scope, receive, send: None,  # type: ignore[arg-type,return-value]
                verifier=make_verifier(keypair),
                replay_cache=InMemoryNonceCache(),
            )
