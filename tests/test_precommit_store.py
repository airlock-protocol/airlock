"""Tests for PreCommitmentStore persistence and in-memory operations."""

from __future__ import annotations

import os
from datetime import UTC, datetime

from airlock.rotation.precommit import PreRotationCommitment
from airlock.rotation.precommit_store import PreCommitmentStore


def _make_commitment(
    digest: str = "abcd1234",
    did: str = "did:key:z6MkTest",
) -> PreRotationCommitment:
    return PreRotationCommitment(
        alg="sha256",
        digest=digest,
        committed_at=datetime.now(UTC),
        committed_by_did=did,
        signature="sig_placeholder",
    )


class TestInMemory:
    """In-memory mode (path=None) — no disk I/O."""

    def test_in_memory_put_get(self) -> None:
        store = PreCommitmentStore()
        commitment = _make_commitment()
        store.put("chain_a", commitment)

        result = store.get("chain_a")
        assert result is not None
        assert result.digest == commitment.digest
        assert result.committed_by_did == commitment.committed_by_did

    def test_in_memory_delete(self) -> None:
        store = PreCommitmentStore()
        commitment = _make_commitment()
        store.put("chain_a", commitment)
        store.delete("chain_a")

        assert store.get("chain_a") is None

    def test_get_nonexistent(self) -> None:
        store = PreCommitmentStore()
        assert store.get("does_not_exist") is None

    def test_overwrite(self) -> None:
        store = PreCommitmentStore()
        first = _make_commitment(digest="first_digest")
        second = _make_commitment(digest="second_digest")

        store.put("chain_a", first)
        store.put("chain_a", second)

        result = store.get("chain_a")
        assert result is not None
        assert result.digest == "second_digest"

    def test_delete_nonexistent_no_error(self) -> None:
        store = PreCommitmentStore()
        store.delete("ghost")  # should not raise


class TestFilePersistence:
    """File-backed mode — data survives store recreation."""

    def test_persist_to_file(self, tmp_path: object) -> None:
        path = str(tmp_path) + "/precommit.json"  # type: ignore[operator]
        store = PreCommitmentStore(path=path)
        commitment = _make_commitment()
        store.put("chain_b", commitment)

        assert os.path.exists(path)

        store2 = PreCommitmentStore(path=path)
        result = store2.get("chain_b")
        assert result is not None
        assert result.digest == commitment.digest

    def test_atomic_write(self, tmp_path: object) -> None:
        path = str(tmp_path) + "/precommit.json"  # type: ignore[operator]
        store = PreCommitmentStore(path=path)
        store.put("chain_c", _make_commitment())

        assert os.path.exists(path)
        # Temp file should have been cleaned up by os.replace
        assert not os.path.exists(path + ".tmp")

    def test_survives_restart(self, tmp_path: object) -> None:
        path = str(tmp_path) + "/precommit.json"  # type: ignore[operator]
        commitment = _make_commitment(digest="survive_this")

        store1 = PreCommitmentStore(path=path)
        store1.put("chain_d", commitment)
        del store1  # simulate process exit

        store2 = PreCommitmentStore(path=path)
        result = store2.get("chain_d")
        assert result is not None
        assert result.digest == "survive_this"
        assert result.alg == "sha256"

    def test_delete_persists(self, tmp_path: object) -> None:
        path = str(tmp_path) + "/precommit.json"  # type: ignore[operator]
        store = PreCommitmentStore(path=path)
        store.put("chain_e", _make_commitment())
        store.delete("chain_e")

        store2 = PreCommitmentStore(path=path)
        assert store2.get("chain_e") is None

    def test_multiple_chains(self, tmp_path: object) -> None:
        path = str(tmp_path) + "/precommit.json"  # type: ignore[operator]
        store = PreCommitmentStore(path=path)
        store.put("chain_f", _make_commitment(digest="f_digest"))
        store.put("chain_g", _make_commitment(digest="g_digest"))

        store2 = PreCommitmentStore(path=path)
        assert store2.get("chain_f") is not None
        assert store2.get("chain_f").digest == "f_digest"  # type: ignore[union-attr]
        assert store2.get("chain_g") is not None
        assert store2.get("chain_g").digest == "g_digest"  # type: ignore[union-attr]
