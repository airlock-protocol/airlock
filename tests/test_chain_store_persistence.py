"""Tests for RotationChainRegistry JSON persistence."""

from __future__ import annotations

import os

import pytest

from airlock.rotation.chain import RotationChainRegistry, compute_chain_id


def _fake_pubkey(seed: int = 0) -> bytes:
    """Generate a deterministic 32-byte fake public key."""
    return bytes([seed % 256]) * 32


class TestChainPersistence:
    """Verify chain records survive store recreation from disk."""

    def test_chain_persists_to_file(self, tmp_path: object) -> None:
        path = str(tmp_path) + "/chains.json"  # type: ignore[operator]
        pubkey = _fake_pubkey(1)
        chain_id = compute_chain_id(pubkey)

        reg1 = RotationChainRegistry(path=path)
        reg1.register_chain("did:key:z6MkAlice", pubkey)
        assert os.path.exists(path)
        del reg1

        reg2 = RotationChainRegistry(path=path)
        record = reg2.get_chain(chain_id)
        assert record is not None
        assert record.current_did == "did:key:z6MkAlice"
        assert record.rotation_count == 0

    def test_rotation_persists(self, tmp_path: object) -> None:
        path = str(tmp_path) + "/chains.json"  # type: ignore[operator]
        pubkey = _fake_pubkey(2)
        chain_id = compute_chain_id(pubkey)

        reg1 = RotationChainRegistry(path=path)
        reg1.register_chain("did:key:z6MkBob", pubkey)
        reg1.rotate(
            old_did="did:key:z6MkBob",
            new_did="did:key:z6MkBob2",
            chain_id=chain_id,
        )
        del reg1

        reg2 = RotationChainRegistry(path=path)
        record = reg2.get_chain(chain_id)
        assert record is not None
        assert record.current_did == "did:key:z6MkBob2"
        assert record.rotation_count == 1
        assert "did:key:z6MkBob" in record.previous_dids

    def test_rotated_from_persists(self, tmp_path: object) -> None:
        path = str(tmp_path) + "/chains.json"  # type: ignore[operator]
        pubkey = _fake_pubkey(3)
        chain_id = compute_chain_id(pubkey)

        reg1 = RotationChainRegistry(path=path)
        reg1.register_chain("did:key:z6MkCarol", pubkey)
        reg1.rotate(
            old_did="did:key:z6MkCarol",
            new_did="did:key:z6MkCarol2",
            chain_id=chain_id,
        )
        del reg1

        reg2 = RotationChainRegistry(path=path)
        # First-write-wins: re-rotating old DID should fail
        with pytest.raises(ValueError, match="already been rotated"):
            reg2.rotate(
                old_did="did:key:z6MkCarol",
                new_did="did:key:z6MkCarol3",
                chain_id=chain_id,
            )

    def test_did_index_rebuilt_on_load(self, tmp_path: object) -> None:
        path = str(tmp_path) + "/chains.json"  # type: ignore[operator]
        pubkey = _fake_pubkey(4)
        chain_id = compute_chain_id(pubkey)

        reg1 = RotationChainRegistry(path=path)
        reg1.register_chain("did:key:z6MkDave", pubkey)
        reg1.rotate(
            old_did="did:key:z6MkDave",
            new_did="did:key:z6MkDave2",
            chain_id=chain_id,
        )
        del reg1

        reg2 = RotationChainRegistry(path=path)
        # Current DID lookup
        assert reg2.get_chain_id_for_did("did:key:z6MkDave2") == chain_id
        # Historical DID lookup
        assert reg2.get_chain_id_for_did("did:key:z6MkDave") == chain_id
        # Both belong to the same chain
        assert reg2.are_same_chain("did:key:z6MkDave", "did:key:z6MkDave2")

    def test_in_memory_no_file_created(self) -> None:
        reg = RotationChainRegistry()
        pubkey = _fake_pubkey(5)
        reg.register_chain("did:key:z6MkEve", pubkey)
        # No path => no file written; just confirm no exception
        chain_id = compute_chain_id(pubkey)
        assert reg.get_chain(chain_id) is not None

    def test_atomic_write_no_tmp_leftover(self, tmp_path: object) -> None:
        path = str(tmp_path) + "/chains.json"  # type: ignore[operator]
        reg = RotationChainRegistry(path=path)
        reg.register_chain("did:key:z6MkFrank", _fake_pubkey(6))

        assert os.path.exists(path)
        assert not os.path.exists(path + ".tmp")
