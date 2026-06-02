"""Smoke test for the public ``cardanowall.merkle`` namespace.

Asserts that every re-export resolves and that a tiny 4-leaf round-trip
(root → inclusion proof → verify) succeeds. The deep KAT coverage already
lives in ``tests/test_merkle_sha2_256.py`` and ``tests/test_merkle_leaves_list.py``
(cross-language byte parity is enforced by the shared fixtures); we do NOT
duplicate that surface here. The only contract this file owns is "the SDK
re-export barrel is correctly wired."
"""

from __future__ import annotations

import hashlib

import pytest

from cardanowall.merkle import (
    LEAVES_LIST_FORMAT_V1,
    MERKLE_ALG_ID,
    MerkleLeavesListError,
    decode_leaves_list,
    encode_leaves_list,
    merkle_sha2_256_inclusion_proof,
    merkle_sha2_256_root,
    merkle_sha2_256_verify_inclusion,
)


def _make_leaf(seed: int) -> bytes:
    return hashlib.sha256(bytes([seed & 0xFF])).digest()


def test_merkle_alg_id_and_leaves_list_format_constants() -> None:
    assert MERKLE_ALG_ID == "rfc9162-sha256"
    assert LEAVES_LIST_FORMAT_V1 == "cardano-poe-merkle-leaves-v1"


def test_round_trips_a_four_leaf_tree() -> None:
    leaves = [_make_leaf(i) for i in range(4)]
    root = merkle_sha2_256_root(leaves)
    assert isinstance(root, bytes)
    assert len(root) == 32

    for i in range(len(leaves)):
        proof = merkle_sha2_256_inclusion_proof(leaves, i)
        # RFC 9162 audit-path length for a 4-leaf tree is log2(4) = 2.
        assert len(proof) == 2
        assert merkle_sha2_256_verify_inclusion(
            leaf=leaves[i], index=i, tree_size=len(leaves), proof=proof, root=root
        )


def test_leaves_list_encode_decode_round_trip() -> None:
    leaves = [_make_leaf(10), _make_leaf(11)]
    root = merkle_sha2_256_root(leaves)
    cbor = encode_leaves_list(leaves=leaves, root=root)
    decoded = decode_leaves_list(cbor)
    assert decoded["format"] == LEAVES_LIST_FORMAT_V1
    assert decoded["tree_alg"] == "rfc9162-sha256"
    assert decoded["leaf_count"] == 2
    assert len(decoded["leaves"]) == 2


def test_decode_surfaces_typed_error() -> None:
    # Negative path — a non-CBOR buffer surfaces the typed error class.
    with pytest.raises(MerkleLeavesListError):
        decode_leaves_list(b"\xff\xff\xff")
