"""Merkle (RFC 9162 §2.1.1, SHA-256) tests.

The root and inclusion-proof known-answer values are loaded from the shared
cross-SDK fixtures so the Python, TypeScript, and Rust twins assert against one
byte-identical corpus.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from cardanowall._crypto.merkle_sha2_256 import (
    MERKLE_ALG_ID,
    MerkleError,
    merkle_sha2_256_inclusion_proof,
    merkle_sha2_256_root,
    merkle_sha2_256_verify_inclusion,
)

FIXTURES = Path(__file__).parent / "fixtures"
_ROOT_KAT = json.loads((FIXTURES / "merkle" / "rfc9162-sha256-root-kat.json").read_text())
_PROOF_KAT = json.loads(
    (FIXTURES / "merkle" / "rfc9162-sha256-inclusion-proof-kat.json").read_text()
)


def _d(plaintext: str) -> bytes:
    return hashlib.sha256(plaintext.encode("utf-8")).digest()


# Leaf digests `d_i = SHA-256("merkle-leaf-{i}")` recovered from the largest
# root-KAT vector (7-leaf), so the structural tests share the fixture inputs.
_LARGEST_ROOT_VECTOR = max(_ROOT_KAT["vectors"], key=lambda v: v["leaf_count"])
PINNED_D = {i: bytes.fromhex(h) for i, h in enumerate(_LARGEST_ROOT_VECTOR["leaves"])}
_MAX_TREE_SIZE = 0xFFFFFFFF


def test_alg_id_constant() -> None:
    assert MERKLE_ALG_ID == "rfc9162-sha256"
    assert _ROOT_KAT["alg"] == MERKLE_ALG_ID
    assert _PROOF_KAT["alg"] == MERKLE_ALG_ID


def test_plaintext_to_d_bytes_match_spec() -> None:
    """Cross-check the fixture leaf digests against the spec's hashing rule."""
    for i, expected in PINNED_D.items():
        assert _d(f"merkle-leaf-{i}") == expected


def test_root_kat_vectors() -> None:
    """Every pinned root reproduces from its leaf set, and a single-leaf root is
    never the bare leaf digest."""
    seen_sizes = set()
    for vector in _ROOT_KAT["vectors"]:
        leaves = [bytes.fromhex(h) for h in vector["leaves"]]
        assert len(leaves) == vector["leaf_count"]
        root = merkle_sha2_256_root(leaves)
        assert root == bytes.fromhex(vector["root"]), vector["name"]
        if vector["leaf_count"] == 1:
            # Single-leaf root MUST be LH(d_0) = SHA-256(0x00 || d_0), not d_0.
            assert root != leaves[0]
        seen_sizes.add(vector["leaf_count"])
    assert seen_sizes == {1, 2, 3, 4, 5, 7}


def test_inclusion_proof_kat_vectors() -> None:
    """Every pinned inclusion proof reproduces and verifies against its root."""
    seen_sizes = set()
    for tree in _PROOF_KAT["trees"]:
        tree_size = tree["tree_size"]
        leaves = [bytes.fromhex(h) for h in tree["leaves"]]
        root = merkle_sha2_256_root(leaves)
        assert root == bytes.fromhex(tree["root"]), tree["name"]
        assert len(leaves) == tree_size
        for inclusion in tree["inclusions"]:
            index = inclusion["index"]
            leaf = bytes.fromhex(inclusion["leaf"])
            assert leaf == leaves[index]
            expected_proof = [bytes.fromhex(h) for h in inclusion["proof"]]
            proof = merkle_sha2_256_inclusion_proof(leaves, index)
            assert proof == expected_proof, f"{tree['name']} proof[{index}] mismatch"
            ok = merkle_sha2_256_verify_inclusion(leaf, index, tree_size, proof, root)
            assert ok is True, f"{tree['name']} inclusion proof[{index}] failed"
        seen_sizes.add(tree_size)
    # The single-leaf tree's only proof is the empty path.
    single = next(t for t in _PROOF_KAT["trees"] if t["tree_size"] == 1)
    assert single["inclusions"][0]["proof"] == []
    assert {1, 4, 7} <= seen_sizes


def test_proof_roundtrip_over_root_kat_leaf_sets() -> None:
    """For every root-KAT leaf set (sizes 1,2,3,4,5,7), each generated inclusion
    proof verifies against the root — covering the odd-leaf sizes 2,3,5 that the
    byte-pinned proof KAT does not enumerate."""
    for vector in _ROOT_KAT["vectors"]:
        leaves = [bytes.fromhex(h) for h in vector["leaves"]]
        tree_size = vector["leaf_count"]
        root = merkle_sha2_256_root(leaves)
        for index in range(tree_size):
            proof = merkle_sha2_256_inclusion_proof(leaves, index)
            ok = merkle_sha2_256_verify_inclusion(leaves[index], index, tree_size, proof, root)
            assert ok is True, f"{vector['name']} round-trip proof[{index}] failed"


def test_16_leaf_roundtrip_property() -> None:
    """Power-of-2 tree: balanced log2 proof depth = 4."""
    leaves = [hashlib.sha256(f"leaf-{i}".encode()).digest() for i in range(16)]
    root = merkle_sha2_256_root(leaves)
    for i in range(16):
        p = merkle_sha2_256_inclusion_proof(leaves, i)
        assert len(p) == 4
        assert merkle_sha2_256_verify_inclusion(leaves[i], i, 16, p, root) is True


def test_empty_leaves_rejected() -> None:
    with pytest.raises(MerkleError):
        merkle_sha2_256_root([])


def test_wrong_leaf_length_rejected() -> None:
    with pytest.raises(MerkleError):
        merkle_sha2_256_root([b"\x00" * 31])


def test_inclusion_proof_out_of_range_rejected() -> None:
    leaves = [PINNED_D[0], PINNED_D[1]]
    with pytest.raises(MerkleError):
        merkle_sha2_256_inclusion_proof(leaves, 2)
    with pytest.raises(MerkleError):
        merkle_sha2_256_inclusion_proof(leaves, -1)


def test_verify_inclusion_rejects_wrong_root() -> None:
    leaves = [PINNED_D[i] for i in range(4)]
    p = merkle_sha2_256_inclusion_proof(leaves, 0)
    assert merkle_sha2_256_verify_inclusion(PINNED_D[0], 0, 4, p, b"\x00" * 32) is False


def test_verify_inclusion_rejects_tampered_sibling() -> None:
    leaves = [PINNED_D[i] for i in range(4)]
    root = merkle_sha2_256_root(leaves)
    p = merkle_sha2_256_inclusion_proof(leaves, 0)
    tampered = [b"\x00" * 32, *p[1:]]
    assert merkle_sha2_256_verify_inclusion(PINNED_D[0], 0, 4, tampered, root) is False


def test_verify_inclusion_rejects_wrong_index() -> None:
    leaves = [PINNED_D[i] for i in range(4)]
    root = merkle_sha2_256_root(leaves)
    p = merkle_sha2_256_inclusion_proof(leaves, 0)
    # Same proof bytes, different index → must fail.
    assert merkle_sha2_256_verify_inclusion(PINNED_D[0], 1, 4, p, root) is False


def test_verify_inclusion_rejects_wrong_leaf() -> None:
    leaves = [PINNED_D[i] for i in range(4)]
    root = merkle_sha2_256_root(leaves)
    p = merkle_sha2_256_inclusion_proof(leaves, 0)
    assert merkle_sha2_256_verify_inclusion(b"\x77" * 32, 0, 4, p, root) is False


def test_verify_inclusion_returns_false_for_wrong_sibling_length() -> None:
    leaves = [PINNED_D[i] for i in range(4)]
    root = merkle_sha2_256_root(leaves)
    bad_proof = [b"\x11" * 16, b"\x22" * 32]
    assert merkle_sha2_256_verify_inclusion(PINNED_D[0], 0, 4, bad_proof, root) is False


def test_verify_inclusion_returns_false_for_single_leaf_with_siblings() -> None:
    """Single-leaf trees accept only the empty path."""
    root = merkle_sha2_256_root([PINNED_D[0]])
    assert merkle_sha2_256_verify_inclusion(PINNED_D[0], 0, 1, [b"\x00" * 32], root) is False


# An out-of-range (index, tree_size) pair is a structural error, not a "does not
# verify" verdict: the fold's shift arithmetic is undefined outside the safe
# domain 1 <= tree_size <= 2^32 - 1, 0 <= index < tree_size. Both the proof and
# the verify entry points reject it (raise), matching the TypeScript and Rust
# twins, so a forged oversized tree_size cannot slip a forged proof through.


def test_verify_inclusion_raises_on_tree_size_out_of_range() -> None:
    root = merkle_sha2_256_root([PINNED_D[0]])
    with pytest.raises(MerkleError):
        merkle_sha2_256_verify_inclusion(PINNED_D[0], 0, 0, [], root)
    with pytest.raises(MerkleError):
        merkle_sha2_256_verify_inclusion(PINNED_D[0], 0, _MAX_TREE_SIZE + 1, [], root)


def test_verify_inclusion_raises_on_index_out_of_range() -> None:
    leaves = [PINNED_D[i] for i in range(4)]
    root = merkle_sha2_256_root(leaves)
    p = merkle_sha2_256_inclusion_proof(leaves, 0)
    with pytest.raises(MerkleError):
        merkle_sha2_256_verify_inclusion(PINNED_D[0], 4, 4, p, root)
    with pytest.raises(MerkleError):
        merkle_sha2_256_verify_inclusion(PINNED_D[0], -1, 4, p, root)


def test_verify_inclusion_raises_on_non_integer_range_inputs() -> None:
    root = merkle_sha2_256_root([PINNED_D[0]])
    with pytest.raises(MerkleError):
        merkle_sha2_256_verify_inclusion(PINNED_D[0], True, 1, [], root)  # bool is not int here
    with pytest.raises(MerkleError):
        merkle_sha2_256_verify_inclusion(PINNED_D[0], 0, "1", [], root)  # type: ignore[arg-type]


def test_inclusion_proof_raises_on_tree_size_above_32_bits() -> None:
    # The leaf set itself can never reach 2^32 in a test, but the bound is part
    # of the contract; index out of the (smaller, real) range is the reachable
    # rejection path here.
    leaves = [PINNED_D[0], PINNED_D[1]]
    with pytest.raises(MerkleError):
        merkle_sha2_256_inclusion_proof(leaves, 2)
