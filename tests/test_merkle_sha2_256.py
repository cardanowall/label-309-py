"""Merkle (RFC 9162 §2.1.1, SHA-256) tests.

Fixture bytes are inlined so this test is self-contained.
"""

from __future__ import annotations

import hashlib

import pytest

from cardanowall._crypto.merkle_sha2_256 import (
    MERKLE_ALG_ID,
    MerkleError,
    merkle_sha2_256_inclusion_proof,
    merkle_sha2_256_root,
    merkle_sha2_256_verify_inclusion,
)


def _d(plaintext: str) -> bytes:
    return hashlib.sha256(plaintext.encode("utf-8")).digest()


# Pinned `d_i = SHA-256("merkle-leaf-i")` for i = 0..6.
PINNED_D = {
    0: bytes.fromhex("b5e62a21038c1c2fdf28ad4d39ba6502e0568591c8647cac6998bfff67a25b3c"),
    1: bytes.fromhex("986aad6d251d450b9e7cd0c811e65bc95f95688060d963a83ab6505da350be56"),
    2: bytes.fromhex("27f4c2b7157b2e28b1a08e47fce1c3fa27a0f2c8a6760f5995c8a83c9cd1cacc"),
    3: bytes.fromhex("49707d9c71d5ebf72aaa3ada7a34e152d41811b345366681fc09849e8c634076"),
    4: bytes.fromhex("e1599f1d13ee839f0fe64c2d5697b9d098ea947053f2fd8033e93b5ea1da8970"),
    5: bytes.fromhex("7777a46ef6264ec24caf8239bea80bd6b3b1e38e9d3dc4f9daf6ce3722e8ba02"),
    6: bytes.fromhex("741c8f1001d6e807fac74c182d15f01fba2ed98375ca7a7cdc6257fdae97b621"),
}

# Pinned leaf hashes L_i = SHA-256(0x00 || d_i)
PINNED_L = {
    0: bytes.fromhex("b696b144b6e6815fb3e83cbd501bca5b3e509fd0d309d582a8329718b9516ccc"),
    1: bytes.fromhex("7c55458ad0046eaadabc4a77b312225471068b6e98aae84050312dd49fbd5db5"),
    2: bytes.fromhex("807ffa56924d0647034b00f8ce5517917ab065335048a1ea53f920c2274a2890"),
    3: bytes.fromhex("2c03e3ac9e4cf8ec8b505361e892e257ca59d91fa6a3b4741de9cd5962b62737"),
    4: bytes.fromhex("57fe46aac0fcd5d1392884b3523724bd145dcf9f70aa176318808ea56a9f8009"),
    5: bytes.fromhex("f03cea80d0e99780698a755e4684555e821c2af821f97058926caf8e2d7d2969"),
    6: bytes.fromhex("5bd8bd33c7e3c41a98511068b7dfea418b5a6c84ff53767a1c7c0565efb651f4"),
}

PINNED_H01 = bytes.fromhex("f44b533747be7db04b33260c722d24b7e8bc9231511cc1dd291bb9134cd9aaee")
PINNED_H23 = bytes.fromhex("1e4e22ce45fea38703a4c93994677fdb3b2602650c835bb7448c81a68a561363")
PINNED_H45 = bytes.fromhex("02c09225565b2fb10fd263edc6951200c743b9121192f68ba7967ffc8a6f1128")
PINNED_H0123 = bytes.fromhex("93a86cdff4f26f1a7c9793cc7c3ce107102570a81a323902617f7c13670582ee")
PINNED_H456 = bytes.fromhex("32f86b4111e8859b214cf501d1091023da954f169d8916dce42aa469c5795d17")


def test_alg_id_constant() -> None:
    assert MERKLE_ALG_ID == "rfc9162-sha256"


def test_plaintext_to_d_bytes_match_spec() -> None:
    """Cross-check the inline PINNED_D dict against the spec's hashing rule."""
    for i, expected in PINNED_D.items():
        assert _d(f"merkle-leaf-{i}") == expected


def test_1_leaf_root() -> None:
    # root = LH(d_0) = SHA-256(0x00 || d_0).
    root = merkle_sha2_256_root([PINNED_D[0]])
    assert root == PINNED_L[0]


def test_1_leaf_proof_and_verify() -> None:
    proof = merkle_sha2_256_inclusion_proof([PINNED_D[0]], 0)
    assert proof == []
    root = merkle_sha2_256_root([PINNED_D[0]])
    assert merkle_sha2_256_verify_inclusion(PINNED_D[0], 0, 1, proof, root) is True


def test_1_leaf_root_is_not_d0() -> None:
    """Single-leaf root MUST NOT equal d_0."""
    root = merkle_sha2_256_root([PINNED_D[0]])
    assert root != PINNED_D[0]


def test_2_leaf_root() -> None:
    root = merkle_sha2_256_root([PINNED_D[0], PINNED_D[1]])
    assert root == PINNED_H01


def test_2_leaf_proofs() -> None:
    leaves = [PINNED_D[0], PINNED_D[1]]
    root = merkle_sha2_256_root(leaves)
    p0 = merkle_sha2_256_inclusion_proof(leaves, 0)
    p1 = merkle_sha2_256_inclusion_proof(leaves, 1)
    assert p0 == [PINNED_L[1]]
    assert p1 == [PINNED_L[0]]
    assert merkle_sha2_256_verify_inclusion(PINNED_D[0], 0, 2, p0, root) is True
    assert merkle_sha2_256_verify_inclusion(PINNED_D[1], 1, 2, p1, root) is True


def test_3_leaf_root() -> None:
    # root = IH(IH(L0, L1), L2).
    leaves = [PINNED_D[0], PINNED_D[1], PINNED_D[2]]
    root = merkle_sha2_256_root(leaves)
    expected_root = bytes.fromhex(
        "2c5230105235655a072f552fddcbc78bf5a76e16476c882e8199f9fce20a8f55"
    )
    assert root == expected_root


def test_3_leaf_proofs() -> None:
    leaves = [PINNED_D[0], PINNED_D[1], PINNED_D[2]]
    root = merkle_sha2_256_root(leaves)
    p0 = merkle_sha2_256_inclusion_proof(leaves, 0)
    p1 = merkle_sha2_256_inclusion_proof(leaves, 1)
    p2 = merkle_sha2_256_inclusion_proof(leaves, 2)
    assert p0 == [PINNED_L[1], PINNED_L[2]]
    assert p1 == [PINNED_L[0], PINNED_L[2]]
    assert p2 == [PINNED_H01]
    for i, p in enumerate((p0, p1, p2)):
        ok = merkle_sha2_256_verify_inclusion(PINNED_D[i], i, 3, p, root)
        assert ok is True, f"3-leaf inclusion proof[{i}] failed"


def test_4_leaf_root() -> None:
    # Baseline — root pinned.
    leaves = [PINNED_D[i] for i in range(4)]
    root = merkle_sha2_256_root(leaves)
    assert root == PINNED_H0123


def test_4_leaf_proofs() -> None:
    leaves = [PINNED_D[i] for i in range(4)]
    root = merkle_sha2_256_root(leaves)
    p0 = merkle_sha2_256_inclusion_proof(leaves, 0)
    p1 = merkle_sha2_256_inclusion_proof(leaves, 1)
    p2 = merkle_sha2_256_inclusion_proof(leaves, 2)
    p3 = merkle_sha2_256_inclusion_proof(leaves, 3)
    assert p0 == [PINNED_L[1], PINNED_H23]
    assert p1 == [PINNED_L[0], PINNED_H23]
    assert p2 == [PINNED_L[3], PINNED_H01]
    assert p3 == [PINNED_L[2], PINNED_H01]
    for i, p in enumerate((p0, p1, p2, p3)):
        ok = merkle_sha2_256_verify_inclusion(PINNED_D[i], i, 4, p, root)
        assert ok is True, f"4-leaf inclusion proof[{i}] failed"


def test_5_leaf_root_and_proofs() -> None:
    leaves = [PINNED_D[i] for i in range(5)]
    root = merkle_sha2_256_root(leaves)
    expected_root = bytes.fromhex(
        "03928445a6003ca5f6a925cddb04a508116b06cf80037dca9e579ed41122fb9f"
    )
    assert root == expected_root
    expected = {
        0: [PINNED_L[1], PINNED_H23, PINNED_L[4]],
        1: [PINNED_L[0], PINNED_H23, PINNED_L[4]],
        2: [PINNED_L[3], PINNED_H01, PINNED_L[4]],
        3: [PINNED_L[2], PINNED_H01, PINNED_L[4]],
        4: [PINNED_H0123],
    }
    for i in range(5):
        p = merkle_sha2_256_inclusion_proof(leaves, i)
        assert p == expected[i], f"5-leaf proof[{i}] mismatch"
        assert merkle_sha2_256_verify_inclusion(PINNED_D[i], i, 5, p, root) is True


def test_7_leaf_root_and_proofs() -> None:
    leaves = [PINNED_D[i] for i in range(7)]
    root = merkle_sha2_256_root(leaves)
    expected_root = bytes.fromhex(
        "90306bf5dca8f89e7b253471148f3795e7a6c857f04924c8309d81375e79d987"
    )
    assert root == expected_root
    expected = {
        0: [PINNED_L[1], PINNED_H23, PINNED_H456],
        1: [PINNED_L[0], PINNED_H23, PINNED_H456],
        2: [PINNED_L[3], PINNED_H01, PINNED_H456],
        3: [PINNED_L[2], PINNED_H01, PINNED_H456],
        4: [PINNED_L[5], PINNED_L[6], PINNED_H0123],
        5: [PINNED_L[4], PINNED_L[6], PINNED_H0123],
        6: [PINNED_H45, PINNED_H0123],
    }
    for i in range(7):
        p = merkle_sha2_256_inclusion_proof(leaves, i)
        assert p == expected[i], f"7-leaf proof[{i}] mismatch"
        assert merkle_sha2_256_verify_inclusion(PINNED_D[i], i, 7, p, root) is True


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
