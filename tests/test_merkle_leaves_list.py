"""CIP-309 Merkle leaves-list codec tests.

The 4-leaf canonical CBOR bytes pinned below (275 bytes) drive the
byte-identical encode/decode round-trip.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from cardanowall._crypto.merkle_leaves_list import (
    DEFAULT_TREE_ALG,
    LEAVES_LIST_FORMAT_V1,
    MerkleLeavesListError,
    decode_leaves_list,
    encode_leaves_list,
)
from cardanowall._crypto.merkle_sha2_256 import merkle_sha2_256_root

# 4-leaf fixture inputs.
PINNED_LEAVES = [
    bytes.fromhex("b5e62a21038c1c2fdf28ad4d39ba6502e0568591c8647cac6998bfff67a25b3c"),
    bytes.fromhex("986aad6d251d450b9e7cd0c811e65bc95f95688060d963a83ab6505da350be56"),
    bytes.fromhex("27f4c2b7157b2e28b1a08e47fce1c3fa27a0f2c8a6760f5995c8a83c9cd1cacc"),
    bytes.fromhex("49707d9c71d5ebf72aaa3ada7a34e152d41811b345366681fc09849e8c634076"),
]
PINNED_ROOT = bytes.fromhex("93a86cdff4f26f1a7c9793cc7c3ce107102570a81a323902617f7c13670582ee")

# Expected canonical-CBOR leaves-list bytes (275 B).
PINNED_LEAVES_LIST_CBOR = bytes.fromhex(
    "a664726f6f74582093a86cdff4f26f1a7c9793cc7c3ce107102570a81a323902617f7c13670582ee"
    "66666f726d6174781c63617264616e6f2d706f652d6d65726b6c652d6c65617665732d7631666c65"
    "61766573845820b5e62a21038c1c2fdf28ad4d39ba6502e0568591c8647cac6998bfff67a25b3c58"
    "20986aad6d251d450b9e7cd0c811e65bc95f95688060d963a83ab6505da350be56582027f4c2b715"
    "7b2e28b1a08e47fce1c3fa27a0f2c8a6760f5995c8a83c9cd1cacc582049707d9c71d5ebf72aaa3a"
    "da7a34e152d41811b345366681fc09849e8c634076686c6561665f616c6768736861322d32353668"
    "747265655f616c676e726663393136322d7368613235366a6c6561665f636f756e7404"
)


def test_constants_are_canonical_v1() -> None:
    assert LEAVES_LIST_FORMAT_V1 == "cardano-poe-merkle-leaves-v1"
    assert DEFAULT_TREE_ALG == "rfc9162-sha256"


def test_encode_matches_pinned_cbor_bytes() -> None:
    """Encoded bytes MUST match the pinned 275-byte CBOR."""
    out = encode_leaves_list(leaves=PINNED_LEAVES, root=PINNED_ROOT, leaf_alg="sha2-256")
    assert out == PINNED_LEAVES_LIST_CBOR
    assert len(out) == 275


def test_decode_returns_canonical_dict() -> None:
    decoded = decode_leaves_list(PINNED_LEAVES_LIST_CBOR)
    assert decoded["format"] == LEAVES_LIST_FORMAT_V1
    assert decoded["tree_alg"] == DEFAULT_TREE_ALG
    assert decoded["root"] == PINNED_ROOT
    assert decoded["leaves"] == PINNED_LEAVES
    assert decoded["leaf_count"] == 4
    assert decoded["leaf_alg"] == "sha2-256"


def test_decode_root_matches_recomputed_root() -> None:
    """Sanity: the decoded leaves recompute to the same root as the on-chain commit."""
    decoded = decode_leaves_list(PINNED_LEAVES_LIST_CBOR)
    recomputed = merkle_sha2_256_root(decoded["leaves"])
    assert recomputed == decoded["root"]


def test_round_trip_without_leaf_alg() -> None:
    encoded = encode_leaves_list(leaves=PINNED_LEAVES, root=PINNED_ROOT)
    decoded = decode_leaves_list(encoded)
    assert "leaf_alg" not in decoded
    assert decoded["leaf_count"] == 4
    assert decoded["root"] == PINNED_ROOT


def _build_blob(fmt: str, leaf_count: int) -> bytes:
    from cardanowall._crypto.cbor import (
        CanonicalCborValue,
        encode_canonical_cbor,
    )

    payload: dict[str | int, CanonicalCborValue] = {
        "format": fmt,
        "tree_alg": DEFAULT_TREE_ALG,
        "root": PINNED_ROOT,
        "leaves": [bytes(leaf) for leaf in PINNED_LEAVES],
        "leaf_count": leaf_count,
    }
    return encode_canonical_cbor(payload)


def test_decode_rejects_unknown_format() -> None:
    blob = _build_blob("cardano-poe-merkle-leaves-v2", 4)
    with pytest.raises(MerkleLeavesListError) as exc:
        decode_leaves_list(blob)
    assert exc.value.code == "SCHEMA_MERKLE_LEAVES_FORMAT_UNSUPPORTED"


def test_decode_rejects_leaf_count_mismatch() -> None:
    blob = _build_blob(LEAVES_LIST_FORMAT_V1, 99)
    with pytest.raises(MerkleLeavesListError) as exc:
        decode_leaves_list(blob)
    assert exc.value.code == "SCHEMA_MERKLE_LEAF_COUNT_MISMATCH"


def test_encode_rejects_non_32_byte_leaf() -> None:
    bad_leaves = [PINNED_LEAVES[0], b"\x00" * 16]
    with pytest.raises(MerkleLeavesListError) as exc:
        encode_leaves_list(leaves=bad_leaves, root=PINNED_ROOT)
    assert exc.value.code == "SCHEMA_MERKLE_LEAVES_MALFORMED"


def test_encode_rejects_empty_leaves() -> None:
    with pytest.raises(MerkleLeavesListError) as exc:
        encode_leaves_list(leaves=[], root=PINNED_ROOT)
    assert exc.value.code == "SCHEMA_MERKLE_LEAVES_MALFORMED"


def test_encode_rejects_wrong_length_root() -> None:
    with pytest.raises(MerkleLeavesListError) as exc:
        encode_leaves_list(leaves=PINNED_LEAVES, root=b"\x00" * 16)
    assert exc.value.code == "SCHEMA_MERKLE_LEAVES_MALFORMED"


def test_decode_rejects_non_map() -> None:
    from cardanowall._crypto.cbor import (
        CanonicalCborValue,
        encode_canonical_cbor,
    )

    payload: list[CanonicalCborValue] = [1, 2, 3]
    blob = encode_canonical_cbor(payload)
    with pytest.raises(MerkleLeavesListError) as exc:
        decode_leaves_list(blob)
    assert exc.value.code == "SCHEMA_MERKLE_LEAVES_MALFORMED"


def test_decode_rejects_wrong_length_leaf() -> None:
    from cardanowall._crypto.cbor import (
        CanonicalCborValue,
        encode_canonical_cbor,
    )

    payload: dict[str | int, CanonicalCborValue] = {
        "format": LEAVES_LIST_FORMAT_V1,
        "tree_alg": DEFAULT_TREE_ALG,
        "root": PINNED_ROOT,
        "leaves": [PINNED_LEAVES[0], b"\x00" * 16],
        "leaf_count": 2,
    }
    blob = encode_canonical_cbor(payload)
    with pytest.raises(MerkleLeavesListError) as exc:
        decode_leaves_list(blob)
    assert exc.value.code == "SCHEMA_MERKLE_LEAVES_MALFORMED"


def test_decode_rejects_root_mismatch() -> None:
    """Recomputed Merkle root MUST match declared `root`.

    Mirrors the TS twin's
    `decodeLeavesList — schema rejection > rejects root that does not match
    recomputed Merkle root with MERKLE_ROOT_MISMATCH` case.
    """
    from cardanowall._crypto.cbor import (
        CanonicalCborValue,
        encode_canonical_cbor,
    )

    fake_root = b"\xab" * 32
    assert fake_root != PINNED_ROOT  # sanity: a different 32-byte value
    payload: dict[str | int, CanonicalCborValue] = {
        "format": LEAVES_LIST_FORMAT_V1,
        "tree_alg": DEFAULT_TREE_ALG,
        "root": fake_root,
        "leaves": [bytes(leaf) for leaf in PINNED_LEAVES],
        "leaf_count": 4,
    }
    blob = encode_canonical_cbor(payload)
    with pytest.raises(MerkleLeavesListError) as exc:
        decode_leaves_list(blob)
    assert exc.value.code == "MERKLE_ROOT_MISMATCH"


def test_decode_leaves_list_shared_kat_negative() -> None:
    """Shared cross-SDK KAT: every negative vector raises with the pinned code.

    Includes the `wrong-tree-alg` case (`tree_alg != "rfc9162-sha256"` →
    SCHEMA_MERKLE_LEAVES_MALFORMED), the new gate this reconciliation adds.
    """
    fixture = Path(__file__).parent / "fixtures" / "merkle" / "leaves-list-negative.json"
    corpus = json.loads(fixture.read_text())
    vectors = corpus["vectors"]
    assert isinstance(vectors, list)
    for vector in vectors:
        blob = bytes.fromhex(vector["cbor_hex"])
        with pytest.raises(MerkleLeavesListError) as exc:
            decode_leaves_list(blob)
        assert exc.value.code == vector["expected_error_code"], vector["name"]
