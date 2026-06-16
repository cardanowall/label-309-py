"""Label 309 Merkle leaves-list codec tests.

The positive known-answer vectors (per-size canonical-CBOR bytes, both with and
without the optional leaf_alg key) are loaded from the shared cross-SDK fixture
so the Python, TypeScript, and Rust twins assert against one byte-identical
corpus. The 4-leaf vector doubles as the input set for the structural and
negative codec tests below.
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

FIXTURES = Path(__file__).parent / "fixtures"
_LEAVES_LIST_KAT = json.loads((FIXTURES / "merkle" / "leaves-list-kat.json").read_text())
_LEAVES_LIST_VECTORS = _LEAVES_LIST_KAT["vectors"]

# The 4-leaf vector seeds the structural/negative tests below.
_FOUR_LEAF = next(v for v in _LEAVES_LIST_VECTORS if v["leaf_count"] == 4)
PINNED_LEAVES = [bytes.fromhex(h) for h in _FOUR_LEAF["leaves"]]
PINNED_ROOT = bytes.fromhex(_FOUR_LEAF["root"])
PINNED_LEAVES_LIST_CBOR = bytes.fromhex(_FOUR_LEAF["cbor_hex_with_leaf_alg"])


def test_constants_are_canonical_v1() -> None:
    assert LEAVES_LIST_FORMAT_V1 == "cardano-poe-merkle-leaves-v1"
    assert DEFAULT_TREE_ALG == "rfc9162-sha256"
    assert _LEAVES_LIST_KAT["format"] == LEAVES_LIST_FORMAT_V1
    assert _LEAVES_LIST_KAT["alg"] == DEFAULT_TREE_ALG


def test_leaves_list_kat_encode_decode_round_trip() -> None:
    """Every pinned vector: encode(inputs) == cbor (with and without leaf_alg),
    and decode(cbor) recovers the canonical dict whose leaves recompute the root."""
    seen_sizes = set()
    for vector in _LEAVES_LIST_VECTORS:
        leaves = [bytes.fromhex(h) for h in vector["leaves"]]
        root = bytes.fromhex(vector["root"])
        leaf_alg = vector["leaf_alg"]
        with_alg = bytes.fromhex(vector["cbor_hex_with_leaf_alg"])
        no_alg = bytes.fromhex(vector["cbor_hex_no_leaf_alg"])

        # Encode reproduces both pinned forms byte-for-byte.
        assert encode_leaves_list(leaves=leaves, root=root, leaf_alg=leaf_alg) == with_alg, (
            f"{vector['name']} with leaf_alg"
        )
        assert encode_leaves_list(leaves=leaves, root=root) == no_alg, (
            f"{vector['name']} without leaf_alg"
        )

        # Decode of the with-leaf_alg form yields the canonical dict.
        decoded = decode_leaves_list(with_alg)
        assert decoded["format"] == LEAVES_LIST_FORMAT_V1
        assert decoded["tree_alg"] == DEFAULT_TREE_ALG
        assert decoded["root"] == root
        assert decoded["leaves"] == leaves
        assert decoded["leaf_count"] == vector["leaf_count"]
        assert decoded["leaf_alg"] == leaf_alg
        # The decoded leaves recompute to the declared on-chain commit.
        assert merkle_sha2_256_root(decoded["leaves"]) == root

        # encode(decode(cbor)) == cbor byte-for-byte (both forms).
        assert (
            encode_leaves_list(
                leaves=decoded["leaves"], root=decoded["root"], leaf_alg=decoded["leaf_alg"]
            )
            == with_alg
        )

        # The no-leaf_alg form omits exactly that key on decode.
        decoded_no_alg = decode_leaves_list(no_alg)
        assert "leaf_alg" not in decoded_no_alg
        assert decoded_no_alg["leaf_count"] == vector["leaf_count"]
        assert decoded_no_alg["root"] == root
        assert encode_leaves_list(leaves=leaves, root=root) == no_alg

        seen_sizes.add(vector["leaf_count"])

    assert seen_sizes == {1, 2, 3, 4, 5, 7}


def test_encode_matches_pinned_cbor_bytes() -> None:
    """Encoded bytes MUST match the pinned 4-leaf CBOR (275 B)."""
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
