# CIP-309 Merkle leaves-list codec (canonical CBOR normative).
# The on-storage byte-normative form of the leaves-list file is canonical
# CBOR per RFC 8949 §4.2.1. Producers publish CBOR bytes to the
# content-addressed substrate referenced by `merkle[i].uris[]`; verifiers
# parse CBOR.

from __future__ import annotations

import hmac
from typing import Any, Final, cast

from .cbor import (
    CanonicalCborError,
    CanonicalCborValue,
    decode_canonical_cbor,
    encode_canonical_cbor,
)
from .merkle_sha2_256 import merkle_sha2_256_root

# Literal `format` value bound to the CDDL. Future schema revisions bump
# the suffix; v1 verifiers MUST reject any other value with
# SCHEMA_MERKLE_LEAVES_FORMAT_UNSUPPORTED.
LEAVES_LIST_FORMAT_V1: Final[str] = "cardano-poe-merkle-leaves-v1"

# On-wire Merkle list-commitment algorithm identifier.
DEFAULT_TREE_ALG: Final[str] = "rfc9162-sha256"

_LEAF_LENGTH: Final[int] = 32


class MerkleLeavesListError(Exception):
    """Raised on any structural / schema violation of the leaves-list payload.

    The `code` attribute carries the verifier-side error discriminator.
    The decoder may raise with any of:

    - ``SCHEMA_MERKLE_LEAVES_MALFORMED``
    - ``SCHEMA_MERKLE_LEAVES_FORMAT_UNSUPPORTED``
    - ``SCHEMA_MERKLE_LEAF_COUNT_MISMATCH``
    - ``MERKLE_ROOT_MISMATCH``
    """

    def __init__(self, code: str, message: str = "") -> None:
        super().__init__(f"{code}: {message}" if message else code)
        self.code: str = code


def encode_leaves_list(
    *,
    leaves: list[bytes] | tuple[bytes, ...],
    root: bytes,
    leaf_alg: str | None = None,
) -> bytes:
    """Emit canonical CBOR bytes for the leaves-list.

    `leaf_count` is set automatically to len(leaves). The output is canonical
    CBOR (RFC 8949 §4.2.1): shortest-form integers, definite length, bytewise
    lex-sorted map keys, no duplicates.
    """
    if not isinstance(root, (bytes, bytearray)) or len(root) != _LEAF_LENGTH:
        raise MerkleLeavesListError(
            "SCHEMA_MERKLE_LEAVES_MALFORMED",
            f"root must be exactly {_LEAF_LENGTH} bytes",
        )
    if len(leaves) == 0:
        raise MerkleLeavesListError(
            "SCHEMA_MERKLE_LEAVES_MALFORMED", "leaves must be a non-empty list"
        )
    for i, leaf in enumerate(leaves):
        if not isinstance(leaf, (bytes, bytearray)) or len(leaf) != _LEAF_LENGTH:
            raise MerkleLeavesListError(
                "SCHEMA_MERKLE_LEAVES_MALFORMED",
                f"leaves[{i}] must be exactly {_LEAF_LENGTH} bytes",
            )

    obj: dict[str | int, CanonicalCborValue] = {
        "format": LEAVES_LIST_FORMAT_V1,
        "tree_alg": DEFAULT_TREE_ALG,
        "root": bytes(root),
        "leaves": [bytes(leaf) for leaf in leaves],
        "leaf_count": len(leaves),
    }
    if leaf_alg is not None:
        obj["leaf_alg"] = leaf_alg
    return encode_canonical_cbor(cast(CanonicalCborValue, obj))


def decode_leaves_list(blob: bytes) -> dict[str, Any]:
    """Parse canonical CBOR bytes into a leaves-list dict.

    Returns a dict with keys: `format`, `tree_alg`, `root`, `leaves`,
    `leaf_count`, and optionally `leaf_alg`. Raises MerkleLeavesListError on
    any structural or schema violation.
    """
    try:
        decoded = decode_canonical_cbor(blob)
    except CanonicalCborError as e:
        raise MerkleLeavesListError(
            "SCHEMA_MERKLE_LEAVES_MALFORMED", f"CBOR decode failed: {e}"
        ) from e

    if not isinstance(decoded, dict):
        raise MerkleLeavesListError(
            "SCHEMA_MERKLE_LEAVES_MALFORMED", "top-level must be a CBOR map"
        )

    fmt = decoded.get("format")
    if not isinstance(fmt, str):
        raise MerkleLeavesListError(
            "SCHEMA_MERKLE_LEAVES_MALFORMED", "`format` must be a text string"
        )
    if fmt != LEAVES_LIST_FORMAT_V1:
        raise MerkleLeavesListError(
            "SCHEMA_MERKLE_LEAVES_FORMAT_UNSUPPORTED",
            f"unsupported leaves-list format: {fmt!r}",
        )

    tree_alg = decoded.get("tree_alg")
    if not isinstance(tree_alg, str):
        raise MerkleLeavesListError(
            "SCHEMA_MERKLE_LEAVES_MALFORMED", "`tree_alg` must be a text string"
        )
    if tree_alg != DEFAULT_TREE_ALG:
        raise MerkleLeavesListError(
            "SCHEMA_MERKLE_LEAVES_MALFORMED",
            f"unsupported `tree_alg`: {tree_alg!r} (expected {DEFAULT_TREE_ALG!r})",
        )

    root = decoded.get("root")
    if not isinstance(root, (bytes, bytearray)) or len(root) != _LEAF_LENGTH:
        raise MerkleLeavesListError(
            "SCHEMA_MERKLE_LEAVES_MALFORMED",
            f"`root` must be a {_LEAF_LENGTH}-byte byte string",
        )

    leaves_raw = decoded.get("leaves")
    if not isinstance(leaves_raw, list) or len(leaves_raw) == 0:
        raise MerkleLeavesListError(
            "SCHEMA_MERKLE_LEAVES_MALFORMED", "`leaves` must be a non-empty array"
        )
    leaves: list[bytes] = []
    for i, leaf in enumerate(leaves_raw):
        if not isinstance(leaf, (bytes, bytearray)) or len(leaf) != _LEAF_LENGTH:
            raise MerkleLeavesListError(
                "SCHEMA_MERKLE_LEAVES_MALFORMED",
                f"`leaves[{i}]` must be a {_LEAF_LENGTH}-byte byte string",
            )
        leaves.append(bytes(leaf))

    leaf_count = decoded.get("leaf_count")
    if not isinstance(leaf_count, int) or isinstance(leaf_count, bool) or leaf_count < 0:
        raise MerkleLeavesListError(
            "SCHEMA_MERKLE_LEAVES_MALFORMED",
            "`leaf_count` must be a non-negative integer",
        )
    if leaf_count != len(leaves):
        raise MerkleLeavesListError(
            "SCHEMA_MERKLE_LEAF_COUNT_MISMATCH",
            f"`leaf_count` ({leaf_count}) does not match len(leaves) ({len(leaves)})",
        )

    leaf_alg = decoded.get("leaf_alg")
    if leaf_alg is not None and not isinstance(leaf_alg, str):
        raise MerkleLeavesListError(
            "SCHEMA_MERKLE_LEAVES_MALFORMED",
            "`leaf_alg` (if present) must be a text string",
        )

    # Defence-in-depth: recompute the Merkle root from the decoded leaves
    # and constant-time compare against the declared `root`.
    # Mirrors the TypeScript parity twin in @cardanowall/crypto-core.
    declared_root = bytes(root)
    recomputed_root = merkle_sha2_256_root(leaves)
    if not hmac.compare_digest(recomputed_root, declared_root):
        raise MerkleLeavesListError(
            "MERKLE_ROOT_MISMATCH",
            "leaves recompute does not match declared root",
        )

    out: dict[str, Any] = {
        "format": fmt,
        "tree_alg": tree_alg,
        "root": declared_root,
        "leaves": leaves,
        "leaf_count": leaf_count,
    }
    if leaf_alg is not None:
        out["leaf_alg"] = leaf_alg

    return out


__all__ = [
    "DEFAULT_TREE_ALG",
    "LEAVES_LIST_FORMAT_V1",
    "MerkleLeavesListError",
    "decode_leaves_list",
    "encode_leaves_list",
]
