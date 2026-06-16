# RFC 9162 §2.1.1 binary Merkle tree, SHA-256 underlying. Registered in the
# IANA COSE Verifiable Data Structure Algorithms registry, codepoint 1,
# draft-ietf-cose-merkle-tree-proofs-18. RFC 9162 §2.1.1 is a re-publication
# of RFC 6962 §2.1 with identical 0x00/0x01 prefixes; either citation is
# normative.

from __future__ import annotations

import hashlib
import hmac
from collections.abc import Sequence
from typing import Final

# Identifier registered in the Label 309 Merkle list-commitment registry.
MERKLE_ALG_ID: Final[str] = "rfc9162-sha256"

_DIGEST_LENGTH: Final[int] = 32
_LEAF_PREFIX: Final[bytes] = b"\x00"
_INTERNAL_PREFIX: Final[bytes] = b"\x01"

# The verify fold tracks the leaf index and subtree size with a right shift.
# That arithmetic is only exact while both values stay within 32 bits, so the
# algorithm's safe domain is 1 <= tree_size <= 2^32 - 1 (and 0 <= index <
# tree_size). A tree_size at or above 2^32 would let a forged proof verify
# against the wrong subtree shape, so we reject the whole out-of-range domain up
# front rather than fold it. The on-chain commitment caps leaf_count at the same
# 2^32 - 1, so no legitimate tree is excluded.
_MAX_TREE_SIZE: Final[int] = 0xFFFFFFFF


class MerkleError(ValueError):
    """Structural rejection raised by the public Merkle entry points.

    Inherits ValueError so callers expecting `ValueError` (the historic
    Python idiom) continue to work; the explicit class lets downstream
    code discriminate on `isinstance(e, MerkleError)` when needed.
    """


def _validate_tree_range(index: int, tree_size: int, fn_name: str) -> None:
    # Reject an out-of-range (index, tree_size) pair as a structural error. The
    # parity twins in the TypeScript and Rust SDKs mirror this guard so a forged
    # oversized tree_size is refused identically across all implementations.
    if (
        not isinstance(tree_size, int)
        or isinstance(tree_size, bool)
        or tree_size < 1
        or tree_size > _MAX_TREE_SIZE
    ):
        raise MerkleError(
            f"{fn_name}: tree_size {tree_size!r} out of range [1, {_MAX_TREE_SIZE}]"
        )
    if not isinstance(index, int) or isinstance(index, bool) or index < 0 or index >= tree_size:
        raise MerkleError(f"{fn_name}: index {index!r} out of range [0, {tree_size})")


def _largest_pow2_lt(n: int) -> int:
    # Largest k = 2^j such that k < n; n MUST be >= 2 (RFC 9162 §2.1.1).
    if n < 2:
        raise MerkleError(f"_largest_pow2_lt requires n >= 2; got {n}")
    return 1 << ((n - 1).bit_length() - 1)


def _hash_leaf(d: bytes) -> bytes:
    # Leaf hash: SHA-256(0x00 || d). The leaf prefix prevents collisions
    # with internal-node-shaped hashes (CVE-2012-2459 family).
    return hashlib.sha256(_LEAF_PREFIX + d).digest()


def _hash_node(left: bytes, right: bytes) -> bytes:
    # Internal-node hash: SHA-256(0x01 || left || right).
    return hashlib.sha256(_INTERNAL_PREFIX + left + right).digest()


def _validate_leaves(leaves: Sequence[bytes]) -> None:
    # Empty trees forbidden (n >= 1); each leaf exactly 32 B.
    if len(leaves) == 0:
        raise MerkleError("empty Merkle tree forbidden (n >= 1)")
    for i, d in enumerate(leaves):
        if not isinstance(d, (bytes, bytearray)):
            raise MerkleError(f"leaves[{i}] must be bytes; got {type(d).__name__}")
        if len(d) != _DIGEST_LENGTH:
            raise MerkleError(f"leaves[{i}] must be exactly {_DIGEST_LENGTH} bytes; got {len(d)}")


def _root_unchecked(leaves: Sequence[bytes]) -> bytes:
    # Caller is responsible for _validate_leaves(leaves).
    n = len(leaves)
    if n == 1:
        return _hash_leaf(leaves[0])
    k = _largest_pow2_lt(n)
    left = _root_unchecked(leaves[:k])
    right = _root_unchecked(leaves[k:])
    return _hash_node(left, right)


def _audit_path(leaves: Sequence[bytes], i: int) -> list[bytes]:
    # Standard RFC 9162 §2.1.1 audit path, leaf-to-root order.
    n = len(leaves)
    if n == 1:
        return []
    k = _largest_pow2_lt(n)
    if i < k:
        # leaf in LEFT subtree; sibling is right-subtree root
        return [*_audit_path(leaves[:k], i), _root_unchecked(leaves[k:])]
    # leaf in RIGHT subtree; sibling is left-subtree root
    return [*_audit_path(leaves[k:], i - k), _root_unchecked(leaves[:k])]


def merkle_sha2_256_root(leaves: Sequence[bytes]) -> bytes:
    """Canonical Merkle root per RFC 9162 §2.1.1 (SHA-256).

    Each leaf MUST be exactly 32 bytes. Raises MerkleError on empty input or
    wrong-length leaves. For n == 1, returns SHA-256(0x00 || d_0); the leaf
    prefix prevents collision with internal-node-shaped hashes.
    """
    _validate_leaves(leaves)
    return _root_unchecked(leaves)


def merkle_sha2_256_inclusion_proof(leaves: Sequence[bytes], index: int) -> list[bytes]:
    """Inclusion proof (audit path) for the leaf at `index`.

    Returns the ordered list of 32-byte sibling hashes from leaf to root. For
    single-leaf trees the path is empty (RFC 9162 §2.1.1).
    """
    _validate_leaves(leaves)
    _validate_tree_range(index, len(leaves), "merkle_sha2_256_inclusion_proof")
    return _audit_path(leaves, index)


def merkle_sha2_256_verify_inclusion(
    leaf: bytes,
    index: int,
    tree_size: int,
    proof: Sequence[bytes],
    root: bytes,
) -> bool:
    """Verify an inclusion proof.

    Iterative RFC 9162 §2.1.3.2 fold. Returns True iff the proof reconstructs
    a hash byte-equal to `root` (constant-time compared). A byte-shape problem
    (wrong-length leaf/root/sibling) returns False — that is genuine non-
    verification. An out-of-range (index, tree_size) pair is a structural error,
    not a "does not verify" verdict: the fold's shift arithmetic is undefined
    outside the safe domain, so we raise rather than return a (potentially
    forged) Boolean.
    """
    # Out-of-range (index, tree_size) is rejected up front (raises).
    _validate_tree_range(index, tree_size, "merkle_sha2_256_verify_inclusion")
    # Byte-shape checks (Boolean predicate, never raise).
    if not isinstance(leaf, (bytes, bytearray)) or len(leaf) != _DIGEST_LENGTH:
        return False
    if not isinstance(root, (bytes, bytearray)) or len(root) != _DIGEST_LENGTH:
        return False
    for s in proof:
        if not isinstance(s, (bytes, bytearray)) or len(s) != _DIGEST_LENGTH:
            return False

    if tree_size == 1:
        # Single-leaf trees admit only the trivial empty-path proof; root
        # MUST equal SHA-256(0x00 || leaf), NOT leaf itself.
        if len(proof) != 0 or index != 0:
            return False
        return hmac.compare_digest(_hash_leaf(bytes(leaf)), bytes(root))

    fn = index
    sn = tree_size - 1
    r = _hash_leaf(bytes(leaf))
    for s in proof:
        if sn == 0:
            # More siblings supplied than the tree has levels.
            return False
        if (fn & 1) == 1 or fn == sn:
            # current node is the RIGHT child of its pair → sibling on LEFT
            r = _hash_node(bytes(s), r)
            # When fn was a right-most-carried node (LSB clear, fn == sn),
            # walk both fn and sn upward until fn lands on a right child or
            # the root is reached (RFC 9162 §2.1.3.2 inner adjustment).
            while (fn & 1) == 0 and fn != 0:
                fn >>= 1
                sn >>= 1
        else:
            # current node is the LEFT child of its pair → sibling on RIGHT
            r = _hash_node(r, bytes(s))
        fn >>= 1
        sn >>= 1
    if sn != 0:
        # Proof shorter than the tree's depth.
        return False
    return hmac.compare_digest(r, bytes(root))


__all__ = [
    "MERKLE_ALG_ID",
    "MerkleError",
    "merkle_sha2_256_inclusion_proof",
    "merkle_sha2_256_root",
    "merkle_sha2_256_verify_inclusion",
]
