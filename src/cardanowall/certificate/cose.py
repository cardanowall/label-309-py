"""Artifact 2 — the per-item COSE / RFC 9162 aligned CBOR inclusion proof.

The inner ``inclusion-proof`` structure is byte-identical to the IETF COSE
Merkle-tree-proofs encoding, so third-party COSE / SCITT verifiers read the
proof math directly::

    inclusion-proof = bstr .cbor [ tree_size: uint, leaf_index: uint, [ + bstr ] ]

Note the ``bstr .cbor`` wrapper: the standalone IETF value is a CBOR *byte
string* whose contents are the canonical-CBOR encoding of the
``[tree_size, leaf_index, inclusion-path]`` array.

We wrap that bstr in a ``cw-inclusion-proof`` map that carries the blockchain
anchor in place of the COSE_Sign1 signature an IETF Receipt would hold — the
proof is deliberately unsigned-and-blockchain-anchored (the timestamp authority
is the Cardano transaction, not a key we control)::

    cw-inclusion-proof = {
      "vds":             1,                 ; RFC9162_SHA256 (IANA value 1)
      "inclusion_proof": inclusion-proof,   ; the IETF bstr.cbor array
      "root":            bytes .size 32,
      "anchor": { "chain", "network", "tx_hash": bytes, "metadata_label": 309 },
      "leaf":            bytes .size 32,
      ? "leaf_alg":      tstr
    }

The CBOR artifact exists only for a *proven* inclusion: a missing or unverified
item has no valid proof to encode, so the encoders refuse it rather than emit a
sentinel that decodes to a malformed proof.

All encoding goes through the shared canonical-CBOR codec (RFC 8949 §4.2.1).
"""

from __future__ import annotations

import re

from cardanowall._crypto.cbor import CanonicalCborValue, encode_canonical_cbor

from .constants import METADATA_LABEL_309, VDS_RFC9162_SHA256
from .types import CertificateAnchor, CertificateMerkle, InclusionCertificateItem

_DIGEST_LENGTH = 32
_MAX_TREE_SIZE = 0xFFFFFFFF

# Accept upper or lower hex, but reject any non-hex character (including
# whitespace) and odd length — matching the strict TypeScript and Rust decoders.
_HEX_FIELD = re.compile(r"(?:[0-9a-fA-F]{2})*")


def _hex_to_bytes(value: str, field: str) -> bytes:
    if _HEX_FIELD.fullmatch(value) is None:
        raise TypeError(f"encode_cose_inclusion_proof: {field} is not valid hex")
    return bytes.fromhex(value)


def _decode_proven_item(
    item: InclusionCertificateItem,
    merkle: CertificateMerkle,
) -> tuple[bytes, list[bytes], int, int]:
    """Decode + validate a proven inclusion item into raw bytes ready for CBOR.

    Raises :class:`TypeError` if the item is not a proven inclusion — a miss
    (``error`` set), an unverified item, an out-of-range index, or any
    leaf/root/sibling that is not exactly 32 bytes. The COSE artifact must never
    be produced for anything but a valid proof.
    """
    if item.get("error") is not None:
        raise TypeError(
            f"encode_cose_inclusion_proof: refusing to encode an item with error {item['error']!r}"
        )
    if item.get("verified") is not True:
        raise TypeError("encode_cose_inclusion_proof: refusing to encode an unverified item")
    index = item.get("index")
    if not isinstance(index, int) or isinstance(index, bool) or index < 0:
        raise TypeError(f"encode_cose_inclusion_proof: invalid item index {index!r}")
    tree_size = merkle.tree_size
    if (
        not isinstance(tree_size, int)
        or isinstance(tree_size, bool)
        or tree_size < 1
        or tree_size > _MAX_TREE_SIZE
        or index >= tree_size
    ):
        raise TypeError(
            f"encode_cose_inclusion_proof: index {index} out of range for tree_size {tree_size!r}"
        )

    leaf = _decode32(item.get("leaf", ""), "leaf")
    siblings = [_decode32(s, f"proof[{i}]") for i, s in enumerate(item.get("proof", []))]
    return leaf, siblings, tree_size, index


def _decode32(hex_str: object, field: str) -> bytes:
    if not isinstance(hex_str, str):
        raise TypeError(f"encode_cose_inclusion_proof: {field} must be a hex string")
    value = _hex_to_bytes(hex_str, field)
    if len(value) != _DIGEST_LENGTH:
        raise TypeError(
            f"encode_cose_inclusion_proof: {field} must be {_DIGEST_LENGTH} bytes, got {len(value)}"
        )
    return value


def _encode_inclusion_path_array(
    item: InclusionCertificateItem,
    merkle: CertificateMerkle,
) -> bytes:
    """The canonical-CBOR bytes of the bare ``[tree_size, leaf_index, [siblings]]``
    array — the *contents* that the IETF ``bstr .cbor`` wraps.
    """
    _leaf, siblings, tree_size, index = _decode_proven_item(item, merkle)
    array: CanonicalCborValue = [tree_size, index, list(siblings)]
    return encode_canonical_cbor(array)


def encode_ietf_inclusion_proof(
    item: InclusionCertificateItem,
    merkle: CertificateMerkle,
) -> bytes:
    """Encode the bare IETF ``inclusion-proof`` value for one item.

    A CBOR byte string whose contents are the canonical CBOR of
    ``[tree_size, leaf_index, [ ...siblings ]]`` (the ``bstr .cbor [...]`` form).
    This is exactly the value a pure COSE / RFC 9162 verifier consumes — decode
    it as a byte string, then decode those bytes as the array. Refuses
    non-inclusion items.
    """
    array_bytes = _encode_inclusion_path_array(item, merkle)
    # Wrap the array bytes as a CBOR byte string (the `bstr .cbor` envelope).
    return encode_canonical_cbor(array_bytes)


def encode_cose_inclusion_proof(
    item: InclusionCertificateItem,
    merkle: CertificateMerkle,
    anchor: CertificateAnchor,
) -> bytes:
    """Encode the full ``cw-inclusion-proof`` CBOR map for one item.

    The IETF inclusion-proof bstr plus the root, the blockchain anchor, the
    committed leaf, and the optional leaf algorithm. Canonical CBOR; the parity
    twins reproduce the bytes exactly. Refuses non-inclusion items.
    """
    # The map stores the *array bytes* as a bytes value; the encoder renders that
    # as a bstr, so `inclusion_proof` is byte-identical to encode_ietf_inclusion_proof.
    inclusion_path_array = _encode_inclusion_path_array(item, merkle)
    leaf = _decode32(item.get("leaf", ""), "leaf")

    if not isinstance(merkle.root, (bytes, bytearray)) or len(merkle.root) != _DIGEST_LENGTH:
        raise TypeError(f"encode_cose_inclusion_proof: merkle.root must be {_DIGEST_LENGTH} bytes")

    anchor_map: dict[str | int, CanonicalCborValue] = {
        "chain": anchor.chain,
        "network": anchor.network,
        "tx_hash": _hex_to_bytes(anchor.tx_hash, "anchor.tx_hash"),
        "metadata_label": METADATA_LABEL_309,
    }
    cbor_map: dict[str | int, CanonicalCborValue] = {
        "vds": VDS_RFC9162_SHA256,
        "inclusion_proof": inclusion_path_array,
        "root": bytes(merkle.root),
        "anchor": anchor_map,
        "leaf": leaf,
    }
    if item.get("leaf_alg") is not None:
        cbor_map["leaf_alg"] = item["leaf_alg"]

    return encode_canonical_cbor(cbor_map)


__all__ = ["encode_cose_inclusion_proof", "encode_ietf_inclusion_proof"]
