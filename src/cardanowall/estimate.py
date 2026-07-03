"""Tight upper-bound estimator for the canonical-CBOR record size.

A publish quote precedes the upload, so the record byte count handed to
``POST /poe/quote`` must be computed **before** the final record exists. The
gateway enforces ``actual <= quoted`` at consume time, so the estimate must
never undershoot: a quote priced for fewer bytes than the record turns out to
be would be rejected at publish. This module computes an **upper bound** of
:func:`cardanowall.poe_standard.encode_poe_record` from the record's *shape* —
its content items (each with a hash-algorithm list, an optional URI list, and
an optional sealed envelope) and an optional Merkle commitment.

``items`` and ``merkle`` are independent top-level peers: a record can carry
one, the other, or both (the floor is that it carries at least one of them).
The estimate charges each present component and the exact top-level key count.

Each CBOR header is charged its **exact** canonical width for the count or
length being encoded (:func:`_cbor_header_len`) rather than a worst-case
width, so the bound stays tight even near a gateway's record ceiling — a
record whose real CBOR sits just under :data:`MAX_RECORD_BYTES` must not be
falsely rejected by a slack estimate. The only deliberate slack is a small
fixed safety margin and the use of fixed maxima for the AEAD/KEM identifier
strings and the path-1 COSE_Sign1 (all fixed-shape, so their maxima are exact
upper bounds).
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Literal

# Pre-quote ceiling on the canonical record size, set just under the gateway's
# ~14,500-byte record ceiling. A record (by its shape) estimated above this can
# be rejected before a quote is requested with a clear "record too large / too
# many recipients" error, rather than discovering the rejection at the gateway
# after a paid upload.
MAX_RECORD_BYTES = 14_000

# The KEM a sealed item is sealed under, for the per-slot size of the estimate.
# Unsealed items carry no envelope and need no KEM here.
EstimateKem = Literal["x25519", "mlkem768x25519"]

# The 24-byte sealed-envelope content nonce.
_ENVELOPE_NONCE_BYTES = 24
# The 32-byte slots MAC.
_SLOTS_MAC_BYTES = 32
# The 48-byte per-slot wrapped CEK (`wrap`).
_SLOT_WRAP_BYTES = 48
# The classical per-slot ephemeral public key (`epk`), 32 bytes.
_SLOT_EPK_BYTES = 32
# The X-Wing per-slot ciphertext (`kem_ct`), 1120 bytes.
_SLOT_KEM_CT_BYTES = 1120
# The 32-byte transaction hash a `supersedes` carries.
_SUPERSEDES_BYTES = 32

# A small fixed slack added once to the whole estimate, absorbing any rounding
# the per-component sums do not already cover. Kept deliberately small (the
# component widths are exact) so the bound stays close to the real size near
# the MAX_RECORD_BYTES ceiling rather than rejecting valid records.
_SAFETY_MARGIN = 16

# A content-hash digest is 32 bytes for every registered v1 algorithm
# (`sha2-256`, `blake2b-256`).
_DIGEST_BYTES = 32
# The longest AEAD identifier (`chacha20-poly1305-stream64k`, 27 bytes);
# charged for any envelope so the bound holds regardless of the exact id.
_AEAD_ID_BYTES = 27
# The longest KEM identifier (`mlkem768x25519`, 14 bytes).
_KEM_ID_BYTES = 14
# The exact byte length of a detached **path-1** COSE_Sign1, which is fully
# fixed-shape: a 4-element array (0x84) of the 38-byte protected header
# ({1: -8, 4: <32-byte kid>}, encoded as a 40-byte byte string), an empty
# unprotected header (0xa0), a null detached payload (0xf6), and the 64-byte
# Ed25519 signature (encoded as a 66-byte byte string): 1 + 40 + 1 + 1 + 66.
_COSE_SIGN1_PATH1_BYTES = 109

# `leaf_count` is unknown at estimate time; the leaf count fits a u64, so the
# estimate charges the maximum uint width — an exact upper bound for any
# realisable batch.
_U64_MAX = 0xFFFF_FFFF_FFFF_FFFF

# --- field name byte lengths (the canonical encoder keys records by text) ---
_V_KEY = 1  # "v"
_ITEMS_KEY = 5  # "items"
_MERKLE_KEY = 6  # "merkle"
_SUPERSEDES_KEY = 10  # "supersedes"
_SIGS_KEY = 4  # "sigs"
_HASHES_KEY = 6  # "hashes"
_URIS_KEY = 4  # "uris"
_ENC_KEY = 3  # "enc"
_ALG_KEY = 3  # "alg"
_ROOT_KEY = 4  # "root"
_LEAF_COUNT_KEY = 10  # "leaf_count"
_SCHEME_KEY = 6  # "scheme"
_AEAD_KEY = 4  # "aead"
_NONCE_KEY = 5  # "nonce"
_KEM_KEY = 3  # "kem"
_SLOTS_KEY = 5  # "slots"
_SLOTS_MAC_KEY = 9  # "slots_mac"
_EPK_KEY = 3  # "epk"
_KEM_CT_KEY = 6  # "kem_ct"
_WRAP_KEY = 4  # "wrap"
_COSE_SIGN1_KEY = 10  # "cose_sign1"


def _cbor_header_len(n: int) -> int:
    """The exact width, in bytes, of a canonical-CBOR argument header for a
    major-type item whose count/length/value is ``n``.

    Canonical CBOR encodes the argument in the shortest form: inline in the
    initial byte for ``n <= 23``, then a 1-, 2-, 4-, or 8-byte big-endian
    extension. The returned width includes the initial byte, so it is the exact
    header width for an unsigned integer, a map/array element count, or a
    text/byte-string length — the estimate charges precisely what the encoder
    will emit, never a worst-case width.
    """
    if n <= 23:
        return 1
    if n <= 0xFF:
        return 2
    if n <= 0xFFFF:
        return 3
    if n <= 0xFFFF_FFFF:
        return 5
    return 9


def _container_header(entries: int) -> int:
    """The exact encoded width of a CBOR map or array header for ``entries``
    elements: its argument header (the element count is the argument)."""
    return _cbor_header_len(entries)


def _uint_bytes(value: int) -> int:
    """The exact encoded width of a CBOR unsigned integer holding ``value``."""
    return _cbor_header_len(value)


def _str_bytes(length: int) -> int:
    """The exact encoded width of a CBOR text/byte string of ``length`` bytes:
    its length-prefix header plus the payload."""
    return _cbor_header_len(length) + length


def _utf8_len(value: str) -> int:
    """The UTF-8 byte length of a caller-supplied string. CBOR text strings
    are length-prefixed by their encoded BYTE count, so a non-ASCII URI or
    algorithm id must be charged its UTF-8 width, not its character count —
    undercounting would break the upper-bound guarantee."""
    return len(value.encode("utf-8"))


@dataclass(frozen=True)
class ItemShape:
    """The shape of one content item to size. Every field maps to a CBOR
    component whose maximum encoded width the estimate sums.

    ``hash_algs`` lists the content-hash algorithm ids the item will carry
    (e.g. ``["sha2-256", "blake2b-256"]``); each contributes a key string plus
    a 32-byte digest value. ``uris`` lists the off-chain URIs, each charged its
    full string width (empty for a hash-only item). ``recipient_count`` is the
    number of sealed-envelope slots (0 for an unsealed item), and ``kem`` names
    the KEM the envelope is sealed under — ``None`` for an unsealed item (no
    ``enc`` block is charged).
    """

    hash_algs: Sequence[str]
    uris: Sequence[str] = ()
    recipient_count: int = 0
    kem: EstimateKem | None = None


@dataclass(frozen=True)
class MerkleShape:
    """The shape of a Merkle commitment for the estimate: its list-commitment
    algorithm id (e.g. ``rfc9162-sha256``) plus the off-chain URIs the
    commitment will carry (e.g. the leaves-list ``ar://`` pointer; empty when
    the manifest is kept private)."""

    alg: str
    uris: Sequence[str] = ()


@dataclass(frozen=True)
class RecordShape:
    """The shape of the record to size: its content items plus an optional
    Merkle commitment (independent top-level peers — both may be present), and
    the record-level signature / supersedes flags."""

    items: Sequence[ItemShape] = ()
    signed: bool = False
    supersedes: bool = False
    merkle: MerkleShape | None = None


def _uris_bytes(uris: Sequence[str]) -> int:
    """The `uris` component shared by an item and a merkle commitment: an array
    of URI strings, or nothing when empty (the field is omitted)."""
    if not uris:
        return 0
    total = _str_bytes(_URIS_KEY) + _container_header(len(uris))
    for uri in uris:
        total += _str_bytes(_utf8_len(uri))
    return total


def _envelope_bytes(item: ItemShape, kem: EstimateKem) -> int:
    """The `enc` scheme-1 envelope: `{scheme, aead, nonce, kem, slots,
    slots_mac}` (6 keys) plus one slot per recipient."""
    env = _container_header(6)
    env += _str_bytes(_SCHEME_KEY) + _uint_bytes(1)  # scheme is the value 1
    env += _str_bytes(_AEAD_KEY) + _str_bytes(_AEAD_ID_BYTES)
    env += _str_bytes(_NONCE_KEY) + _str_bytes(_ENVELOPE_NONCE_BYTES)
    env += _str_bytes(_KEM_KEY) + _str_bytes(_KEM_ID_BYTES)
    env += _str_bytes(_SLOTS_MAC_KEY) + _str_bytes(_SLOTS_MAC_BYTES)
    # slots: an array of per-recipient slot maps.
    env += _str_bytes(_SLOTS_KEY) + _container_header(item.recipient_count)
    if kem == "x25519":
        # `{epk: 32, wrap: 48}` — a 2-key map.
        per_slot = (
            _container_header(2)
            + _str_bytes(_EPK_KEY)
            + _str_bytes(_SLOT_EPK_BYTES)
            + _str_bytes(_WRAP_KEY)
            + _str_bytes(_SLOT_WRAP_BYTES)
        )
    else:
        # `{kem_ct: 1120, wrap: 48}` — a 2-key map.
        per_slot = (
            _container_header(2)
            + _str_bytes(_KEM_CT_KEY)
            + _str_bytes(_SLOT_KEM_CT_BYTES)
            + _str_bytes(_WRAP_KEY)
            + _str_bytes(_SLOT_WRAP_BYTES)
        )
    return env + per_slot * item.recipient_count


def _item_bytes(item: ItemShape) -> int:
    """The encoded width of one `items[i]` map: a `{hashes, uris?, enc?}` map."""
    # The item map carries `hashes` always, then `uris` (when non-empty) and
    # `enc` (when sealed).
    item_keys = 1  # hashes
    if item.uris:
        item_keys += 1
    if item.kem is not None:
        item_keys += 1
    total = _container_header(item_keys)
    # hashes: a map of (alg-id -> 32-byte digest).
    total += _str_bytes(_HASHES_KEY) + _container_header(len(item.hash_algs))
    for alg in item.hash_algs:
        total += _str_bytes(_utf8_len(alg)) + _str_bytes(_DIGEST_BYTES)
    total += _uris_bytes(item.uris)
    if item.kem is not None:
        total += _str_bytes(_ENC_KEY) + _envelope_bytes(item, item.kem)
    return total


def _merkle_bytes(merkle: MerkleShape) -> int:
    """The `merkle` component: a one-entry array of a single
    `{alg, root, leaf_count, uris?}` commitment."""
    commit_keys = 3 if not merkle.uris else 4
    commit = _container_header(commit_keys)
    commit += _str_bytes(_ALG_KEY) + _str_bytes(_utf8_len(merkle.alg))
    commit += _str_bytes(_ROOT_KEY) + _str_bytes(_DIGEST_BYTES)
    commit += _str_bytes(_LEAF_COUNT_KEY) + _uint_bytes(_U64_MAX)
    commit += _uris_bytes(merkle.uris)
    return _str_bytes(_MERKLE_KEY) + _container_header(1) + commit


def _sig_entry_bytes() -> int:
    """The exact size of one `sigs[0]` entry: a 1-key `{cose_sign1: <bstr>}`
    map whose value is the fixed-shape path-1 COSE_Sign1. The record stores
    `cose_sign1` as a single byte string, so there is no chunk-array overhead
    here."""
    return _container_header(1) + _str_bytes(_COSE_SIGN1_KEY) + _str_bytes(_COSE_SIGN1_PATH1_BYTES)


def estimate_record_bytes(shape: RecordShape) -> int:
    """An upper bound on the canonical-CBOR size of the record ``shape``
    describes — guaranteed ``>=`` the encoded length of the record actually
    built from the same shape."""
    # The top-level record map carries `v` always, then `items` (when the
    # record has any items) and/or `merkle` (when it carries a batch), plus
    # optional `supersedes` and `sigs`. Charge the map header for the exact
    # key count.
    key_count = 1  # `v`
    if shape.items:
        key_count += 1
    if shape.merkle is not None:
        key_count += 1
    if shape.supersedes:
        key_count += 1
    if shape.signed:
        key_count += 1

    # The top-level record map header + the `v` key + its `1` value (a 1-byte
    # immediate uint).
    total = _container_header(key_count) + _str_bytes(_V_KEY) + _uint_bytes(1)

    if shape.items:
        # `"items"` key + the array header + every item's encoded width.
        total += _str_bytes(_ITEMS_KEY) + _container_header(len(shape.items))
        for item in shape.items:
            total += _item_bytes(item)
    if shape.merkle is not None:
        total += _merkle_bytes(shape.merkle)
    if shape.supersedes:
        # `"supersedes"` key + a 32-byte byte string.
        total += _str_bytes(_SUPERSEDES_KEY) + _str_bytes(_SUPERSEDES_BYTES)
    if shape.signed:
        # `"sigs"` key + a one-entry array of one `{cose_sign1}` map.
        total += _str_bytes(_SIGS_KEY) + _container_header(1) + _sig_entry_bytes()

    return total + _SAFETY_MARGIN


__all__ = [
    "MAX_RECORD_BYTES",
    "EstimateKem",
    "ItemShape",
    "MerkleShape",
    "RecordShape",
    "estimate_record_bytes",
]
