"""Label 309 v1 wire-format types.

Mirrors the on-wire CBOR shape: top-level record, items + hashes map,
encryption envelope, merkle commits, sig entries, supersedes. TypedDicts are
preferred over dataclasses for parity: the on-wire shape is exactly what the
validator returns under ``record`` in a successful result, and TypedDict
carries the field-name discipline without an instantiation layer.

Every logical byte string is a SINGLE CBOR byte string and every URI is a
SINGLE text string: record-body fields carry no 64-byte cap and no chunk
wrappers. The ledger's 64-byte metadata-string cap is satisfied by the
whole-body transport chunk array alone, which is reassembled before the
validator ever sees the body.

Naming mirrors ``@cardanowall/poe-standard`` (TypeScript).
"""

from __future__ import annotations

import re
from typing import Final, Literal, NotRequired, TypedDict

# Algorithm-identifier literal aliases. The on-wire field is a plain CBOR
# text string; the Literal here documents v1's closed registry and lets mypy
# catch typos at producer-side construction.
HashAlgId = Literal["sha2-256", "blake2b-256"]
MerkleCommitAlgId = Literal["rfc9162-sha256"]
AeadAlgId = Literal["chacha20-poly1305-stream64k"]
KemAlgId = Literal["x25519", "mlkem768x25519"]
PassphraseAlgId = Literal["argon2id"]


class Argon2Params(TypedDict):
    """Closed ``enc.passphrase.params`` shape for ``alg = "argon2id"``.

    Cost-parameter floor: m >= 65536 KiB, t >= 3, p >= 1. Each value is a
    CBOR unsigned integer in the pinned exact-integer range 0 .. 2^32 - 1.
    """

    m: int
    t: int
    p: int


class PassphraseKdf(TypedDict):
    """``enc.passphrase`` — the passphrase-derived key-path block.

    Salt length is constrained to the inclusive range [16, 64] bytes.
    """

    alg: PassphraseAlgId
    salt: bytes
    params: Argon2Params


class Slot(TypedDict):
    """Per-recipient sealed slot. The slot shape is KEM-driven and the type is
    a permissive superset of both key paths:

    - x25519:         ``{ epk: bstr(32), wrap: bstr(48) }`` — ``epk`` is the
      per-slot ephemeral X25519 public key; ``wrap`` is the 48-byte
      ciphertext+tag (32-byte CEK + 16-byte ChaCha20-Poly1305 tag).
    - mlkem768x25519: ``{ kem_ct: bstr(1120), wrap: bstr(48) }`` — ``kem_ct``
      is the SINGLE 1120-byte X-Wing (ML-KEM-768 + X25519) encapsulation;
      there is NO per-slot ``epk`` on the hybrid path (the X25519 ephemeral
      is the trailing 32 bytes of ``kem_ct``).

    Which field MUST/MUST NOT be present for the declared envelope ``kem`` is
    enforced by the validator's KEM-driven domain pass (the type cannot see
    the envelope ``kem`` from a slot in isolation), so all three fields are
    optional here.
    """

    epk: NotRequired[bytes]
    kem_ct: NotRequired[bytes]
    wrap: NotRequired[bytes]


class EncryptionEnvelope(TypedDict):
    """``item.enc`` — the typed scheme-1 envelope, a permissive superset of the
    slots and passphrase key paths. The two paths are mutually exclusive on
    the wire; cross-field invariants are enforced by the validator rather
    than the type.

    The wire value is a CHOICE between this typed shape and an OPAQUE reading
    (``scheme`` plus arbitrary bounded metadata) that the validator applies
    when ``scheme`` / ``kem`` / ``aead`` name identifiers outside the
    implemented set. The choice is decided by identifier support, never by
    shape success — a ``scheme: 1`` envelope that fails the typed shape is
    rejected with its typed code, never reclassified as opaque.
    """

    scheme: Literal[1]
    aead: AeadAlgId
    nonce: bytes
    # The KEM identifier is hoisted to envelope scope because every slot in a
    # record shares the same KEM by construction. Required when `slots` is
    # present; unused on the passphrase path.
    kem: NotRequired[KemAlgId]
    slots: NotRequired[list[Slot]]
    slots_mac: NotRequired[bytes]
    passphrase: NotRequired[PassphraseKdf]


class Item(TypedDict):
    """``items[i]`` — content-hash commitments + optional retrieval URIs +
    optional encryption envelope.

    ``hashes`` is a non-empty CBOR map keyed by content-hash algorithm
    identifier; each value is the digest. ``uris`` is an array of absolute
    URIs, each a SINGLE text string from the closed ``{ar://, ipfs://}``
    fetch set.

    No per-item ``sig`` — signatures attach at the record level only.
    """

    hashes: dict[HashAlgId, bytes]
    uris: NotRequired[list[str]]
    enc: NotRequired[EncryptionEnvelope]


class MerkleCommit(TypedDict):
    """``merkle[i]`` — a top-level list commitment.

    ``alg`` is from the list-commitment registry (currently
    ``{rfc9162-sha256}``). ``root`` is the canonical Merkle root (32 bytes
    for ``rfc9162-sha256``). ``leaf_count`` is REQUIRED, a CBOR unsigned
    integer pinned to ``1 .. 2^32 - 1``, and binds the commitment to the
    off-chain leaves-list size.
    """

    alg: MerkleCommitAlgId
    root: bytes
    leaf_count: int
    uris: NotRequired[list[str]]


class SigEntry(TypedDict):
    """``sigs[i]`` — a closed CBOR map ``{cose_sign1, ? cose_key}``.

    ``cose_sign1`` is REQUIRED: a SINGLE byte string carrying the
    CBOR-encoded detached COSE_Sign1. ``cose_key`` is OPTIONAL: a SINGLE
    byte string carrying a ``cbor<COSE_Key>`` map for the wallet signer path
    (path 2). No other keys are permitted.
    """

    cose_sign1: bytes
    cose_key: NotRequired[bytes]


# On the wire `supersedes` is the bare 32-byte transaction hash.
Supersedes = bytes


class PoeRecord(TypedDict):
    """Top-level Label 309 record.

    A conformant record MUST carry at least one of ``items`` (>= 1 entry) or
    ``merkle`` (>= 1 entry); cross-field enforcement lives in the validator
    and an empty record surfaces as SCHEMA_EMPTY_RECORD. Extension keys
    (``x-…`` / ``<companion>-…``) live on the record at runtime but not in
    this static shape.
    """

    v: Literal[1]
    items: NotRequired[list[Item]]
    merkle: NotRequired[list[MerkleCommit]]
    supersedes: NotRequired[bytes]
    sigs: NotRequired[list[SigEntry]]
    crit: NotRequired[list[str]]


# ---------------------------------------------------------------------------
# Closed top-level base-key registry
# ---------------------------------------------------------------------------
#
# Used by the validator's domain pass to distinguish unknown-typo keys from
# well-formed extension keys.
TOP_LEVEL_BASE_KEYS: Final[frozenset[str]] = frozenset(
    {"v", "items", "merkle", "supersedes", "sigs", "crit"}
)

# Extension-key namespaces: `x-…` (vendor / experimental) and `<lowercase>-…`
# (companion namespace), with control characters (U+0000..U+001F,
# U+007F..U+009F) rejected ANYWHERE in the key — including a trailing newline,
# so `x-note\n` and `x-a\nb` are both outside the namespace. The suffix
# character class spells the exclusion out rather than relying on `.`
# semantics, the literal `x-` / `[a-z]+-` prefixes admit no control
# characters by construction, and the `\A…\Z` anchors match only the true
# string boundaries (Python's `$` would tolerate a single trailing newline).
EXTENSION_KEY_VENDOR_RE: Final[re.Pattern[str]] = re.compile(r"\Ax-[^\x00-\x1f\x7f-\x9f]+\Z")
EXTENSION_KEY_COMPANION_RE: Final[re.Pattern[str]] = re.compile(
    r"\A[a-z]+-[^\x00-\x1f\x7f-\x9f]+\Z"
)


def is_extension_key(key: str) -> bool:
    return (
        EXTENSION_KEY_VENDOR_RE.match(key) is not None
        or EXTENSION_KEY_COMPANION_RE.match(key) is not None
    )


__all__ = [
    "EXTENSION_KEY_COMPANION_RE",
    "EXTENSION_KEY_VENDOR_RE",
    "TOP_LEVEL_BASE_KEYS",
    "AeadAlgId",
    "Argon2Params",
    "EncryptionEnvelope",
    "HashAlgId",
    "Item",
    "KemAlgId",
    "MerkleCommit",
    "MerkleCommitAlgId",
    "PassphraseAlgId",
    "PassphraseKdf",
    "PoeRecord",
    "SigEntry",
    "Slot",
    "Supersedes",
    "is_extension_key",
]
