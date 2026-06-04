from __future__ import annotations

from typing import Literal, NotRequired, TypedDict

# Label 309 v1 wire-format types. Mirrors the on-wire CBOR shape: top-level
# record, items + hashes map, encryption envelope, merkle commits, sig
# entries, supersedes, and CDDL. TypedDicts are preferred over dataclasses
# for parity: the JSON-ish on-wire shape is exactly what the validator
# returns under `record:` in a successful result, and TypedDict carries the
# field-name discipline without an instantiation layer.
#
# Naming mirrors @cardanowall/poe-standard (TypeScript).

# Algorithm-identifier literal aliases. The on-wire field is a plain CBOR
# text string; the Literal here documents v1's closed registry and lets mypy
# catch typos at producer-side construction.
HashAlgId = Literal["sha2-256", "blake2b-256"]
MerkleCommitAlgId = Literal["rfc9162-sha256"]
AeadAlgId = Literal["xchacha20-poly1305"]
KemAlgId = Literal["x25519", "mlkem768x25519"]
PassphraseAlgId = Literal["argon2id"]


# Chunked byte/text arrays — each chunk is at most 64 bytes, so a value larger
# than one CBOR chunk is split across array entries that reassemble in order.
ChunkedBytesArray = list[bytes]
ChunkedTextArray = list[str]


class Argon2Params(TypedDict):
    """Closed `enc.passphrase.params` shape for `alg = "argon2id"`.

    Cost-parameter floor: m >= 65536 KiB, t >= 3, p >= 1.
    """

    m: int
    t: int
    p: int


class PassphraseKdf(TypedDict):
    """`enc.passphrase` — the passphrase-derived key-path block.

    Salt length is constrained to the inclusive range [16, 64] bytes.
    """

    alg: PassphraseAlgId
    salt: bytes
    params: Argon2Params


class Slot(TypedDict):
    """Per-recipient sealed slot. The slot shape is KEM-driven and the type is
    a permissive superset of both key-paths:

      - x25519:         ``{ epk: bstr(32), wrap: bstr(48) }`` — ``epk`` is the
        per-slot ephemeral X25519 public key; ``wrap`` is the 48-B
        ciphertext+tag (32-B CEK + 16-B ChaCha20-Poly1305 tag).
      - mlkem768x25519: ``{ kem_ct: [ bstr, ... ], wrap: bstr(48) }`` — ``kem_ct``
        is the 1120-byte X-Wing (ML-KEM-768 + X25519) ``enc`` carried as a
        chunked byte-string array; there is NO per-slot ``epk`` on the hybrid
        path.

    Which field MUST/MUST NOT be present for the declared envelope ``kem`` is
    enforced by the validator's KEM-driven domain pass (the type cannot see the
    envelope ``kem`` from a slot in isolation), so all three fields are optional
    here.
    """

    epk: NotRequired[bytes]
    kem_ct: NotRequired[ChunkedBytesArray]
    wrap: NotRequired[bytes]


class EncryptionEnvelope(TypedDict):
    """`item.enc` — a permissive superset of the slots and passphrase
    key-paths. The two paths are mutually exclusive on the wire; cross-field
    invariants are enforced by the validator rather than the type.
    """

    scheme: Literal[1]
    aead: AeadAlgId
    nonce: bytes
    # The KEM identifier is hoisted to envelope scope because every slot in a
    # record shares the same KEM by construction. Required when
    # `slots` is present; unused on the passphrase path.
    kem: NotRequired[KemAlgId]
    slots: NotRequired[list[Slot]]
    slots_mac: NotRequired[bytes]
    passphrase: NotRequired[PassphraseKdf]


class Item(TypedDict):
    """`items[i]` — content-hash commitments + optional retrieval URIs +
    optional encryption envelope.

    `hashes` is a CBOR map keyed by content-hash algorithm identifier; each
    value is the 32-byte digest. `uris` is an array of chunked-text-array
    URIs, each reconstructing to one absolute URI from the closed
    `{ar://, ipfs://}` fetch set.

    No per-item `sig` — signatures attach at the record level only.
    """

    hashes: dict[HashAlgId, bytes]
    uris: NotRequired[list[ChunkedTextArray]]
    enc: NotRequired[EncryptionEnvelope]


class MerkleCommit(TypedDict):
    """`merkle[i]` — a top-level list commitment.

    `alg` is from the list-commitment registry (currently `{rfc9162-sha256}`).
    `root` is the canonical Merkle root (32 B for `rfc9162-sha256`).
    `leaf_count` is REQUIRED and binds the commitment to the off-chain
    leaves-list size; a mismatch surfaces as SCHEMA_MERKLE_LEAF_COUNT_MISMATCH.
    """

    alg: MerkleCommitAlgId
    root: bytes
    leaf_count: int
    uris: NotRequired[list[ChunkedTextArray]]


class SigEntry(TypedDict):
    """`sigs[i]` — a closed CBOR map.

    `cose_sign1` is REQUIRED, chunked-bytes-array of the COSE_Sign1.
    `cose_key` is OPTIONAL, chunked-bytes-array of a `cbor<COSE_Key>` map
    used for the CIP-30 wallet signer path (path 2). No other keys permitted.
    """

    cose_sign1: ChunkedBytesArray
    cose_key: NotRequired[ChunkedBytesArray]


class Supersedes(TypedDict):
    """Supersedes wrapper. The bare 32-byte tx hash is wrapped to keep
    producer-side shapes uniform; the on-wire value under `record.supersedes`
    is the raw 32-byte bstr, not this wrapper map.
    """

    tx: bytes


class PoeRecord(TypedDict):
    """Top-level Label 309 record.

    A conformant record MUST carry at least one of `items` (≥ 1 entry) or
    `merkle` (≥ 1 entry); cross-field enforcement lives in the validator and an
    empty record surfaces as SCHEMA_EMPTY_RECORD.
    """

    v: Literal[1]
    items: NotRequired[list[Item]]
    merkle: NotRequired[list[MerkleCommit]]
    sigs: NotRequired[list[SigEntry]]
    crit: NotRequired[list[str]]
    # On-wire shape: `supersedes` is the raw 32-byte tx hash (bstr), not a
    # wrapper map. The `Supersedes` TypedDict above is a
    # convenience constructor for producer-side tooling that wants a named
    # type; the canonical PoeRecord field is `bytes`.
    supersedes: NotRequired[bytes]


__all__ = [
    "AeadAlgId",
    "Argon2Params",
    "ChunkedBytesArray",
    "ChunkedTextArray",
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
]
