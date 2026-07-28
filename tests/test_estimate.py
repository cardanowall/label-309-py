"""Tests for :mod:`cardanowall.estimate` — the pre-quote upper-bound record
sizer.

Two properties are enforced against the real canonical encoder:

1. **Upper bound** — for every shape the composerable record space produces,
   ``estimate_record_bytes(shape) >= len(encode_poe_record(record))`` for a
   real record built from the same shape (including real sealed envelopes and
   real path-1 signatures).
2. **Tightness** — the over-charge stays within the fixed safety margin plus
   the few bytes of fixed-identifier slack, so a record whose real CBOR sits
   just under ``MAX_RECORD_BYTES`` is never falsely rejected pre-quote.

The parity-table test pins the exact byte counts shared literal-for-literal
with the TypeScript and Rust SDK test suites, so the three estimators cannot
drift apart silently.
"""

from __future__ import annotations

from typing import cast

from cardanowall import (
    PoeRecord,
    derive_mlkem768x25519_keypair_from_seed,
    derive_x25519_keypair_from_seed,
    ecies_sealed_poe_wrap,
    encode_poe_record,
    signer_from_seed,
)
from cardanowall.client import assemble_cose_sign1, prepare_sig_structure
from cardanowall.client.publish import _envelope_to_wire
from cardanowall.estimate import (
    _COSE_SIGN1_PATH1_BYTES,
    MAX_RECORD_BYTES,
    EstimateKem,
    ItemShape,
    KemEncShape,
    MerkleShape,
    PassphraseEncShape,
    RecordShape,
    _cbor_header_len,
    estimate_record_bytes,
)
from cardanowall.merkle import MERKLE_ALG_ID, merkle_sha2_256_root
from cardanowall.poe_standard import EncryptionEnvelope, Item

# 48 characters — the cross-SDK parity-table URI (5-byte scheme + 43-byte id).
URI = "ar://0123456789abcdefghijklmnopqrstuvwxyzABCDEFG"


def _signed(record: PoeRecord, seed: bytes) -> PoeRecord:
    """Attach a real path-1 COSE_Sign1 built from ``seed``, so signed shapes
    are compared against an actually-signed record."""
    signer = signer_from_seed(seed)
    sig_structure_bytes, _protected = prepare_sig_structure(
        record=record, signer_pubkey=signer.signer_pubkey
    )
    _cose_sign1_bytes, sig_entry = assemble_cose_sign1(
        record=record,
        signer_pubkey=signer.signer_pubkey,
        signature=signer.sign(sig_structure_bytes),
    )
    return {**record, "sigs": [sig_entry]}


def _sealed_item(
    *,
    plaintext: bytes,
    recipient_seeds: list[bytes],
    kem: EstimateKem,
    uri: str,
) -> tuple[Item, int]:
    """Build a real sealed ``items[0]`` (sha2-256 bind hash + envelope) for
    ``len(recipient_seeds)`` recipients under ``kem``. Returns the item and the
    recipient count."""
    from cardanowall._crypto.hash import sha256

    if kem == "x25519":
        recipients = [derive_x25519_keypair_from_seed(s)["public_key"] for s in recipient_seeds]
    else:
        recipients = [
            derive_mlkem768x25519_keypair_from_seed(s)["public_key"] for s in recipient_seeds
        ]
    digest = sha256(plaintext)
    sealed = ecies_sealed_poe_wrap(
        plaintext=plaintext,
        recipient_public_keys=recipients,
        hashes={"sha2-256": digest},
        kem=kem,
    )
    item: Item = {
        "hashes": {"sha2-256": digest},
        "uris": [uri],
        "enc": _envelope_to_wire(sealed.envelope),
    }
    return item, len(recipients)


def _assert_upper_bound(shape: RecordShape, record: PoeRecord) -> None:
    actual = len(encode_poe_record(record))
    estimate = estimate_record_bytes(shape)
    assert estimate >= actual, f"estimate {estimate} must be >= actual {actual} for {shape!r}"


def _assert_tight(shape: RecordShape, record: PoeRecord, slack: int) -> None:
    actual = len(encode_poe_record(record))
    estimate = estimate_record_bytes(shape)
    assert estimate >= actual, f"estimate {estimate} must be >= actual {actual} for {shape!r}"
    assert estimate - actual <= slack, (
        f"estimate {estimate} over-charges actual {actual} by {estimate - actual} "
        f"(> slack {slack}) for {shape!r}"
    )


# ---------------------------------------------------------------------------
# Cross-SDK parity table
# ---------------------------------------------------------------------------


def test_parity_table_matches_cross_sdk_literals() -> None:
    """The exact same seven literals are asserted in the TypeScript and Rust
    estimator tests; a change here is a cross-SDK breaking change."""
    assert len(URI) == 48
    t1 = RecordShape(items=[ItemShape(hash_algs=["sha2-256"])])
    assert estimate_record_bytes(t1) == 79

    t2 = RecordShape(
        items=[ItemShape(hash_algs=["sha2-256", "blake2b-256"])],
        signed=True,
        supersedes=True,
    )
    assert estimate_record_bytes(t2) == 299

    t3 = RecordShape(items=[ItemShape(hash_algs=["sha2-256", "blake2b-256"], uris=[URI])])
    assert estimate_record_bytes(t3) == 181

    t4 = RecordShape(merkle=MerkleShape(alg="rfc9162-sha256", uris=[URI]), signed=True)
    assert estimate_record_bytes(t4) == 292

    t5 = RecordShape(
        items=[
            ItemShape(
                hash_algs=["sha2-256"],
                uris=[URI],
                enc=KemEncShape(kem="x25519", recipient_count=2),
            )
        ]
    )
    assert estimate_record_bytes(t5) == 472

    t6 = RecordShape(
        items=[
            ItemShape(
                hash_algs=["sha2-256"],
                uris=[URI],
                enc=KemEncShape(kem="mlkem768x25519", recipient_count=11),
            )
        ],
        signed=True,
    )
    assert estimate_record_bytes(t6) == 13459

    t7 = RecordShape(
        items=[
            ItemShape(
                hash_algs=["sha2-256", "blake2b-256"],
                uris=[URI],
                enc=PassphraseEncShape(),
            )
        ],
        signed=True,
    )
    assert estimate_record_bytes(t7) == 457


# ---------------------------------------------------------------------------
# Upper-bound property against the real encoder
# ---------------------------------------------------------------------------


def test_hash_only_single_alg_is_bounded() -> None:
    shape = RecordShape(items=[ItemShape(hash_algs=["sha2-256"])])
    record: PoeRecord = {"v": 1, "items": [{"hashes": {"sha2-256": b"\xab" * 32}}]}
    _assert_upper_bound(shape, record)


def test_hash_only_dual_alg_signed_supersedes_is_bounded() -> None:
    shape = RecordShape(
        items=[ItemShape(hash_algs=["sha2-256", "blake2b-256"])],
        signed=True,
        supersedes=True,
    )
    record: PoeRecord = {
        "v": 1,
        "items": [
            {"hashes": {"sha2-256": b"\xab" * 32, "blake2b-256": b"\xcd" * 32}},
        ],
        "supersedes": b"\x22" * 32,
    }
    _assert_upper_bound(shape, _signed(record, b"\x11" * 32))


def test_public_with_content_uri_is_bounded() -> None:
    shape = RecordShape(items=[ItemShape(hash_algs=["sha2-256", "blake2b-256"], uris=[URI])])
    record: PoeRecord = {
        "v": 1,
        "items": [
            {
                "hashes": {"sha2-256": b"\xab" * 32, "blake2b-256": b"\xcd" * 32},
                "uris": [URI],
            },
        ],
    }
    _assert_upper_bound(shape, record)


def test_multi_item_public_record_is_bounded() -> None:
    """N file items, each with its own hashes + URI: the estimator sums every
    item."""
    shapes: list[ItemShape] = []
    items: list[Item] = []
    for i in range(4):
        uri = f"ar://item-{i}-0123456789abcdefghijklmnopqrstuvwxyzAB"
        shapes.append(ItemShape(hash_algs=["sha2-256", "blake2b-256"], uris=[uri]))
        items.append(
            {
                "hashes": {
                    "sha2-256": bytes([i]) * 32,
                    "blake2b-256": bytes([i + 1]) * 32,
                },
                "uris": [uri],
            }
        )
    shape = RecordShape(items=shapes)
    record: PoeRecord = {"v": 1, "items": items}
    _assert_upper_bound(shape, record)


def test_items_plus_merkle_combined_record_is_bounded() -> None:
    """A record carrying BOTH items[] AND merkle[] (the additive, combinable
    shape): the estimator charges both top-level peers and the exact top-level
    key count."""
    item_uri = "ar://content-item-uri-0123456789abcdefghijklmnop"
    leaves_uri = "ar://leaves-list-uri-0123456789abcdefghijklmnopq"
    leaves = [bytes([i]) * 32 for i in range(3)]
    root = merkle_sha2_256_root(leaves)
    shape = RecordShape(
        items=[ItemShape(hash_algs=["sha2-256", "blake2b-256"], uris=[item_uri])],
        merkle=MerkleShape(alg=MERKLE_ALG_ID, uris=[leaves_uri]),
    )
    record: PoeRecord = {
        "v": 1,
        "items": [
            {
                "hashes": {"sha2-256": b"\xab" * 32, "blake2b-256": b"\xcd" * 32},
                "uris": [item_uri],
            },
        ],
        "merkle": [
            {
                "alg": "rfc9162-sha256",
                "root": root,
                "leaf_count": len(leaves),
                "uris": [leaves_uri],
            },
        ],
    }
    _assert_upper_bound(shape, record)


def test_merkle_record_is_bounded() -> None:
    leaves = [bytes([i]) * 32 for i in range(4)]
    root = merkle_sha2_256_root(leaves)
    uri = "ar://leaves-list-tx"
    shape = RecordShape(merkle=MerkleShape(alg=MERKLE_ALG_ID, uris=[uri]))
    record: PoeRecord = {
        "v": 1,
        "merkle": [
            {"alg": "rfc9162-sha256", "root": root, "leaf_count": len(leaves), "uris": [uri]},
        ],
    }
    _assert_upper_bound(shape, record)


def test_sealed_x25519_many_recipients_is_bounded() -> None:
    uri = "ar://sealed-ciphertext-tx-id-000000000000000000000000000"
    item, recipient_count = _sealed_item(
        plaintext=b"some plaintext",
        recipient_seeds=[bytes([i]) * 32 for i in range(5)],
        kem="x25519",
        uri=uri,
    )
    shape = RecordShape(
        items=[
            ItemShape(
                hash_algs=["sha2-256"],
                uris=[uri],
                enc=KemEncShape(kem="x25519", recipient_count=recipient_count),
            )
        ]
    )
    record: PoeRecord = {"v": 1, "items": [item]}
    _assert_upper_bound(shape, record)


def test_sealed_xwing_signed_is_bounded() -> None:
    uri = "ar://xwing-ct"
    item, recipient_count = _sealed_item(
        plaintext=b"hybrid plaintext",
        recipient_seeds=[bytes([i]) * 32 for i in range(3)],
        kem="mlkem768x25519",
        uri=uri,
    )
    shape = RecordShape(
        items=[
            ItemShape(
                hash_algs=["sha2-256"],
                uris=[uri],
                enc=KemEncShape(kem="mlkem768x25519", recipient_count=recipient_count),
            )
        ],
        signed=True,
    )
    record: PoeRecord = {"v": 1, "items": [item]}
    _assert_upper_bound(shape, _signed(record, b"\x33" * 32))


def _passphrase_envelope_wire(salt: bytes, m: int, t: int, p: int) -> EncryptionEnvelope:
    """A real scheme-1 passphrase envelope (4 keys, no slots) with the given
    salt and Argon2id parameters, exactly as the passphrase publish path
    lowers it into the record."""
    return cast(
        "EncryptionEnvelope",
        {
            "scheme": 1,
            "aead": "chacha20-poly1305-stream64k",
            "nonce": b"\x66" * 24,
            "passphrase": {
                "alg": "argon2id",
                "salt": salt,
                "params": {"m": m, "t": t, "p": p},
            },
        },
    )


def test_sealed_passphrase_signed_is_a_tight_upper_bound() -> None:
    """A signed passphrase-sealed record at the canonical producer shape
    (16-byte salt, registry-floor parameters): the estimate must bound the
    real encoding and stay tight — the only slack is the fixed safety margin
    plus the fixed-id maxima."""
    uri = "ar://0123456789abcdefghijklmnopqrstuvwxyzABCDEF"
    shape = RecordShape(
        items=[
            ItemShape(
                hash_algs=["sha2-256", "blake2b-256"],
                uris=[uri],
                enc=PassphraseEncShape(),
            )
        ],
        signed=True,
    )
    record: PoeRecord = {
        "v": 1,
        "items": [
            {
                "hashes": {"sha2-256": b"\xab" * 32, "blake2b-256": b"\xcd" * 32},
                "uris": [uri],
                "enc": _passphrase_envelope_wire(b"\x55" * 16, 65536, 3, 1),
            },
        ],
    }
    _assert_tight(shape, _signed(record, b"\x2c" * 32), 64)


def test_passphrase_charge_covers_the_in_contract_parameter_region() -> None:
    """The passphrase charge stays an upper bound across the whole in-contract
    parameter region: ``m`` anywhere in the u32 wire range (its floor already
    charges the 4-byte-extension uint width) and ``t`` / ``p`` up to CBOR's
    one-byte immediate maximum of 23."""
    shape = RecordShape(items=[ItemShape(hash_algs=["sha2-256"], enc=PassphraseEncShape())])
    for m, t, p in [
        (65536, 3, 1),
        (2**32 - 1, 3, 1),
        (65536, 23, 23),
        (2**32 - 1, 23, 23),
    ]:
        record: PoeRecord = {
            "v": 1,
            "items": [
                {
                    "hashes": {"sha2-256": b"\xab" * 32},
                    "enc": _passphrase_envelope_wire(b"\x55" * 16, m, t, p),
                },
            ],
        }
        _assert_upper_bound(shape, record)


# ---------------------------------------------------------------------------
# Exact-width invariants
# ---------------------------------------------------------------------------


def test_cbor_header_len_matches_canonical_widths() -> None:
    """The exact canonical-CBOR argument-header widths at each boundary."""
    assert _cbor_header_len(0) == 1
    assert _cbor_header_len(23) == 1
    assert _cbor_header_len(24) == 2
    assert _cbor_header_len(0xFF) == 2
    assert _cbor_header_len(0x100) == 3
    assert _cbor_header_len(0xFFFF) == 3
    assert _cbor_header_len(0x1_0000) == 5
    assert _cbor_header_len(0xFFFF_FFFF) == 5
    assert _cbor_header_len(0x1_0000_0000) == 9
    assert _cbor_header_len(0xFFFF_FFFF_FFFF_FFFF) == 9


def test_path1_cose_sign1_constant_matches_real_encoding() -> None:
    """The path-1 COSE_Sign1 the estimator charges is exactly the size a real
    detached path-1 signature encodes to — the fixed-shape constant must track
    the SDK's encoder so a signed record's `sigs` charge stays exact."""
    record: PoeRecord = {"v": 1, "items": [{"hashes": {"sha2-256": b"\xab" * 32}}]}
    signer = signer_from_seed(b"\x44" * 32)
    sig_structure_bytes, _protected = prepare_sig_structure(
        record=record, signer_pubkey=signer.signer_pubkey
    )
    cose_sign1_bytes, sig_entry = assemble_cose_sign1(
        record=record,
        signer_pubkey=signer.signer_pubkey,
        signature=signer.sign(sig_structure_bytes),
    )
    assert len(cose_sign1_bytes) == _COSE_SIGN1_PATH1_BYTES
    # And the record carrying it must still be a true upper bound.
    signed: PoeRecord = {**record, "sigs": [sig_entry]}
    shape = RecordShape(items=[ItemShape(hash_algs=["sha2-256"])], signed=True)
    _assert_upper_bound(shape, signed)


def test_estimate_is_tight_for_sealed_xwing_signed() -> None:
    """The estimator stays tight: with exact per-component CBOR widths the
    only slack is the fixed safety margin plus a few bytes of fixed-id maxima
    (AEAD/KEM identifiers), together well under 64 bytes."""
    uri = "ar://0123456789abcdefghijklmnopqrstuvwxyzABCDEF"
    item, recipient_count = _sealed_item(
        plaintext=b"hybrid plaintext",
        recipient_seeds=[bytes([i]) * 32 for i in range(3)],
        kem="mlkem768x25519",
        uri=uri,
    )
    shape = RecordShape(
        items=[
            ItemShape(
                hash_algs=["sha2-256"],
                uris=[uri],
                enc=KemEncShape(kem="mlkem768x25519", recipient_count=recipient_count),
            )
        ],
        signed=True,
    )
    record: PoeRecord = {"v": 1, "items": [item]}
    _assert_tight(shape, _signed(record, b"\x33" * 32), 64)


def test_realistic_many_xwing_record_under_ceiling_is_not_rejected() -> None:
    """A many-X-Wing-recipient record whose real CBOR sits just under the
    14_000-byte ceiling must NOT be rejected by the pre-quote estimate: the
    estimate of a sub-ceiling record stays under MAX_RECORD_BYTES."""
    uri = "ar://0123456789abcdefghijklmnopqrstuvwxyzABCDEF"
    item, recipient_count = _sealed_item(
        plaintext=b"a realistic sealed payload to many recipients",
        recipient_seeds=[bytes([i]) * 32 for i in range(11)],
        kem="mlkem768x25519",
        uri=uri,
    )
    shape = RecordShape(
        items=[
            ItemShape(
                hash_algs=["sha2-256"],
                uris=[uri],
                enc=KemEncShape(kem="mlkem768x25519", recipient_count=recipient_count),
            )
        ],
        signed=True,
    )
    record: PoeRecord = {"v": 1, "items": [item]}
    signed = _signed(record, b"\x5a" * 32)
    actual = len(encode_poe_record(signed))
    # Preconditions: the real record is genuinely sub-ceiling AND close enough
    # to it for the assertion to be meaningful.
    assert actual < MAX_RECORD_BYTES
    assert actual > MAX_RECORD_BYTES - 1500
    estimate = estimate_record_bytes(shape)
    assert estimate >= actual
    assert estimate <= MAX_RECORD_BYTES, (
        f"a sub-ceiling record (actual {actual}) must not be rejected by the estimate {estimate}"
    )


# ---------------------------------------------------------------------------
# UTF-8 string sizing
# ---------------------------------------------------------------------------

# CBOR text strings are length-prefixed by their UTF-8 BYTE count. Charging
# Python character counts instead would undercount every non-ASCII character
# and silently break the upper-bound contract ("é" is 1 character, 2 bytes).
_NON_ASCII_URI = "é" * 24  # 24 characters, 48 UTF-8 bytes


def test_charges_strings_by_utf8_byte_length_not_characters() -> None:
    non_ascii = estimate_record_bytes(
        RecordShape(items=[ItemShape(hash_algs=["sha2-256"], uris=[_NON_ASCII_URI])])
    )
    ascii_same_bytes = estimate_record_bytes(
        RecordShape(items=[ItemShape(hash_algs=["sha2-256"], uris=["a" * 48])])
    )
    assert non_ascii == ascii_same_bytes


def test_non_ascii_uri_like_string_is_bounded() -> None:
    shape = RecordShape(items=[ItemShape(hash_algs=["sha2-256"], uris=[_NON_ASCII_URI])])
    record: PoeRecord = {
        "v": 1,
        "items": [{"hashes": {"sha2-256": b"\xab" * 32}, "uris": [_NON_ASCII_URI]}],
    }
    _assert_upper_bound(shape, record)


def test_absurd_recipient_count_stays_above_ceiling() -> None:
    """Python ints are unbounded, so no precision guard is needed — this pins
    the cross-SDK property the saturating TS/RS arithmetic protects: an absurd
    recipient count can never come out under the ceiling check."""
    shape = RecordShape(
        items=[
            ItemShape(
                hash_algs=["sha2-256"],
                enc=KemEncShape(kem="mlkem768x25519", recipient_count=2**53),
            )
        ]
    )
    assert estimate_record_bytes(shape) >= MAX_RECORD_BYTES
