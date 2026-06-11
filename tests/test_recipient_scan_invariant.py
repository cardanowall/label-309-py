"""The recipient-scan invariant: given ONLY (a) a recipient's seed-derived
private key and (b) the on-chain record bytes — the canonical-CBOR record body
whose item carries the ``enc`` envelope (slots, slots_mac, nonce, kem, aead) —
the implementation determines that the sealed record is addressed to that key
AND recovers the CEK, with no ciphertext available at all.

This is the contract an inbox feed-scan runs on: it walks a public records
feed of bare record bodies and trial-decrypts each one client-side; the
off-chain ciphertext is fetched only later, when the user opens a matched
record. The tests below never hand the scan the ciphertext, and a blocked
``socket.socket`` proves the whole path performs zero network I/O.
"""

from __future__ import annotations

import hashlib
import socket
from typing import cast

import pytest

from cardanowall._crypto.sealed_poe import (
    TRIAL_DECRYPT_KIND_MATCH,
    TRIAL_DECRYPT_KIND_NO_MATCH,
    SealedEnvelope,
    ecies_sealed_poe_trial_decrypt,
    ecies_sealed_poe_wrap,
)
from cardanowall.poe_standard import PoeRecord, encode_poe_record, validate
from cardanowall.poe_standard.schema import EncryptionEnvelope, Item, Slot
from cardanowall.seed_derive import (
    derive_mlkem768x25519_keypair_from_seed,
    derive_x25519_keypair_from_seed,
)
from cardanowall.verifier.decrypt import _sealed_envelope_from_parsed

RECIPIENT_SEED = bytes(0x42 for _ in range(32))
OTHER_SEED = bytes(0x43 for _ in range(32))
STRANGER_SEED = bytes(0x44 for _ in range(32))

PLAINTEXT = b"feed-scan invariant payload"
HASHES = {"sha2-256": hashlib.sha256(PLAINTEXT).digest()}
CEK = bytes((0xC0 + i) & 0xFF for i in range(32))


@pytest.fixture(autouse=True)
def _no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    """The scan consumes record bytes and a key; it must never open a socket."""

    def _refuse(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("the recipient scan must not perform network I/O")

    monkeypatch.setattr(socket, "socket", _refuse)
    monkeypatch.setattr(socket, "create_connection", _refuse)


def _pattern(start: int, length: int) -> bytes:
    return bytes((start + i) & 0xFF for i in range(length))


def _encode_sealed_record(envelope: SealedEnvelope) -> bytes:
    """The on-chain record body: canonical CBOR of a one-item record whose
    item carries the hash claim plus the ``enc`` envelope — and nothing else."""
    slots: list[Slot]
    if envelope.kem == "x25519":
        slots = [cast("Slot", {"epk": s.epk, "wrap": s.wrap}) for s in envelope.slots]
    else:
        slots = [cast("Slot", {"kem_ct": s.kem_ct, "wrap": s.wrap}) for s in envelope.slots]
    enc = cast(
        "EncryptionEnvelope",
        {
            "scheme": envelope.scheme,
            "aead": envelope.aead,
            "kem": envelope.kem,
            "nonce": envelope.nonce,
            "slots": slots,
            "slots_mac": envelope.slots_mac,
        },
    )
    item = cast("Item", {"hashes": dict(HASHES), "enc": enc})
    record = cast("PoeRecord", {"v": 1, "items": [item]})
    return encode_poe_record(record)


def _scan_record_bytes(
    record_bytes: bytes, secret_key: bytes
) -> tuple[str, int | None, bytes | None]:
    """Walk the product feed-scan path: structural validation of the bare
    record bytes, envelope projection, then ciphertext-free trial-decrypt."""
    result = validate(record_bytes, role="recipient_or_strict")
    assert result.ok, f"record bytes must validate structurally: {result}"
    items = result.record.get("items")
    assert items is not None and len(items) == 1
    item = items[0]
    enc = item.get("enc")
    assert enc is not None
    envelope = _sealed_envelope_from_parsed(enc)
    assert envelope is not None, "record does not carry a sealed-recipient envelope"
    item_hashes: dict[str, bytes] = {str(alg): digest for alg, digest in item["hashes"].items()}
    trial = ecies_sealed_poe_trial_decrypt(
        envelope=envelope,
        hashes=item_hashes,
        recipient_secret_keys=[secret_key],
    )
    return trial.kind, trial.slot_idx, trial.cek


def _x25519_record_bytes() -> bytes:
    recipient = derive_x25519_keypair_from_seed(RECIPIENT_SEED)
    other = derive_x25519_keypair_from_seed(OTHER_SEED)
    # The scanning recipient sits in the SECOND slot so the scan demonstrably
    # walks past a foreign slot; only the envelope survives into the record —
    # the wrap's ciphertext is deliberately discarded.
    out = ecies_sealed_poe_wrap(
        plaintext=PLAINTEXT,
        recipient_public_keys=[other["public_key"], recipient["public_key"]],
        hashes=HASHES,
        cek=CEK,
        nonce=_pattern(0x10, 24),
        ephemeral_secrets=[_pattern(0x20, 32), _pattern(0x60, 32)],
        skip_shuffle=True,
    )
    return _encode_sealed_record(out.envelope)


def _hybrid_record_bytes() -> bytes:
    recipient = derive_mlkem768x25519_keypair_from_seed(RECIPIENT_SEED)
    other = derive_mlkem768x25519_keypair_from_seed(OTHER_SEED)
    out = ecies_sealed_poe_wrap(
        plaintext=PLAINTEXT,
        recipient_public_keys=[other["public_key"], recipient["public_key"]],
        hashes=HASHES,
        kem="mlkem768x25519",
        cek=CEK,
        nonce=_pattern(0x30, 24),
        eseeds=[_pattern(0x21, 64), _pattern(0x61, 64)],
        skip_shuffle=True,
    )
    return _encode_sealed_record(out.envelope)


def test_x25519_seed_scan_matches_and_recovers_the_cek_without_ciphertext() -> None:
    record_bytes = _x25519_record_bytes()
    scanned = derive_x25519_keypair_from_seed(RECIPIENT_SEED)
    kind, slot_idx, cek = _scan_record_bytes(record_bytes, scanned["secret_key"])
    assert kind == TRIAL_DECRYPT_KIND_MATCH
    assert slot_idx == 1
    assert cek == CEK


def test_x25519_non_recipient_seed_scans_to_no_match() -> None:
    record_bytes = _x25519_record_bytes()
    stranger = derive_x25519_keypair_from_seed(STRANGER_SEED)
    kind, slot_idx, cek = _scan_record_bytes(record_bytes, stranger["secret_key"])
    assert kind == TRIAL_DECRYPT_KIND_NO_MATCH
    assert slot_idx is None
    assert cek is None


def test_hybrid_seed_scan_matches_and_recovers_the_cek_without_ciphertext() -> None:
    record_bytes = _hybrid_record_bytes()
    scanned = derive_mlkem768x25519_keypair_from_seed(RECIPIENT_SEED)
    kind, slot_idx, cek = _scan_record_bytes(record_bytes, scanned["secret_seed"])
    assert kind == TRIAL_DECRYPT_KIND_MATCH
    assert slot_idx == 1
    assert cek == CEK


def test_hybrid_non_recipient_seed_scans_to_no_match() -> None:
    record_bytes = _hybrid_record_bytes()
    stranger = derive_mlkem768x25519_keypair_from_seed(STRANGER_SEED)
    kind, slot_idx, cek = _scan_record_bytes(record_bytes, stranger["secret_seed"])
    assert kind == TRIAL_DECRYPT_KIND_NO_MATCH
    assert slot_idx is None
    assert cek is None
