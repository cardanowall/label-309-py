from __future__ import annotations

from cardanowall.poe_standard import (
    EncryptionEnvelope,
    Item,
    PassphraseKdf,
    PoeRecord,
    Slot,
)


def test_minimal_record_construction() -> None:
    record: PoeRecord = {
        "v": 1,
        "items": [{"hashes": {"sha2-256": b"\x00" * 32}}],
    }
    assert record["v"] == 1
    assert record["items"][0]["hashes"]["sha2-256"] == b"\x00" * 32


def test_supersedes_is_bare_32_bytes() -> None:
    record: PoeRecord = {
        "v": 1,
        "items": [{"hashes": {"sha2-256": b"\xaa" * 32}}],
        "supersedes": b"\x01" * 32,
    }
    assert record["supersedes"] == b"\x01" * 32


def test_envelope_with_slots_and_kem() -> None:
    slot: Slot = {"epk": b"\x00" * 32, "wrap": b"\x00" * 48}
    enc: EncryptionEnvelope = {
        "scheme": 1,
        "aead": "xchacha20-poly1305",
        "kem": "x25519",
        "nonce": b"\x00" * 24,
        "slots": [slot],
        "slots_mac": b"\x00" * 32,
    }
    assert enc["scheme"] == 1
    assert enc["slots"][0]["wrap"] == b"\x00" * 48


def test_envelope_with_hybrid_kem_ct_slots() -> None:
    # The permissive Slot type admits the hybrid (mlkem768x25519) shape:
    # `{ kem_ct: [ bstr, ... ], wrap: bstr(48) }` — no per-slot `epk`.
    kem_ct = [b"\x11" * 64] * 17 + [b"\x11" * 32]  # 1120-byte X-Wing enc, chunked
    slot: Slot = {"kem_ct": kem_ct, "wrap": b"\x02" * 48}
    enc: EncryptionEnvelope = {
        "scheme": 1,
        "aead": "xchacha20-poly1305",
        "kem": "mlkem768x25519",
        "nonce": b"\x00" * 24,
        "slots": [slot],
        "slots_mac": b"\x07" * 32,
    }
    assert enc["kem"] == "mlkem768x25519"
    assert b"".join(enc["slots"][0]["kem_ct"]) == b"\x11" * 1120
    assert "epk" not in enc["slots"][0]


def test_envelope_with_passphrase() -> None:
    pp: PassphraseKdf = {
        "alg": "argon2id",
        "salt": b"\x00" * 16,
        "params": {"m": 65536, "t": 3, "p": 1},
    }
    enc: EncryptionEnvelope = {
        "scheme": 1,
        "aead": "xchacha20-poly1305",
        "nonce": b"\x00" * 24,
        "passphrase": pp,
    }
    assert enc["passphrase"]["alg"] == "argon2id"
    assert enc["passphrase"]["params"]["m"] == 65536


def test_item_with_uris_chunked() -> None:
    item: Item = {
        "hashes": {"sha2-256": b"\xaa" * 32},
        "uris": [["ar://", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]],
    }
    assert item["uris"][0] == ["ar://", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]
