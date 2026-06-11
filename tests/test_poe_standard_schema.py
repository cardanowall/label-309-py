from __future__ import annotations

from cardanowall.poe_standard import (
    EncryptionEnvelope,
    Item,
    PassphraseKdf,
    PoeRecord,
    Slot,
    is_extension_key,
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
        "aead": "chacha20-poly1305-stream64k",
        "kem": "x25519",
        "nonce": b"\x00" * 24,
        "slots": [slot],
        "slots_mac": b"\x00" * 32,
    }
    assert enc["scheme"] == 1
    assert enc["slots"][0]["wrap"] == b"\x00" * 48


def test_envelope_with_hybrid_kem_ct_slots() -> None:
    # The permissive Slot type admits the hybrid (mlkem768x25519) shape:
    # `{ kem_ct: bstr(1120), wrap: bstr(48) }` — a SINGLE byte string, no
    # per-slot `epk`.
    slot: Slot = {"kem_ct": b"\x11" * 1120, "wrap": b"\x02" * 48}
    enc: EncryptionEnvelope = {
        "scheme": 1,
        "aead": "chacha20-poly1305-stream64k",
        "kem": "mlkem768x25519",
        "nonce": b"\x00" * 24,
        "slots": [slot],
        "slots_mac": b"\x07" * 32,
    }
    assert enc["kem"] == "mlkem768x25519"
    assert enc["slots"][0]["kem_ct"] == b"\x11" * 1120
    assert "epk" not in enc["slots"][0]


def test_envelope_with_passphrase() -> None:
    pp: PassphraseKdf = {
        "alg": "argon2id",
        "salt": b"\x00" * 16,
        "params": {"m": 65536, "t": 3, "p": 1},
    }
    enc: EncryptionEnvelope = {
        "scheme": 1,
        "aead": "chacha20-poly1305-stream64k",
        "nonce": b"\x00" * 24,
        "passphrase": pp,
    }
    assert enc["passphrase"]["alg"] == "argon2id"
    assert enc["passphrase"]["params"]["m"] == 65536


def test_item_with_plain_uri_strings() -> None:
    item: Item = {
        "hashes": {"sha2-256": b"\xaa" * 32},
        "uris": ["ar://" + "a" * 43],
    }
    assert item["uris"] == ["ar://" + "a" * 43]


def test_extension_key_namespaces() -> None:
    assert is_extension_key("x-note")
    assert is_extension_key("cip100-body") is False  # digits break `[a-z]+-`
    assert is_extension_key("companion-claim")
    assert not is_extension_key("bogus")
    assert not is_extension_key("X-note")
    # Control characters are rejected anywhere, including a trailing newline
    # that a `$`-anchored pattern would tolerate.
    assert not is_extension_key("x-note\n")
    assert not is_extension_key("x-a\nb")
