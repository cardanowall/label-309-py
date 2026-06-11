"""Behaviour tests for the enc.scheme 1 sealed-PoE construction.

These are self-generated (no pinned fixture bytes): they encrypt and decrypt
inside the test, so they exercise the construction's properties without
depending on the conformance vectors. They lock in the transcript binding (the
slots transcript commits scheme/path/aead/kem/nonce, the slot set, and the
item's hashes digest), the nonce-salted per-slot KEK derivation under both
KEMs, the per-slot KEK-uniqueness rejection, the explicit all-zero
shared-secret rejection, the payload-key separation (content keyed under a CEK
leaf, never the CEK directly), and the pinned STREAM constants.
"""

from __future__ import annotations

import hashlib

import pytest

from cardanowall._crypto.kem import x25519_public_key
from cardanowall._crypto.mlkem768x25519 import xwing_keygen
from cardanowall._crypto.sealed_poe import (
    UNWRAP_REASON_TAMPERED_HEADER,
    UNWRAP_REASON_WRONG_RECIPIENT_KEY,
    EciesSealedPoeError,
    SealedEnvelope,
    SealedSlot,
    _compute_slots_hash,
    _slots_mac_from_hash,
    _x25519_kek_salt,
    _xwing_kek_salt,
    ecies_sealed_poe_unwrap,
    ecies_sealed_poe_wrap,
    item_hashes_hash,
)


def _priv(seed: int) -> bytes:
    return bytes((seed + i) & 0xFF for i in range(32))


def _hashes_for(plaintext: bytes) -> dict[str, bytes]:
    return {"sha2-256": hashlib.sha256(plaintext).digest()}


# ---------------------------------------------------------------------------
# Round-trips under the STREAM content layer.
# ---------------------------------------------------------------------------


def test_classical_roundtrip() -> None:
    priv = _priv(0x11)
    plaintext = b"classical payload"
    hashes = _hashes_for(plaintext)
    out = ecies_sealed_poe_wrap(
        plaintext=plaintext,
        recipient_public_keys=[x25519_public_key(priv)],
        hashes=hashes,
    )
    res = ecies_sealed_poe_unwrap(
        envelope=out.envelope, ciphertext=out.ciphertext, hashes=hashes, recipient_secret_key=priv
    )
    assert res.matched is True
    assert res.plaintext == plaintext


def test_hybrid_roundtrip() -> None:
    pub, seed = xwing_keygen(b"\x07" * 32)
    plaintext = b"hybrid payload"
    hashes = _hashes_for(plaintext)
    out = ecies_sealed_poe_wrap(
        plaintext=plaintext,
        recipient_public_keys=[pub],
        hashes=hashes,
        kem="mlkem768x25519",
    )
    res = ecies_sealed_poe_unwrap(
        envelope=out.envelope, ciphertext=out.ciphertext, hashes=hashes, recipient_secret_key=seed
    )
    assert res.matched is True
    assert res.plaintext == plaintext


def test_large_multi_chunk_roundtrip() -> None:
    # A payload crossing the 65536-byte STREAM chunk boundary round-trips.
    priv = _priv(0x13)
    plaintext = bytes(i & 0xFF for i in range(65536 + 1234))
    hashes = _hashes_for(plaintext)
    out = ecies_sealed_poe_wrap(
        plaintext=plaintext,
        recipient_public_keys=[x25519_public_key(priv)],
        hashes=hashes,
    )
    # Two chunks → two 16-byte tags.
    assert len(out.ciphertext) == len(plaintext) + 32
    res = ecies_sealed_poe_unwrap(
        envelope=out.envelope, ciphertext=out.ciphertext, hashes=hashes, recipient_secret_key=priv
    )
    assert res.matched is True
    assert res.plaintext == plaintext


def test_content_not_encrypted_under_cek_directly() -> None:
    """The content payload_key is HKDF(CEK, salt=nonce, info=payload-v1); the CEK
    itself must NOT open the content STREAM."""
    from cardanowall._crypto.stream import StreamTamperedError, stream_open

    priv = _priv(0x22)
    cek = b"\x5a" * 32
    nonce = b"\x33" * 24
    plaintext = b"payload-key separation"
    hashes = _hashes_for(plaintext)
    out = ecies_sealed_poe_wrap(
        plaintext=plaintext,
        recipient_public_keys=[x25519_public_key(priv)],
        hashes=hashes,
        cek=cek,
        nonce=nonce,
        skip_shuffle=True,
    )
    with pytest.raises(StreamTamperedError):
        stream_open(cek, out.ciphertext)


# ---------------------------------------------------------------------------
# Transcript binding: scheme/path/aead/kem/nonce + slots + hashes_hash.
# ---------------------------------------------------------------------------


def test_nonce_swap_fails_decryption() -> None:
    """The nonce is bound into every per-slot KEK salt AND the slots
    transcript, so swapping it makes the recipient's own wrap fail to open —
    nothing is accepted (the single generic failure)."""
    priv = _priv(0x44)
    plaintext = b"nonce binding"
    hashes = _hashes_for(plaintext)
    out = ecies_sealed_poe_wrap(
        plaintext=plaintext, recipient_public_keys=[x25519_public_key(priv)], hashes=hashes
    )
    swapped = SealedEnvelope(
        scheme=1,
        aead=out.envelope.aead,
        kem=out.envelope.kem,
        nonce=bytes((b + 1) & 0xFF for b in out.envelope.nonce),
        slots=out.envelope.slots,
        slots_mac=out.envelope.slots_mac,
    )
    res = ecies_sealed_poe_unwrap(
        envelope=swapped, ciphertext=out.ciphertext, hashes=hashes, recipient_secret_key=priv
    )
    assert res.matched is False
    assert res.reason == UNWRAP_REASON_WRONG_RECIPIENT_KEY


def test_slots_mac_is_hmac_over_slots_hash() -> None:
    """slots_mac = HMAC(HKDF(CEK), slots_hash) where slots_hash =
    SHA-256(transcript-prefix || canonicalEncode(SLOTS_TRANSCRIPT)) and the
    transcript binds the item's hashes digest."""
    priv = _priv(0x48)
    cek = b"\x91" * 32
    nonce = b"\x77" * 24
    plaintext = b"mac-over-hash"
    hashes = _hashes_for(plaintext)
    out = ecies_sealed_poe_wrap(
        plaintext=plaintext,
        recipient_public_keys=[x25519_public_key(priv)],
        hashes=hashes,
        cek=cek,
        nonce=nonce,
        skip_shuffle=True,
    )
    hashes_hash = item_hashes_hash(hashes)
    slots_hash = _compute_slots_hash(nonce, out.envelope.slots, "x25519", hashes_hash)
    assert len(slots_hash) == 32
    expected_mac = _slots_mac_from_hash(cek, slots_hash)
    assert out.envelope.slots_mac == expected_mac
    # A different hashes map yields a different transcript hash.
    other_hash = item_hashes_hash(_hashes_for(b"other"))
    assert _compute_slots_hash(nonce, out.envelope.slots, "x25519", other_hash) != slots_hash


def test_item_hashes_hash_requires_a_content_hash() -> None:
    with pytest.raises(EciesSealedPoeError) as exc:
        item_hashes_hash({})
    assert exc.value.code == "ENC_REQUIRES_CONTENT_HASH"
    # Deterministic over the canonical map encoding (key order irrelevant).
    a = item_hashes_hash({"sha2-256": b"\x01" * 32, "blake2b-256": b"\x02" * 32})
    b = item_hashes_hash({"blake2b-256": b"\x02" * 32, "sha2-256": b"\x01" * 32})
    assert a == b


# ---------------------------------------------------------------------------
# Per-slot KEK salts: SHA-256(label || enc.nonce || <KEM material> || pub_R).
# ---------------------------------------------------------------------------


def test_x25519_kek_salt_binds_nonce_epk_and_recipient() -> None:
    nonce = b"\x10" * 24
    epk = x25519_public_key(_priv(0x31))
    pub = x25519_public_key(_priv(0x33))
    salt = _x25519_kek_salt(nonce, epk, pub)
    assert len(salt) == 32
    assert _x25519_kek_salt(bytes((b + 1) & 0xFF for b in nonce), epk, pub) != salt
    assert _x25519_kek_salt(nonce, x25519_public_key(_priv(0x35)), pub) != salt
    assert _x25519_kek_salt(nonce, epk, x25519_public_key(_priv(0x37))) != salt
    expected = hashlib.sha256(b"cardano-poe-x25519-kek-salt-v1" + nonce + epk + pub).digest()
    assert salt == expected


def test_hybrid_kek_salt_binds_nonce_kem_ct_and_recipient_pub() -> None:
    pub, _seed = xwing_keygen(b"\x21" * 32)
    plaintext = b"hybrid salt binding"
    hashes = _hashes_for(plaintext)
    out = ecies_sealed_poe_wrap(
        plaintext=plaintext,
        recipient_public_keys=[pub],
        hashes=hashes,
        kem="mlkem768x25519",
        skip_shuffle=True,
    )
    nonce = out.envelope.nonce
    slot = out.envelope.slots[0]
    assert slot.kem_ct is not None
    salt = _xwing_kek_salt(nonce, slot.kem_ct, pub)
    assert len(salt) == 32
    other_pub, _ = xwing_keygen(b"\x99" * 32)
    assert _xwing_kek_salt(nonce, slot.kem_ct, other_pub) != salt
    flipped = bytes([slot.kem_ct[0] ^ 0x01]) + slot.kem_ct[1:]
    assert _xwing_kek_salt(nonce, flipped, pub) != salt
    assert _xwing_kek_salt(bytes((b + 1) & 0xFF for b in nonce), slot.kem_ct, pub) != salt
    expected = hashlib.sha256(b"cardano-poe-xwing-kek-salt-v1" + nonce + slot.kem_ct + pub).digest()
    assert salt == expected


def test_hybrid_decrypt_recomputes_recipient_pub_from_seed() -> None:
    """The decapsulating recipient never sees pub_R on the wire — it recomputes
    its own X-Wing public key from the held seed via xwing_keygen, which is the
    same value the producer bound into the KEK salt. The hybrid round-trip
    succeeding is the proof the recompute matches."""
    seeds = [b"\x31" * 32, b"\x32" * 32, b"\x33" * 32]
    pubs = [xwing_keygen(s)[0] for s in seeds]
    plaintext = b"multi-recipient hybrid"
    hashes = _hashes_for(plaintext)
    out = ecies_sealed_poe_wrap(
        plaintext=plaintext,
        recipient_public_keys=pubs,
        hashes=hashes,
        kem="mlkem768x25519",
    )
    for s in seeds:
        res = ecies_sealed_poe_unwrap(
            envelope=out.envelope, ciphertext=out.ciphertext, hashes=hashes, recipient_secret_key=s
        )
        assert res.matched is True
        assert res.plaintext == plaintext


# ---------------------------------------------------------------------------
# Per-slot KEK uniqueness.
# ---------------------------------------------------------------------------


def test_unwrap_rejects_duplicate_x25519_epk() -> None:
    priv = _priv(0x52)
    plaintext = b"x"
    hashes = _hashes_for(plaintext)
    out = ecies_sealed_poe_wrap(
        plaintext=plaintext,
        recipient_public_keys=[x25519_public_key(priv)],
        hashes=hashes,
        skip_shuffle=True,
    )
    dup = SealedEnvelope(
        scheme=1,
        aead=out.envelope.aead,
        kem="x25519",
        nonce=out.envelope.nonce,
        slots=(out.envelope.slots[0], out.envelope.slots[0]),
        slots_mac=out.envelope.slots_mac,
    )
    with pytest.raises(EciesSealedPoeError) as exc:
        ecies_sealed_poe_unwrap(
            envelope=dup, ciphertext=out.ciphertext, hashes=hashes, recipient_secret_key=priv
        )
    assert exc.value.code == "ENC_SLOTS_DUPLICATE_KEM_MATERIAL"


def test_wrap_rejects_duplicate_recipient_with_reused_ephemeral() -> None:
    """Recipient deduplication failure: the same recipient supplied twice with
    the same ephemeral would reuse one slot's KEM material; the producer
    rejects it."""
    priv = _priv(0x54)
    pub = x25519_public_key(priv)
    plaintext = b"dup recipient"
    with pytest.raises(EciesSealedPoeError) as exc:
        ecies_sealed_poe_wrap(
            plaintext=plaintext,
            recipient_public_keys=[pub, pub],
            hashes=_hashes_for(plaintext),
            ephemeral_secrets=[_priv(0x60), _priv(0x60)],
            skip_shuffle=True,
        )
    assert exc.value.code == "ENC_SLOTS_DUPLICATE_KEM_MATERIAL"


def test_unwrap_rejects_duplicate_hybrid_kem_ct() -> None:
    pub, seed = xwing_keygen(b"\x41" * 32)
    plaintext = b"y"
    hashes = _hashes_for(plaintext)
    out = ecies_sealed_poe_wrap(
        plaintext=plaintext,
        recipient_public_keys=[pub],
        hashes=hashes,
        kem="mlkem768x25519",
        skip_shuffle=True,
    )
    slot = out.envelope.slots[0]
    dup = SealedEnvelope(
        scheme=1,
        aead=out.envelope.aead,
        kem="mlkem768x25519",
        nonce=out.envelope.nonce,
        slots=(slot, SealedSlot(kem_ct=slot.kem_ct, wrap=slot.wrap)),
        slots_mac=out.envelope.slots_mac,
    )
    with pytest.raises(EciesSealedPoeError) as exc:
        ecies_sealed_poe_unwrap(
            envelope=dup, ciphertext=out.ciphertext, hashes=hashes, recipient_secret_key=seed
        )
    assert exc.value.code == "ENC_SLOTS_DUPLICATE_KEM_MATERIAL"


# ---------------------------------------------------------------------------
# Explicit all-zero X25519 shared-secret rejection.
# ---------------------------------------------------------------------------


def test_all_zero_x25519_shared_is_rejected_explicitly() -> None:
    """The direct constant-time all-zero check in the KEM rejects a peer key
    that drives the shared secret to zero; the trial-decrypt loop folds it into
    per-slot acceptance as kem_ok = false (see the low-order regression
    suite)."""
    from cardanowall._crypto.kem import X25519LowOrderPointError, x25519_ecdh

    with pytest.raises(X25519LowOrderPointError):
        x25519_ecdh(_priv(0x70), bytes(32))


def test_all_zero_slot_with_live_sibling_yields_tampered_header() -> None:
    """A low-order epk clobbering one slot makes that slot fail closed while
    the sibling still wrap-opens; the clobbered slot set fails slots_mac, so
    the structured outcome is TAMPERED_HEADER — never a crash."""
    recipient = _priv(0x72)
    other = _priv(0x74)
    plaintext = b"all-zero sibling"
    hashes = _hashes_for(plaintext)
    out = ecies_sealed_poe_wrap(
        plaintext=plaintext,
        recipient_public_keys=[x25519_public_key(recipient), x25519_public_key(other)],
        hashes=hashes,
        skip_shuffle=True,
    )
    slots = (out.envelope.slots[0], SealedSlot(epk=bytes(32), wrap=out.envelope.slots[1].wrap))
    env = SealedEnvelope(
        scheme=1,
        aead=out.envelope.aead,
        kem="x25519",
        nonce=out.envelope.nonce,
        slots=slots,
        slots_mac=out.envelope.slots_mac,
    )
    res = ecies_sealed_poe_unwrap(
        envelope=env, ciphertext=out.ciphertext, hashes=hashes, recipient_secret_key=recipient
    )
    assert res.matched is False
    assert res.reason == UNWRAP_REASON_TAMPERED_HEADER


# ---------------------------------------------------------------------------
# Pinned STREAM constants (the single-shot payload ceiling is retired).
# ---------------------------------------------------------------------------


def test_stream_constants_are_pinned() -> None:
    from cardanowall._crypto.stream import CHUNK_SIZE, TAG_SIZE

    assert CHUNK_SIZE == 65536
    assert TAG_SIZE == 16
