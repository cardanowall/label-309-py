"""Fixture-consumption gates for the shared sealed-PoE conformance vectors that
the inline construction tests exercise only as self-generated properties.

Pinned files, loaded from this package's ``tests/fixtures/sealed-poe`` (the
same bytes mirrored into the TypeScript and Rust twins):

* ``x25519-kek-salt.json`` / ``hybrid-kek-salt.json`` — the per-slot KEK HKDF
  salt is ``SHA-256(label || enc.nonce || <slot KEM material> || pub_R)`` and
  the KEK its HKDF leaf; both pins carry the envelope nonce in the input.
* ``construction-negative.json`` — the all-zero X25519 shared-secret fold, the
  hybrid header-binding nonce swap, hybrid per-slot KEK reuse, scheme / aead /
  kem header flips, and the X-Wing invalid-recipient-key seal rejection.
* ``transcript-bytes.json`` — the exact canonicalEncode bytes of
  SLOTS_TRANSCRIPT (both KEMs) and PASSPHRASE_TRANSCRIPT plus the labelled
  item-hashes digests they bind.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

import pytest

from cardanowall._crypto.kdf import hkdf_sha256
from cardanowall._crypto.kem import x25519_ecdh, x25519_public_key
from cardanowall._crypto.mlkem768x25519 import xwing_encapsulate, xwing_keygen
from cardanowall._crypto.sealed_poe import (
    CARDANO_POE_HKDF_INFO_KEK,
    CARDANO_POE_HKDF_INFO_KEK_MLKEM768X25519,
    Argon2idParams,
    EciesSealedPoeError,
    SealedEnvelope,
    SealedSlot,
    _compute_pw_hash,
    _compute_slots_hash,
    _passphrase_transcript,
    _slots_transcript,
    _x25519_kek_salt,
    _xwing_kek_salt,
    ecies_sealed_poe_unwrap,
    ecies_sealed_poe_wrap,
    item_hashes_hash,
)

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "sealed-poe"


def _load(filename: str) -> dict[str, Any]:
    return cast(dict[str, Any], json.loads((FIXTURES_DIR / filename).read_text()))


def _hashes_from_fixture(hashes_hex: dict[str, str]) -> dict[str, bytes]:
    return {alg: bytes.fromhex(h) for alg, h in hashes_hex.items()}


def _envelope_from_fixture(env: dict[str, Any]) -> SealedEnvelope:
    slots: list[SealedSlot] = []
    for s in env["slots"]:
        if "epk_hex" in s:
            slots.append(
                SealedSlot(epk=bytes.fromhex(s["epk_hex"]), wrap=bytes.fromhex(s["wrap_hex"]))
            )
        else:
            slots.append(
                SealedSlot(kem_ct=bytes.fromhex(s["kem_ct_hex"]), wrap=bytes.fromhex(s["wrap_hex"]))
            )
    return SealedEnvelope(
        scheme=int(env["scheme"]),
        aead=str(env["aead"]),
        kem=str(env["kem"]),
        nonce=bytes.fromhex(str(env["nonce_hex"])),
        slots=tuple(slots),
        slots_mac=bytes.fromhex(str(env["slots_mac_hex"])),
    )


def test_x25519_kek_salt_matches_pinned_vector() -> None:
    vector = _load("x25519-kek-salt.json")["vector"]
    nonce = bytes.fromhex(str(vector["enc_nonce_hex"]))
    priv = bytes.fromhex(str(vector["recipient_secret_hex"]))
    eph = bytes.fromhex(str(vector["ephemeral_secret_hex"]))

    pub = x25519_public_key(priv)
    assert pub.hex() == vector["recipient_public_hex"]
    epk = x25519_public_key(eph)
    assert epk.hex() == vector["epk_hex"]

    salt = _x25519_kek_salt(nonce, epk, pub)
    assert salt.hex() == vector["expected_kek_salt_hex"]

    shared = x25519_ecdh(eph, pub)
    kek = hkdf_sha256(ikm=shared, salt=salt, info=CARDANO_POE_HKDF_INFO_KEK, length=32)
    assert kek.hex() == vector["expected_kek_hex"]


def test_hybrid_kek_salt_matches_pinned_vector() -> None:
    vector = _load("hybrid-kek-salt.json")["vector"]
    nonce = bytes.fromhex(str(vector["enc_nonce_hex"]))
    seed = bytes.fromhex(str(vector["recipient_seed_hex"]))
    eseed = bytes.fromhex(str(vector["eseed_hex"]))

    # pub_R is recomputed from the recipient seed, exactly as the unwrap path
    # does once per private key. xwing_keygen returns (public_key, secret_seed).
    public_key, _ = xwing_keygen(seed)
    assert public_key.hex() == vector["recipient_public_hex"]
    assert len(public_key) == 1216

    kem_ct, shared = xwing_encapsulate(public_key, eseed)
    assert kem_ct.hex() == vector["kem_ct_hex"]
    assert len(kem_ct) == 1120

    salt = _xwing_kek_salt(nonce, kem_ct, public_key)
    assert salt.hex() == vector["expected_kek_salt_hex"]

    kek = hkdf_sha256(
        ikm=shared, salt=salt, info=CARDANO_POE_HKDF_INFO_KEK_MLKEM768X25519, length=32
    )
    assert kek.hex() == vector["expected_kek_hex"]


def test_all_zero_x25519_shared_secret_is_a_failed_slot() -> None:
    corpus = _load("construction-negative.json")
    for vector in corpus["all_zero_shared_vectors"]:
        result = ecies_sealed_poe_unwrap(
            envelope=_envelope_from_fixture(vector["envelope"]),
            ciphertext=bytes.fromhex(str(vector["ciphertext_hex"])),
            hashes=_hashes_from_fixture(vector["hashes"]),
            recipient_secret_key=bytes.fromhex(str(vector["recipient_secret_hex"])),
        )
        assert result.matched is False, vector["name"]
        assert result.reason == vector["expected_reason"], vector["name"]


def test_hybrid_nonce_swap_breaks_header_binding() -> None:
    corpus = _load("construction-negative.json")
    for vector in corpus["hybrid_header_binding_vectors"]:
        result = ecies_sealed_poe_unwrap(
            envelope=_envelope_from_fixture(vector["envelope"]),
            ciphertext=bytes.fromhex(str(vector["ciphertext_hex"])),
            hashes=_hashes_from_fixture(vector["hashes"]),
            recipient_secret_key=bytes.fromhex(str(vector["recipient_secret_hex"])),
        )
        assert result.matched is False, vector["name"]
        assert result.reason == vector["expected_reason"], vector["name"]


def test_header_flips_and_hybrid_duplicates_raise_typed_codes() -> None:
    corpus = _load("construction-negative.json")
    for vector in corpus["header_flip_vectors"] + corpus["hybrid_duplicate_kem_ct_vectors"]:
        with pytest.raises(EciesSealedPoeError) as exc:
            ecies_sealed_poe_unwrap(
                envelope=_envelope_from_fixture(vector["envelope"]),
                ciphertext=bytes.fromhex(str(vector["ciphertext_hex"])),
                hashes=_hashes_from_fixture(vector["hashes"]),
                recipient_secret_key=bytes.fromhex(str(vector["recipient_secret_hex"])),
            )
        assert exc.value.code == vector["expected_error_code"], vector["name"]


def test_xwing_invalid_recipient_pk_is_rejected_at_seal() -> None:
    corpus = _load("construction-negative.json")
    for vector in corpus["xwing_invalid_recipient_pk_vectors"]:
        invalid_pub = bytes.fromhex(str(vector["recipient_public_hex"]))
        assert len(invalid_pub) == 1216
        with pytest.raises(EciesSealedPoeError) as exc:
            ecies_sealed_poe_wrap(
                plaintext=b"never sealed",
                recipient_public_keys=[invalid_pub],
                hashes={"sha2-256": bytes(32)},
                kem="mlkem768x25519",
                eseeds=[bytes.fromhex(str(vector["eseed_hex"]))],
                skip_shuffle=True,
            )
        assert exc.value.code == vector["expected_error_code"], vector["name"]


def _slots_from_wrap(filename: str, kem: str) -> tuple[bytes, tuple[SealedSlot, ...], bytes]:
    """Load (nonce, slots, hashes_hash) inputs from a committed wrap fixture."""
    wrap = _load(filename)["vector"]
    if kem == "x25519":
        slots = tuple(
            SealedSlot(epk=bytes.fromhex(s["epk_hex"]), wrap=bytes.fromhex(s["wrap_hex"]))
            for s in wrap["expected_slots"]
        )
    else:
        slots = tuple(
            SealedSlot(kem_ct=bytes.fromhex(s["kem_ct_hex"]), wrap=bytes.fromhex(s["wrap_hex"]))
            for s in wrap["expected_slots"]
        )
    hashes_hash = item_hashes_hash(_hashes_from_fixture(wrap["hashes"]))
    return bytes.fromhex(wrap["nonce_hex"]), slots, hashes_hash


def test_transcript_bytes_match_pinned_vectors() -> None:
    # Pins the exact canonicalEncode output of SLOTS_TRANSCRIPT (both KEMs),
    # PASSPHRASE_TRANSCRIPT, and the item-hashes digests, so a canonical-
    # encoding divergence is caught directly, not only via a downstream
    # slots_mac / commitment mismatch.
    corpus = _load("transcript-bytes.json")
    saw_hashes = saw_x25519 = saw_hybrid = saw_passphrase = False
    for vector in corpus["vectors"]:
        name = str(vector["name"])
        if name.startswith("item-hashes-hash"):
            hashes = _hashes_from_fixture(vector["hashes"])
            assert item_hashes_hash(hashes).hex() == vector["expected_hashes_hash_hex"], name
            saw_hashes = True
        elif name.startswith("slots-transcript"):
            kem = str(vector["kem"])
            source = "wrap-n3.json" if kem == "x25519" else "wrap-hybrid-n1.json"
            nonce, slots, hashes_hash = _slots_from_wrap(source, kem)
            assert nonce.hex() == vector["nonce_hex"], name
            assert hashes_hash.hex() == vector["expected_hashes_hash_hex"], name

            transcript = _slots_transcript(nonce, slots, kem, hashes_hash)
            assert transcript.hex() == vector["expected_slots_transcript_canonical_hex"], name

            slots_hash = _compute_slots_hash(nonce, slots, kem, hashes_hash)
            assert slots_hash.hex() == vector["expected_slots_hash_hex"], name
            saw_x25519 = saw_x25519 or kem == "x25519"
            saw_hybrid = saw_hybrid or kem == "mlkem768x25519"
        else:
            nonce = bytes.fromhex(str(vector["nonce_hex"]))
            salt = bytes.fromhex(str(vector["salt_hex"]))
            params = Argon2idParams(
                m=int(vector["params"]["m"]),
                t=int(vector["params"]["t"]),
                p=int(vector["params"]["p"]),
            )
            hashes_hash = item_hashes_hash(_hashes_from_fixture(vector["hashes"]))
            assert hashes_hash.hex() == vector["expected_hashes_hash_hex"], name

            transcript = _passphrase_transcript(nonce, salt, params, hashes_hash)
            assert transcript.hex() == vector["expected_passphrase_transcript_canonical_hex"], name
            pw_hash = _compute_pw_hash(nonce, salt, params, hashes_hash)
            assert pw_hash.hex() == vector["expected_pw_hash_hex"], name
            saw_passphrase = True
    assert saw_hashes and saw_x25519 and saw_hybrid and saw_passphrase
