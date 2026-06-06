"""Fixture-consumption gates for the shared sealed-PoE conformance vectors that
the inline construction tests exercise only as self-generated properties.

Three pinned files, loaded from this package's ``tests/fixtures/sealed-poe``
(the same bytes mirrored into the TypeScript and Rust twins):

* ``hybrid-kek-salt.json`` — the X-Wing per-slot KEK salt is
  ``SHA-256("cardano-poe-xwing-kek-salt-v1" || kem_ct || pub_R)``. Re-derive
  ``pub_R`` from the recorded seed via the X-Wing keygen, confirm it matches the
  recorded public key, then assert the salt byte-for-byte.
* ``construction-negative.json`` (``all_zero_shared_vectors``) — an all-zero
  X25519 shared secret must mark the slot failed, not matched
  (``WRONG_RECIPIENT_KEY``).
* ``construction-negative.json`` (``hybrid_header_binding_vectors``) — a hybrid
  envelope whose nonce was swapped after sealing recovers a candidate CEK but
  fails the slots_mac header binding (``TAMPERED_HEADER``).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

from cardanowall._crypto.mlkem768x25519 import xwing_keygen
from cardanowall._crypto.sealed_poe import (
    UNWRAP_REASON_TAMPERED_HEADER,
    UNWRAP_REASON_WRONG_RECIPIENT_KEY,
    SealedEnvelope,
    SealedSlot,
    _ad_content_slots,
    _compute_slots_hash,
    _slots_transcript,
    _xwing_kek_salt,
    ecies_sealed_poe_unwrap,
)
from cardanowall.verifier.decrypt import _ad_content_passphrase

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "sealed-poe"


def _load(filename: str) -> dict[str, Any]:
    return cast(dict[str, Any], json.loads((FIXTURES_DIR / filename).read_text()))


def test_hybrid_kek_salt_matches_pinned_vector() -> None:
    vector = _load("hybrid-kek-salt.json")["vector"]
    seed = bytes.fromhex(str(vector["recipient_seed_hex"]))
    kem_ct = bytes.fromhex(str(vector["kem_ct_hex"]))

    # pub_R is recomputed from the recipient seed, exactly as the unwrap path
    # does once per private key. xwing_keygen returns (public_key, secret_seed).
    public_key, _ = xwing_keygen(seed)
    assert public_key.hex() == vector["recipient_public_hex"]
    assert len(public_key) == 1216
    assert len(kem_ct) == 1120

    salt = _xwing_kek_salt(kem_ct, public_key)
    assert salt.hex() == vector["expected_kek_salt_hex"]


def _x25519_envelope_from_hex(env: dict[str, Any]) -> SealedEnvelope:
    slots = tuple(
        SealedSlot(epk=bytes.fromhex(str(s["epk_hex"])), wrap=bytes.fromhex(str(s["wrap_hex"])))
        for s in env["slots"]
    )
    return SealedEnvelope(
        scheme=int(env["scheme"]),
        aead=str(env["aead"]),
        kem=str(env["kem"]),
        nonce=bytes.fromhex(str(env["nonce_hex"])),
        slots=slots,
        slots_mac=bytes.fromhex(str(env["slots_mac_hex"])),
    )


def _hybrid_envelope_from_hex(env: dict[str, Any]) -> SealedEnvelope:
    # The on-wire chunks reassemble to the 1120-byte enc; the slot carries the
    # flat reassembled bytes (the transcript re-chunks them canonically).
    slots = tuple(
        SealedSlot(
            kem_ct=b"".join(bytes.fromhex(c) for c in s["kem_ct_chunks_hex"]),
            wrap=bytes.fromhex(str(s["wrap_hex"])),
        )
        for s in env["slots"]
    )
    return SealedEnvelope(
        scheme=int(env["scheme"]),
        aead=str(env["aead"]),
        kem=str(env["kem"]),
        nonce=bytes.fromhex(str(env["nonce_hex"])),
        slots=slots,
        slots_mac=bytes.fromhex(str(env["slots_mac_hex"])),
    )


def test_all_zero_x25519_shared_secret_is_a_failed_slot() -> None:
    corpus = _load("construction-negative.json")
    for vector in corpus["all_zero_shared_vectors"]:
        envelope = _x25519_envelope_from_hex(vector["envelope"])
        result = ecies_sealed_poe_unwrap(
            envelope=envelope,
            ciphertext=bytes.fromhex(str(vector["ciphertext_hex"])),
            recipient_secret_key=bytes.fromhex(str(vector["recipient_secret_hex"])),
        )
        assert result.matched is False, vector["name"]
        assert result.reason == vector["expected_reason"], vector["name"]
        # The fixture pins WRONG_RECIPIENT_KEY for the all-zero shared case.
        assert vector["expected_reason"] == UNWRAP_REASON_WRONG_RECIPIENT_KEY


def test_hybrid_nonce_swap_breaks_header_binding() -> None:
    corpus = _load("construction-negative.json")
    for vector in corpus["hybrid_header_binding_vectors"]:
        envelope = _hybrid_envelope_from_hex(vector["envelope"])
        # The recipient seed re-derives the X-Wing key that wrapped the slot, so
        # a candidate CEK is recovered — but the swapped nonce changes the slots
        # transcript and the CEK-keyed slots_mac no longer matches.
        result = ecies_sealed_poe_unwrap(
            envelope=envelope,
            ciphertext=bytes.fromhex(str(vector["ciphertext_hex"])),
            recipient_secret_key=bytes.fromhex(str(vector["recipient_seed_hex"])),
        )
        assert result.matched is False, vector["name"]
        assert result.reason == vector["expected_reason"], vector["name"]
        assert vector["expected_reason"] == UNWRAP_REASON_TAMPERED_HEADER


def _slots_from_wrap(filename: str, kem: str) -> tuple[bytes, tuple[SealedSlot, ...], bytes]:
    """Load (nonce, slots, slots_mac) from a committed wrap fixture."""
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
    return (
        bytes.fromhex(wrap["nonce_hex"]),
        slots,
        bytes.fromhex(wrap["expected_slots_mac_hex"]),
    )


def test_transcript_and_aad_bytes_match_pinned_vectors() -> None:
    # Pins the exact canonicalEncode output of SLOTS_TRANSCRIPT, AD_CONTENT_SLOTS,
    # and AD_CONTENT_PASSPHRASE so a canonical-encoding divergence is caught
    # directly, not only via a downstream slots_mac / AEAD-tag mismatch.
    corpus = _load("transcript-bytes.json")
    saw_x25519 = saw_hybrid = saw_passphrase = False
    for vector in corpus["vectors"]:
        if "kem" in vector:
            kem = str(vector["kem"])
            source = (
                "wrap-n3.json" if kem == "x25519" else "wrap-hybrid-n1.json"
            )
            nonce, slots, slots_mac = _slots_from_wrap(source, kem)
            assert nonce.hex() == vector["nonce_hex"], vector["name"]

            transcript = _slots_transcript(nonce, slots, kem)
            assert transcript.hex() == vector["expected_slots_transcript_canonical_hex"], (
                vector["name"]
            )

            slots_hash = _compute_slots_hash(nonce, slots, kem)
            assert slots_hash.hex() == vector["expected_slots_hash_hex"], vector["name"]

            ad = _ad_content_slots(nonce, kem, slots_hash, slots_mac)
            assert ad.hex() == vector["expected_ad_content_slots_canonical_hex"], vector["name"]
            saw_x25519 = saw_x25519 or kem == "x25519"
            saw_hybrid = saw_hybrid or kem == "mlkem768x25519"
        else:
            kdf = {
                "alg": "argon2id",
                "salt": bytes.fromhex(str(vector["salt_hex"])),
                "params": vector["params"],
            }
            ad = _ad_content_passphrase(bytes.fromhex(str(vector["nonce_hex"])), kdf)  # type: ignore[arg-type]
            expected = vector["expected_ad_content_passphrase_canonical_hex"]
            assert ad.hex() == expected, vector["name"]
            saw_passphrase = True
    assert saw_x25519 and saw_hybrid and saw_passphrase
