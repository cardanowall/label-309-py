"""Python parity tests for ecies_sealed_poe_trial_decrypt.

Reuses the existing multi-priv sealed-PoE fixtures already mirrored from the
TS crypto-core package. The trial-decrypt-only function consumes the same
envelope/slots/slots_mac data as ecies_sealed_poe_unwrap and ignores the
ciphertext field (content AEAD is not invoked at trial-decrypt time)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

import pytest

from cardanowall._crypto.kem import x25519_public_key
from cardanowall._crypto.sealed_poe import (
    TRIAL_DECRYPT_KIND_AEAD_PASS_NO_MAC_MATCH,
    TRIAL_DECRYPT_KIND_MATCH,
    TRIAL_DECRYPT_KIND_NO_AEAD_PASS,
    EciesSealedPoeError,
    SealedEnvelope,
    SealedSlot,
    ecies_sealed_poe_trial_decrypt,
    ecies_sealed_poe_wrap,
)

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "sealed-poe"


def _envelope_from_hex(env: dict[str, Any]) -> SealedEnvelope:
    slots = tuple(
        SealedSlot(epk=bytes.fromhex(s["epk_hex"]), wrap=bytes.fromhex(s["wrap_hex"]))
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


def _load_multipriv(filename: str) -> dict[str, Any]:
    return cast(dict[str, Any], json.loads((FIXTURES_DIR / filename).read_text()))


def test_trial_decrypt_current_match_n1_k4() -> None:
    corpus = _load_multipriv("unwrap-multipriv-current-match.json")
    vector = corpus["vector"]
    envelope = _envelope_from_hex(vector["envelope"])
    privs = [bytes.fromhex(h) for h in vector["recipient_privs_hex"]]
    slots_attempted: list[int] = []
    privs_attempted: list[int] = []
    res = ecies_sealed_poe_trial_decrypt(
        envelope=envelope,
        recipient_secret_keys=privs,
        _slots_attempted_out=slots_attempted,
        _privs_attempted_out=privs_attempted,
    )
    assert res.kind == TRIAL_DECRYPT_KIND_MATCH
    assert res.slot_idx == 0
    assert res.cek is not None and len(res.cek) == 32
    assert privs_attempted[0] == vector["expected_outer_loop_count"]


def test_trial_decrypt_archived_match() -> None:
    corpus = _load_multipriv("unwrap-multipriv-archived-match.json")
    vector = corpus["vector"]
    envelope = _envelope_from_hex(vector["envelope"])
    privs = [bytes.fromhex(h) for h in vector["recipient_privs_hex"]]
    slots_attempted: list[int] = []
    privs_attempted: list[int] = []
    res = ecies_sealed_poe_trial_decrypt(
        envelope=envelope,
        recipient_secret_keys=privs,
        _slots_attempted_out=slots_attempted,
        _privs_attempted_out=privs_attempted,
    )
    assert res.kind == TRIAL_DECRYPT_KIND_MATCH
    assert privs_attempted[0] == vector["expected_outer_loop_count"]


def test_trial_decrypt_no_match() -> None:
    corpus = _load_multipriv("unwrap-multipriv-no-match.json")
    vector = corpus["vector"]
    envelope = _envelope_from_hex(vector["envelope"])
    privs = [bytes.fromhex(h) for h in vector["recipient_privs_hex"]]
    res = ecies_sealed_poe_trial_decrypt(
        envelope=envelope,
        recipient_secret_keys=privs,
    )
    assert res.kind == TRIAL_DECRYPT_KIND_NO_AEAD_PASS
    assert res.slot_idx is None
    assert res.cek is None


def test_trial_decrypt_n32_k10_constant_time_n() -> None:
    corpus = _load_multipriv("unwrap-multipriv-n32-k10-worst-case.json")
    vector = corpus["vector"]
    envelope = _envelope_from_hex(vector["envelope"])
    privs = [bytes.fromhex(h) for h in vector["recipient_privs_hex"]]
    slots_attempted: list[int] = []
    privs_attempted: list[int] = []
    res = ecies_sealed_poe_trial_decrypt(
        envelope=envelope,
        recipient_secret_keys=privs,
        _slots_attempted_out=slots_attempted,
        _privs_attempted_out=privs_attempted,
    )
    assert res.kind == TRIAL_DECRYPT_KIND_MATCH
    assert privs_attempted[0] == 10
    assert len(slots_attempted) == 10
    for c in slots_attempted:
        assert c == 32
    assert sum(slots_attempted) == 320


def test_trial_decrypt_ac9_constant_time_n_matrix() -> None:
    scenarios = [
        ("unwrap-multipriv-ac9-priv0-slot0.json", TRIAL_DECRYPT_KIND_MATCH),
        ("unwrap-multipriv-ac9-priv0-slot31.json", TRIAL_DECRYPT_KIND_MATCH),
        ("unwrap-multipriv-ac9-priv4-slot0.json", TRIAL_DECRYPT_KIND_MATCH),
        ("unwrap-multipriv-ac9-priv4-slot31.json", TRIAL_DECRYPT_KIND_MATCH),
        ("unwrap-multipriv-ac9-no-match.json", TRIAL_DECRYPT_KIND_NO_AEAD_PASS),
    ]
    for filename, expected_kind in scenarios:
        corpus = _load_multipriv(filename)
        vector = corpus["vector"]
        envelope = _envelope_from_hex(vector["envelope"])
        privs = [bytes.fromhex(h) for h in vector["recipient_privs_hex"]]
        slots_attempted: list[int] = []
        res = ecies_sealed_poe_trial_decrypt(
            envelope=envelope,
            recipient_secret_keys=privs,
            _slots_attempted_out=slots_attempted,
        )
        assert res.kind == expected_kind, f"{filename} expected {expected_kind}"
        for c in slots_attempted:
            assert c == 32, f"{filename} per-priv slots_attempted should be 32 (constant-time-N)"


def test_trial_decrypt_aead_pass_no_mac_match_for_forged_envelope() -> None:
    # Build a real single-slot envelope, then flip a byte of slots_mac.
    recipient_priv = bytes([0x7A] * 32)
    pub = x25519_public_key(recipient_priv)
    wrapped = ecies_sealed_poe_wrap(
        plaintext=bytes([0xAB] * 16),
        recipient_public_keys=[pub],
    )
    tampered_mac = bytearray(wrapped.envelope.slots_mac)
    tampered_mac[0] ^= 0xFF
    tampered = SealedEnvelope(
        scheme=wrapped.envelope.scheme,
        aead=wrapped.envelope.aead,
        kem=wrapped.envelope.kem,
        nonce=wrapped.envelope.nonce,
        slots=wrapped.envelope.slots,
        slots_mac=bytes(tampered_mac),
    )
    res = ecies_sealed_poe_trial_decrypt(
        envelope=tampered,
        recipient_secret_keys=[recipient_priv],
    )
    assert res.kind == TRIAL_DECRYPT_KIND_AEAD_PASS_NO_MAC_MATCH


def test_trial_decrypt_rejects_empty_recipient_keys() -> None:
    corpus = _load_multipriv("unwrap-multipriv-current-match.json")
    envelope = _envelope_from_hex(corpus["vector"]["envelope"])
    with pytest.raises(EciesSealedPoeError):
        ecies_sealed_poe_trial_decrypt(envelope=envelope, recipient_secret_keys=[])


def test_trial_decrypt_rejects_bad_nonce_length() -> None:
    corpus = _load_multipriv("unwrap-multipriv-current-match.json")
    envelope_dict = dict(corpus["vector"]["envelope"])
    envelope = _envelope_from_hex(envelope_dict)
    privs = [bytes.fromhex(h) for h in corpus["vector"]["recipient_privs_hex"]]
    bad = SealedEnvelope(
        scheme=envelope.scheme,
        aead=envelope.aead,
        kem=envelope.kem,
        nonce=b"\x00" * 20,
        slots=envelope.slots,
        slots_mac=envelope.slots_mac,
    )
    with pytest.raises(EciesSealedPoeError):
        ecies_sealed_poe_trial_decrypt(envelope=bad, recipient_secret_keys=privs)
