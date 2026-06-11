"""Behaviour + fixture tests for ecies_sealed_poe_trial_decrypt.

Trial-decrypt recovers the CEK + slot index from the on-chain envelope bytes
alone (the content STREAM is never touched). The result is binary — match or
no-match — with every per-slot distinction (KEM validity, wrap-open, MAC)
folded into the acceptance bit. The fixture-driven cases replay the multi-priv
vectors mirrored from the TypeScript builders."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, cast

import pytest

from cardanowall._crypto.kem import x25519_public_key
from cardanowall._crypto.sealed_poe import (
    TRIAL_DECRYPT_KIND_MATCH,
    TRIAL_DECRYPT_KIND_NO_MATCH,
    EciesSealedPoeError,
    SealedEnvelope,
    SealedSlot,
    ecies_sealed_poe_trial_decrypt,
    ecies_sealed_poe_wrap,
)

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "sealed-poe"


def _hashes_for(plaintext: bytes) -> dict[str, bytes]:
    return {"sha2-256": hashlib.sha256(plaintext).digest()}


def _priv(seed: int) -> bytes:
    return bytes((seed + i) & 0xFF for i in range(32))


def test_kind_constants() -> None:
    assert TRIAL_DECRYPT_KIND_MATCH == "match"
    assert TRIAL_DECRYPT_KIND_NO_MATCH == "no_match"


def test_trial_decrypt_match_reports_slot_and_cek() -> None:
    privs = [_priv(0x10), _priv(0x20), _priv(0x30)]
    publics = [x25519_public_key(p) for p in privs]
    plaintext = b"trial decrypt match"
    hashes = _hashes_for(plaintext)
    cek = b"\x6c" * 32
    out = ecies_sealed_poe_wrap(
        plaintext=plaintext,
        recipient_public_keys=publics,
        hashes=hashes,
        cek=cek,
        skip_shuffle=True,
    )
    for idx, priv in enumerate(privs):
        res = ecies_sealed_poe_trial_decrypt(
            envelope=out.envelope, hashes=hashes, recipient_secret_keys=[priv]
        )
        assert res.kind == TRIAL_DECRYPT_KIND_MATCH
        assert res.slot_idx == idx
        assert res.cek == cek


def test_trial_decrypt_no_match_for_stranger() -> None:
    plaintext = b"not for you"
    hashes = _hashes_for(plaintext)
    out = ecies_sealed_poe_wrap(
        plaintext=plaintext,
        recipient_public_keys=[x25519_public_key(_priv(0x40))],
        hashes=hashes,
    )
    res = ecies_sealed_poe_trial_decrypt(
        envelope=out.envelope, hashes=hashes, recipient_secret_keys=[_priv(0x41)]
    )
    assert res.kind == TRIAL_DECRYPT_KIND_NO_MATCH
    assert res.slot_idx is None
    assert res.cek is None


def test_trial_decrypt_forged_mac_is_no_match() -> None:
    # A flipped slots_mac means no candidate CEK can be accepted: the per-slot
    # fold leaves nothing distinguishable from "not mine".
    recipient_priv = bytes([0x7A] * 32)
    pub = x25519_public_key(recipient_priv)
    plaintext = bytes([0xAB] * 16)
    hashes = _hashes_for(plaintext)
    wrapped = ecies_sealed_poe_wrap(plaintext=plaintext, recipient_public_keys=[pub], hashes=hashes)
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
        envelope=tampered, hashes=hashes, recipient_secret_keys=[recipient_priv]
    )
    assert res.kind == TRIAL_DECRYPT_KIND_NO_MATCH


def test_trial_decrypt_hashes_splice_is_no_match() -> None:
    # The transcript binds the item hashes, so the same envelope scanned under
    # a different hash claim is not a match — detection happens on-chain,
    # before any ciphertext fetch.
    priv = _priv(0x50)
    plaintext = b"trial splice"
    hashes = _hashes_for(plaintext)
    out = ecies_sealed_poe_wrap(
        plaintext=plaintext, recipient_public_keys=[x25519_public_key(priv)], hashes=hashes
    )
    res = ecies_sealed_poe_trial_decrypt(
        envelope=out.envelope,
        hashes=_hashes_for(b"a different claim"),
        recipient_secret_keys=[priv],
    )
    assert res.kind == TRIAL_DECRYPT_KIND_NO_MATCH


def test_trial_decrypt_multi_priv_short_circuits_on_match() -> None:
    holder = _priv(0x60)
    plaintext = b"rotation scan"
    hashes = _hashes_for(plaintext)
    out = ecies_sealed_poe_wrap(
        plaintext=plaintext, recipient_public_keys=[x25519_public_key(holder)], hashes=hashes
    )
    privs = [_priv(0x61), _priv(0x62), holder, _priv(0x63)]
    privs_attempted: list[int] = []
    slots_attempted: list[int] = []
    res = ecies_sealed_poe_trial_decrypt(
        envelope=out.envelope,
        hashes=hashes,
        recipient_secret_keys=privs,
        _slots_attempted_out=slots_attempted,
        _privs_attempted_out=privs_attempted,
    )
    assert res.kind == TRIAL_DECRYPT_KIND_MATCH
    assert privs_attempted[0] == 3  # stopped at the matching priv
    assert slots_attempted == [1, 1, 1]  # constant across slots for every priv


def test_trial_decrypt_constant_time_across_slots() -> None:
    n = 8
    privs = [_priv(0x10 + i * 3) for i in range(n)]
    publics = [x25519_public_key(p) for p in privs]
    plaintext = b"constant-time scan"
    hashes = _hashes_for(plaintext)
    out = ecies_sealed_poe_wrap(plaintext=plaintext, recipient_public_keys=publics, hashes=hashes)
    for idx in (0, n // 2, n - 1):
        slots_attempted: list[int] = []
        res = ecies_sealed_poe_trial_decrypt(
            envelope=out.envelope,
            hashes=hashes,
            recipient_secret_keys=[privs[idx]],
            _slots_attempted_out=slots_attempted,
        )
        assert res.kind == TRIAL_DECRYPT_KIND_MATCH
        assert slots_attempted == [n]


def test_trial_decrypt_rejects_empty_recipient_keys() -> None:
    plaintext = b"empty keys"
    hashes = _hashes_for(plaintext)
    out = ecies_sealed_poe_wrap(
        plaintext=plaintext, recipient_public_keys=[x25519_public_key(_priv(0x66))], hashes=hashes
    )
    with pytest.raises(EciesSealedPoeError):
        ecies_sealed_poe_trial_decrypt(
            envelope=out.envelope, hashes=hashes, recipient_secret_keys=[]
        )


def test_trial_decrypt_rejects_bad_nonce_length() -> None:
    plaintext = b"bad nonce"
    hashes = _hashes_for(plaintext)
    priv = _priv(0x68)
    out = ecies_sealed_poe_wrap(
        plaintext=plaintext, recipient_public_keys=[x25519_public_key(priv)], hashes=hashes
    )
    bad = SealedEnvelope(
        scheme=out.envelope.scheme,
        aead=out.envelope.aead,
        kem=out.envelope.kem,
        nonce=b"\x00" * 20,
        slots=out.envelope.slots,
        slots_mac=out.envelope.slots_mac,
    )
    with pytest.raises(EciesSealedPoeError):
        ecies_sealed_poe_trial_decrypt(envelope=bad, hashes=hashes, recipient_secret_keys=[priv])


# ---------------------------------------------------------------------------
# Fixture-driven multi-priv KATs (pinned cross-SDK vectors).
# ---------------------------------------------------------------------------


def _load_multipriv(filename: str) -> dict[str, Any]:
    return cast(dict[str, Any], json.loads((FIXTURES_DIR / filename).read_text()))


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


@pytest.mark.parametrize(
    "filename, expected_kind",
    [
        ("unwrap-multipriv-current-match.json", TRIAL_DECRYPT_KIND_MATCH),
        ("unwrap-multipriv-archived-match.json", TRIAL_DECRYPT_KIND_MATCH),
        ("unwrap-multipriv-no-match.json", TRIAL_DECRYPT_KIND_NO_MATCH),
        ("unwrap-multipriv-n32-k10-worst-case.json", TRIAL_DECRYPT_KIND_MATCH),
        ("unwrap-multipriv-ac9-priv0-slot0.json", TRIAL_DECRYPT_KIND_MATCH),
        ("unwrap-multipriv-ac9-priv0-slot31.json", TRIAL_DECRYPT_KIND_MATCH),
        ("unwrap-multipriv-ac9-priv4-slot0.json", TRIAL_DECRYPT_KIND_MATCH),
        ("unwrap-multipriv-ac9-priv4-slot31.json", TRIAL_DECRYPT_KIND_MATCH),
        ("unwrap-multipriv-ac9-no-match.json", TRIAL_DECRYPT_KIND_NO_MATCH),
    ],
)
def test_trial_decrypt_multipriv_kats(filename: str, expected_kind: str) -> None:
    vector = _load_multipriv(filename)["vector"]
    envelope = _envelope_from_fixture(vector["envelope"])
    hashes = {alg: bytes.fromhex(h) for alg, h in vector["hashes"].items()}
    privs = [bytes.fromhex(h) for h in vector["recipient_privs_hex"]]
    slots_attempted: list[int] = []
    res = ecies_sealed_poe_trial_decrypt(
        envelope=envelope,
        hashes=hashes,
        recipient_secret_keys=privs,
        _slots_attempted_out=slots_attempted,
    )
    assert res.kind == expected_kind, filename
    n_slots = len(envelope.slots)
    for count in slots_attempted:
        assert count == n_slots, f"{filename}: inner loop must be constant across slots"
    if expected_kind == TRIAL_DECRYPT_KIND_MATCH:
        assert res.cek is not None and len(res.cek) == 32
        assert res.slot_idx is not None
