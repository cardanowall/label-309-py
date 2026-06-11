from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, cast

import pytest

from cardanowall._crypto.compare_ct import compare_ct
from cardanowall._crypto.kem import x25519_public_key
from cardanowall._crypto.mlkem768x25519 import xwing_keygen
from cardanowall._crypto.sealed_poe import (
    UNWRAP_REASON_TAMPERED_CIPHERTEXT,
    UNWRAP_REASON_TAMPERED_HEADER,
    UNWRAP_REASON_WRONG_RECIPIENT_KEY,
    EciesSealedPoeError,
    SealedEnvelope,
    SealedPoeOutput,
    SealedSlot,
    ecies_sealed_poe_trial_decrypt,
    ecies_sealed_poe_unwrap,
    ecies_sealed_poe_wrap,
)

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "sealed-poe"


def _load(filename: str) -> dict[str, Any]:
    return cast(dict[str, Any], json.loads((FIXTURES_DIR / filename).read_text()))


def _hashes_for(plaintext: bytes) -> dict[str, bytes]:
    return {"sha2-256": hashlib.sha256(plaintext).digest()}


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


# ---------------------------------------------------------------------------
# Pinned wrap KATs (cross-SDK fixtures).
# ---------------------------------------------------------------------------


def _check_wrap_positive(filename: str) -> None:
    vector = _load(filename)["vector"]
    recipient_publics = [bytes.fromhex(h) for h in vector["recipient_publics_hex"]]
    ephemeral_secrets = [bytes.fromhex(h) for h in vector["ephemeral_secrets_hex"]]
    cek = bytes.fromhex(str(vector["cek_hex"]))
    nonce = bytes.fromhex(str(vector["nonce_hex"]))
    plaintext = bytes.fromhex(str(vector["plaintext_hex"]))
    hashes = _hashes_from_fixture(vector["hashes"])

    out = ecies_sealed_poe_wrap(
        plaintext=plaintext,
        recipient_public_keys=recipient_publics,
        hashes=hashes,
        cek=cek,
        nonce=nonce,
        ephemeral_secrets=ephemeral_secrets,
        skip_shuffle=True,
    )

    assert out.envelope.scheme == 1
    assert out.envelope.aead == "chacha20-poly1305-stream64k"
    assert out.envelope.kem == "x25519"
    assert out.envelope.nonce.hex() == vector["nonce_hex"]
    expected_slots = vector["expected_slots"]
    assert len(out.envelope.slots) == len(expected_slots)
    for i, slot in enumerate(out.envelope.slots):
        assert slot.epk is not None
        assert slot.epk.hex() == expected_slots[i]["epk_hex"]
        assert slot.wrap.hex() == expected_slots[i]["wrap_hex"]
    assert out.envelope.slots_mac.hex() == vector["expected_slots_mac_hex"]
    assert out.ciphertext.hex() == vector["expected_ciphertext_hex"]

    epk_set = {s.epk for s in out.envelope.slots}
    wrap_set = {s.wrap for s in out.envelope.slots}
    assert len(epk_set) == len(out.envelope.slots)
    assert len(wrap_set) == len(out.envelope.slots)


def test_wrap_n1_empty_kat() -> None:
    _check_wrap_positive("wrap-n1-empty.json")


def test_wrap_n3_kat() -> None:
    _check_wrap_positive("wrap-n3.json")


def test_wrap_n32_kat() -> None:
    _check_wrap_positive("wrap-n32.json")


# ---------------------------------------------------------------------------
# Pinned unwrap KATs (cross-SDK fixtures).
# ---------------------------------------------------------------------------


def _check_unwrap_positive(filename: str) -> None:
    vector = _load(filename)["vector"]
    envelope = _envelope_from_fixture(vector["envelope"])
    ciphertext = bytes.fromhex(str(vector["ciphertext_hex"]))
    hashes = _hashes_from_fixture(vector["hashes"])
    expected = bytes.fromhex(str(vector["expected_plaintext_hex"]))
    for priv_hex in vector["recipient_secrets_hex"]:
        result = ecies_sealed_poe_unwrap(
            envelope=envelope,
            ciphertext=ciphertext,
            hashes=hashes,
            recipient_secret_key=bytes.fromhex(priv_hex),
        )
        assert result.matched is True, filename
        assert result.plaintext == expected, filename


def test_unwrap_n1_empty_kat() -> None:
    _check_unwrap_positive("unwrap-n1-empty.json")


def test_unwrap_n3_kat() -> None:
    _check_unwrap_positive("unwrap-n3.json")


def test_unwrap_n32_kat() -> None:
    _check_unwrap_positive("unwrap-n32.json")


def test_unwrap_duplicate_recipient_kat() -> None:
    # The same CEK sealed to the same recipient in two slots (fresh distinct
    # ephemerals) MUST decrypt normally — the CEK-conflict check rejects only
    # DIFFERENT recovered CEKs, never honest recipient padding.
    _check_unwrap_positive("unwrap-duplicate-recipient.json")


def test_unwrap_shadow_slot_kat() -> None:
    # A forged slot that wrap-opens with an attacker CEK placed BEFORE the
    # honest slot is skipped by the per-slot MAC fold; the record decrypts
    # under the honest CEK.
    _check_unwrap_positive("unwrap-shadow-slot.json")


def test_unwrap_negative_kats() -> None:
    corpus = _load("unwrap-negative.json")
    for vector in corpus["matched_false_vectors"]:
        # Multi-priv vectors live in the same fixture but consume the
        # multi-priv API surface; exercised separately.
        if "recipient_secret_hex" not in vector:
            continue
        result = ecies_sealed_poe_unwrap(
            envelope=_envelope_from_fixture(vector["envelope"]),
            ciphertext=bytes.fromhex(str(vector["ciphertext_hex"])),
            hashes=_hashes_from_fixture(vector["hashes"]),
            recipient_secret_key=bytes.fromhex(str(vector["recipient_secret_hex"])),
        )
        assert result.matched is False, vector["name"]
        assert result.reason == vector["expected_reason"], vector["name"]
    for vector in corpus["raise_vectors"]:
        if "recipient_secret_hex" not in vector or "recipient_secret_keys_hex" in vector:
            continue
        with pytest.raises(EciesSealedPoeError) as exc_info:
            ecies_sealed_poe_unwrap(
                envelope=_envelope_from_fixture(vector["envelope"]),
                ciphertext=bytes.fromhex(str(vector["ciphertext_hex"])),
                hashes=_hashes_from_fixture(vector["hashes"]),
                recipient_secret_key=bytes.fromhex(str(vector["recipient_secret_hex"])),
            )
        assert exc_info.value.code == vector["expected_error_code"], vector["name"]


def test_stream_layout_kats() -> None:
    corpus = _load("stream-layout.json")
    from cardanowall._crypto.stream import StreamTamperedError, stream_open, stream_seal

    payload_key = bytes.fromhex(corpus["payload_key_hex"])
    sealed: dict[str, bytes] = {}
    for vector in corpus["positive_vectors"]:
        plaintext = bytes.fromhex(vector["plaintext_hex"])
        ciphertext = stream_seal(payload_key, plaintext)
        assert ciphertext.hex() == vector["expected_ciphertext_hex"], vector["name"]
        assert stream_open(payload_key, ciphertext) == plaintext, vector["name"]
        sealed[vector["name"]] = ciphertext

    def apply_transforms(base: bytes, transforms: list[dict[str, Any]]) -> bytes:
        out = base
        for transform in transforms:
            kind = transform["kind"]
            if kind == "flip_byte":
                mutated = bytearray(out)
                mutated[int(transform["offset"])] ^= 0x01
                out = bytes(mutated)
            elif kind == "truncate_to":
                out = out[: int(transform["length"])]
            elif kind == "append_hex":
                out = out + bytes.fromhex(transform["bytes_hex"])
            elif kind == "remove":
                offset, length = int(transform["offset"]), int(transform["length"])
                out = out[:offset] + out[offset + length :]
            else:
                raise AssertionError(f"unknown transform {kind!r}")
        return out

    for vector in corpus["negative_vectors"]:
        mutated = apply_transforms(sealed[vector["base"]], vector["transforms"])
        with pytest.raises(StreamTamperedError):
            stream_open(payload_key, mutated)


# ---------------------------------------------------------------------------
# Self-generated construction behaviour.
# ---------------------------------------------------------------------------


def _make_priv(seed: int) -> bytes:
    return bytes((seed + i) & 0xFF for i in range(32))


def _unwrap_envelope(out: SealedPoeOutput, hashes: dict[str, bytes], priv: bytes) -> bytes:
    result = ecies_sealed_poe_unwrap(
        envelope=out.envelope,
        ciphertext=out.ciphertext,
        hashes=hashes,
        recipient_secret_key=priv,
    )
    if not result.matched or result.plaintext is None:
        raise AssertionError("no slot decrypted for recipient")
    return result.plaintext


def test_wrap_roundtrip_every_recipient() -> None:
    recipient_privs = [_make_priv(0x11), _make_priv(0x55), _make_priv(0x99)]
    recipient_publics = [x25519_public_key(p) for p in recipient_privs]
    plaintext = b"roundtrip - production path"
    hashes = _hashes_for(plaintext)
    out = ecies_sealed_poe_wrap(
        plaintext=plaintext, recipient_public_keys=recipient_publics, hashes=hashes
    )
    for priv in recipient_privs:
        assert _unwrap_envelope(out, hashes, priv) == plaintext


def test_wrap_shuffle_recipient_position_property() -> None:
    recipient_privs = [_make_priv(0x11), _make_priv(0x55), _make_priv(0x99)]
    recipient_publics = [x25519_public_key(p) for p in recipient_privs]
    plaintext = b"shuffle-by-recipient-position"
    hashes = _hashes_for(plaintext)
    orderings: set[str] = set()
    for _ in range(200):
        out = ecies_sealed_poe_wrap(
            plaintext=plaintext, recipient_public_keys=recipient_publics, hashes=hashes
        )
        # Recover each recipient's slot index via the trial-decrypt surface.
        positions: list[int] = []
        for priv in recipient_privs:
            trial = ecies_sealed_poe_trial_decrypt(
                envelope=out.envelope, hashes=hashes, recipient_secret_keys=[priv]
            )
            assert trial.kind == "match" and trial.slot_idx is not None
            positions.append(trial.slot_idx)
        orderings.add(",".join(str(p) for p in positions))
        if len(orderings) >= 4:
            break
    assert len(orderings) >= 2


def test_wrap_csprng_distinctness() -> None:
    priv = _make_priv(0xA0)
    pub = x25519_public_key(priv)
    plaintext = b"shuffle-property-csprng-distinctness"
    hashes = _hashes_for(plaintext)
    tuples: set[tuple[str, str]] = set()
    for _ in range(50):
        out = ecies_sealed_poe_wrap(plaintext=plaintext, recipient_public_keys=[pub], hashes=hashes)
        tuples.add((out.envelope.nonce.hex(), out.envelope.slots_mac.hex()))
    assert len(tuples) == 50


def test_wrap_supports_unbounded_recipient_count() -> None:
    """No fixed upper bound; producer SDK polices byte budget."""
    recipient_privs = [_make_priv(i * 7) for i in range(64)]
    recipient_publics = [x25519_public_key(p) for p in recipient_privs]
    plaintext = b"unbounded-recipient-count"
    hashes = _hashes_for(plaintext)
    out = ecies_sealed_poe_wrap(
        plaintext=plaintext, recipient_public_keys=recipient_publics, hashes=hashes
    )
    assert len(out.envelope.slots) == 64
    for idx in (0, 31, 63):
        assert _unwrap_envelope(out, hashes, recipient_privs[idx]) == plaintext


def test_wrap_input_validation_codes() -> None:
    priv = _make_priv(0x42)
    pub = x25519_public_key(priv)
    plaintext = b"wrap validation"
    hashes = _hashes_for(plaintext)

    cases: list[tuple[dict[str, Any], str]] = [
        ({"recipient_public_keys": []}, "ENC_SLOTS_EMPTY"),
        ({"recipient_public_keys": [pub[:-1]]}, "KEM_EPK_LENGTH_MISMATCH"),
        ({"recipient_public_keys": [pub], "kem": "kyber768"}, "UNSUPPORTED_KEM_ALG"),
        ({"recipient_public_keys": [pub], "cek": b"\x01" * 31}, "INVALID_CEK_LENGTH"),
        ({"recipient_public_keys": [pub], "nonce": b"\x01" * 23}, "NONCE_LENGTH_MISMATCH"),
        (
            {"recipient_public_keys": [pub], "ephemeral_secrets": [b"\x01" * 31]},
            "INVALID_EPHEMERAL_SECRET_LENGTH",
        ),
        (
            {"recipient_public_keys": [pub], "ephemeral_secrets": [b"\x01" * 32, b"\x02" * 32]},
            "EPHEMERAL_SECRETS_COUNT_MISMATCH",
        ),
        (
            {"recipient_public_keys": [pub], "eseeds": [b"\x01" * 64]},
            "EPHEMERAL_SECRETS_COUNT_MISMATCH",
        ),
        ({"recipient_public_keys": [pub], "hashes_override": {}}, "ENC_REQUIRES_CONTENT_HASH"),
    ]
    for kwargs, expected_code in cases:
        hashes_arg = kwargs.pop("hashes_override", hashes)
        with pytest.raises(EciesSealedPoeError) as exc:
            ecies_sealed_poe_wrap(plaintext=plaintext, hashes=hashes_arg, **kwargs)
        assert exc.value.code == expected_code


# ---------------------------------------------------------------------------
# Per-slot MAC fold semantics.
# ---------------------------------------------------------------------------


def test_shadow_slot_before_honest_decrypts_under_honest_cek() -> None:
    from cardanowall._crypto.sealed_poe import (
        _compute_slots_hash,
        _slots_mac_from_hash,
        _slots_payload_key,
        _wrap_slot_x25519,
        item_hashes_hash,
    )
    from cardanowall._crypto.stream import stream_seal

    priv = _make_priv(0xD0)
    pub = x25519_public_key(priv)
    honest_cek = bytes([0xAA] * 32)
    attacker_cek = bytes([0xBB] * 32)
    nonce = bytes((0xE0 + i) & 0xFF for i in range(24))
    plaintext = b"the honest slot wins"
    hashes = _hashes_for(plaintext)
    hashes_hash = item_hashes_hash(hashes)

    forged = _wrap_slot_x25519(nonce, pub, bytes([0x01] * 32), attacker_cek, 0)
    honest = _wrap_slot_x25519(nonce, pub, bytes([0x02] * 32), honest_cek, 1)
    slots = (forged, honest)
    slots_hash = _compute_slots_hash(nonce, slots, "x25519", hashes_hash)
    slots_mac = _slots_mac_from_hash(honest_cek, slots_hash)
    ciphertext = stream_seal(_slots_payload_key(honest_cek, nonce), plaintext)
    envelope = SealedEnvelope(
        scheme=1,
        aead="chacha20-poly1305-stream64k",
        kem="x25519",
        nonce=nonce,
        slots=slots,
        slots_mac=slots_mac,
    )

    res = ecies_sealed_poe_unwrap(
        envelope=envelope, ciphertext=ciphertext, hashes=hashes, recipient_secret_key=priv
    )
    assert res.matched is True
    assert res.plaintext == plaintext

    trial = ecies_sealed_poe_trial_decrypt(
        envelope=envelope, hashes=hashes, recipient_secret_keys=[priv]
    )
    assert trial.kind == "match"
    assert trial.slot_idx == 1
    assert trial.cek is not None and compare_ct(trial.cek, honest_cek)


def test_cek_conflict_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    # A genuine CEK conflict — two slots both reproducing slots_mac with
    # DIFFERENT CEKs — is the multi-key commitment collision the slot-set MAC
    # assumption rules out, so it cannot be constructed from real bytes. Force
    # the condition by stubbing the MAC comparison to accept everything and
    # assert the defence-in-depth conflict scan fails closed.
    import cardanowall._crypto.sealed_poe as sealed_poe_module

    priv = _make_priv(0xD4)
    pub = x25519_public_key(priv)
    nonce = bytes((0xE4 + i) & 0xFF for i in range(24))
    plaintext = b"conflict probe"
    hashes = _hashes_for(plaintext)
    hashes_hash = sealed_poe_module.item_hashes_hash(hashes)

    slot_a = sealed_poe_module._wrap_slot_x25519(nonce, pub, bytes([0x03] * 32), b"\xaa" * 32, 0)
    slot_b = sealed_poe_module._wrap_slot_x25519(nonce, pub, bytes([0x04] * 32), b"\xbb" * 32, 1)
    slots = (slot_a, slot_b)
    slots_hash = sealed_poe_module._compute_slots_hash(nonce, slots, "x25519", hashes_hash)
    slots_mac = sealed_poe_module._slots_mac_from_hash(b"\xaa" * 32, slots_hash)
    envelope = SealedEnvelope(
        scheme=1,
        aead="chacha20-poly1305-stream64k",
        kem="x25519",
        nonce=nonce,
        slots=slots,
        slots_mac=slots_mac,
    )

    monkeypatch.setattr(
        sealed_poe_module, "_slots_mac_from_hash", lambda cek, slots_hash: slots_mac
    )

    res = ecies_sealed_poe_unwrap(
        envelope=envelope, ciphertext=b"\x00" * 16, hashes=hashes, recipient_secret_key=priv
    )
    assert res.matched is False
    assert res.reason == UNWRAP_REASON_TAMPERED_HEADER

    trial = ecies_sealed_poe_trial_decrypt(
        envelope=envelope, hashes=hashes, recipient_secret_keys=[priv]
    )
    assert trial.kind == "no_match"


def test_tampered_slots_mac_with_open_slot_is_tampered_header() -> None:
    priv = _make_priv(0x21)
    plaintext = b"mac binding"
    hashes = _hashes_for(plaintext)
    out = ecies_sealed_poe_wrap(
        plaintext=plaintext, recipient_public_keys=[x25519_public_key(priv)], hashes=hashes
    )
    tampered = SealedEnvelope(
        scheme=1,
        aead=out.envelope.aead,
        kem=out.envelope.kem,
        nonce=out.envelope.nonce,
        slots=out.envelope.slots,
        slots_mac=bytes([out.envelope.slots_mac[0] ^ 0x01]) + out.envelope.slots_mac[1:],
    )
    res = ecies_sealed_poe_unwrap(
        envelope=tampered, ciphertext=out.ciphertext, hashes=hashes, recipient_secret_key=priv
    )
    assert res.matched is False
    assert res.reason == UNWRAP_REASON_TAMPERED_HEADER


def test_hashes_splice_is_rejected_at_the_mac() -> None:
    priv = _make_priv(0x23)
    plaintext = b"hashes splice"
    hashes = _hashes_for(plaintext)
    out = ecies_sealed_poe_wrap(
        plaintext=plaintext, recipient_public_keys=[x25519_public_key(priv)], hashes=hashes
    )
    res = ecies_sealed_poe_unwrap(
        envelope=out.envelope,
        ciphertext=out.ciphertext,
        hashes=_hashes_for(b"a different claim"),
        recipient_secret_key=priv,
    )
    assert res.matched is False
    assert res.reason == UNWRAP_REASON_TAMPERED_HEADER


def test_stream_tamper_is_tampered_ciphertext() -> None:
    priv = _make_priv(0x25)
    plaintext = b"stream tamper"
    hashes = _hashes_for(plaintext)
    out = ecies_sealed_poe_wrap(
        plaintext=plaintext, recipient_public_keys=[x25519_public_key(priv)], hashes=hashes
    )
    flipped = bytes([out.ciphertext[0] ^ 0x01]) + out.ciphertext[1:]
    res = ecies_sealed_poe_unwrap(
        envelope=out.envelope, ciphertext=flipped, hashes=hashes, recipient_secret_key=priv
    )
    assert res.matched is False
    assert res.reason == UNWRAP_REASON_TAMPERED_CIPHERTEXT


def test_wrong_recipient_surfaces_wrong_recipient_key() -> None:
    target = _make_priv(0x80)
    stranger = _make_priv(0x81)
    plaintext = b"z"
    hashes = _hashes_for(plaintext)
    out = ecies_sealed_poe_wrap(
        plaintext=plaintext, recipient_public_keys=[x25519_public_key(target)], hashes=hashes
    )
    res = ecies_sealed_poe_unwrap(
        envelope=out.envelope,
        ciphertext=out.ciphertext,
        hashes=hashes,
        recipient_secret_key=stranger,
    )
    assert res.matched is False
    assert res.reason == UNWRAP_REASON_WRONG_RECIPIENT_KEY


# ---------------------------------------------------------------------------
# Multi-priv form (self-generated).
# ---------------------------------------------------------------------------


def _multi_setup(n: int, holder_idx: int) -> tuple[SealedPoeOutput, dict[str, bytes], list[bytes]]:
    privs = [_make_priv(0x10 + i * 3) for i in range(n)]
    publics = [x25519_public_key(p) for p in privs]
    plaintext = b"multi-priv"
    hashes = _hashes_for(plaintext)
    out = ecies_sealed_poe_wrap(
        plaintext=plaintext,
        recipient_public_keys=[publics[holder_idx]],
        hashes=hashes,
    )
    return out, hashes, privs


def test_unwrap_multipriv_current_match_short_circuits_outer_loop() -> None:
    out, hashes, privs = _multi_setup(4, 0)
    slots_attempted: list[int] = []
    privs_attempted: list[int] = []
    res = ecies_sealed_poe_unwrap(
        envelope=out.envelope,
        ciphertext=out.ciphertext,
        hashes=hashes,
        recipient_secret_keys=privs,
        _slots_attempted_out=slots_attempted,
        _privs_attempted_out=privs_attempted,
    )
    assert res.matched is True
    assert privs_attempted[0] == 1  # first priv matched; outer loop stopped
    assert slots_attempted == [1]


def test_unwrap_multipriv_archived_match_walks_earlier_privs() -> None:
    out, hashes, privs = _multi_setup(4, 2)
    slots_attempted: list[int] = []
    privs_attempted: list[int] = []
    res = ecies_sealed_poe_unwrap(
        envelope=out.envelope,
        ciphertext=out.ciphertext,
        hashes=hashes,
        recipient_secret_keys=privs,
        _slots_attempted_out=slots_attempted,
        _privs_attempted_out=privs_attempted,
    )
    assert res.matched is True
    assert privs_attempted[0] == 3
    assert slots_attempted == [1, 1, 1]  # inner loop constant per priv


def test_unwrap_multipriv_no_match_walks_every_priv() -> None:
    out, hashes, _ = _multi_setup(4, 0)
    strangers = [_make_priv(0xC0 + i) for i in range(4)]
    privs_attempted: list[int] = []
    res = ecies_sealed_poe_unwrap(
        envelope=out.envelope,
        ciphertext=out.ciphertext,
        hashes=hashes,
        recipient_secret_keys=strangers,
        _privs_attempted_out=privs_attempted,
    )
    assert res.matched is False
    assert res.reason == UNWRAP_REASON_WRONG_RECIPIENT_KEY
    assert privs_attempted[0] == 4


def test_unwrap_multipriv_input_validation() -> None:
    out, hashes, privs = _multi_setup(2, 0)
    with pytest.raises(EciesSealedPoeError) as exc:
        ecies_sealed_poe_unwrap(
            envelope=out.envelope,
            ciphertext=out.ciphertext,
            hashes=hashes,
            recipient_secret_keys=[],
        )
    assert exc.value.code == "INVALID_RECIPIENT_KEY"
    with pytest.raises(EciesSealedPoeError) as exc:
        ecies_sealed_poe_unwrap(
            envelope=out.envelope,
            ciphertext=out.ciphertext,
            hashes=hashes,
            recipient_secret_key=privs[0],
            recipient_secret_keys=privs,
        )
    assert exc.value.code == "INVALID_RECIPIENT_KEY"
    with pytest.raises(EciesSealedPoeError) as exc:
        ecies_sealed_poe_unwrap(envelope=out.envelope, ciphertext=out.ciphertext, hashes=hashes)
    assert exc.value.code == "INVALID_RECIPIENT_KEY"
    with pytest.raises(EciesSealedPoeError) as exc:
        ecies_sealed_poe_unwrap(
            envelope=out.envelope,
            ciphertext=out.ciphertext,
            hashes=hashes,
            recipient_secret_keys=[privs[0], b"\x11" * 31],
        )
    assert exc.value.code == "INVALID_RECIPIENT_KEY"


# ---------------------------------------------------------------------------
# Constant-time-across-slots invariant (always on; no public opt-out).
# ---------------------------------------------------------------------------


def test_unwrap_enters_all_slots_regardless_of_match_position() -> None:
    n = 8
    recipient_privs = [_make_priv(0x10 + i * 3) for i in range(n)]
    recipient_publics = [x25519_public_key(p) for p in recipient_privs]
    plaintext = b"constant-time-N enters all slots"
    hashes = _hashes_for(plaintext)
    out = ecies_sealed_poe_wrap(
        plaintext=plaintext, recipient_public_keys=recipient_publics, hashes=hashes
    )
    for idx in (0, n // 2, n - 1):
        slots_attempted: list[int] = []
        result = ecies_sealed_poe_unwrap(
            envelope=out.envelope,
            ciphertext=out.ciphertext,
            hashes=hashes,
            recipient_secret_key=recipient_privs[idx],
            _slots_attempted_out=slots_attempted,
        )
        assert result.matched is True
        assert slots_attempted[0] == n


def test_unwrap_has_no_variable_time_opt_out() -> None:
    import inspect

    signature = inspect.signature(ecies_sealed_poe_unwrap)
    assert "constant_time_n" not in signature.parameters
    assert "constant_time_n" not in inspect.signature(ecies_sealed_poe_trial_decrypt).parameters


# ---------------------------------------------------------------------------
# Hybrid (X-Wing) behaviour.
# ---------------------------------------------------------------------------


def test_hybrid_wrap_unwrap_roundtrip() -> None:
    pubs_seeds = [xwing_keygen(bytes([0x31 + i]) * 32) for i in range(3)]
    plaintext = b"multi-recipient hybrid"
    hashes = _hashes_for(plaintext)
    out = ecies_sealed_poe_wrap(
        plaintext=plaintext,
        recipient_public_keys=[p for p, _ in pubs_seeds],
        hashes=hashes,
        kem="mlkem768x25519",
    )
    assert all(s.epk is None and s.kem_ct is not None for s in out.envelope.slots)
    for _, seed in pubs_seeds:
        res = ecies_sealed_poe_unwrap(
            envelope=out.envelope,
            ciphertext=out.ciphertext,
            hashes=hashes,
            recipient_secret_key=seed,
        )
        assert res.matched is True
        assert res.plaintext == plaintext


def test_hybrid_wrong_recipient() -> None:
    pub, _seed = xwing_keygen(b"\x41" * 32)
    plaintext = b"hybrid stranger"
    hashes = _hashes_for(plaintext)
    out = ecies_sealed_poe_wrap(
        plaintext=plaintext, recipient_public_keys=[pub], hashes=hashes, kem="mlkem768x25519"
    )
    _stranger_pub, stranger_seed = xwing_keygen(b"\x99" * 32)
    res = ecies_sealed_poe_unwrap(
        envelope=out.envelope,
        ciphertext=out.ciphertext,
        hashes=hashes,
        recipient_secret_key=stranger_seed,
    )
    assert res.matched is False
    assert res.reason == UNWRAP_REASON_WRONG_RECIPIENT_KEY


def test_hybrid_kem_ct_length_mismatch() -> None:
    pub, seed = xwing_keygen(b"\x43" * 32)
    plaintext = b"hybrid lengths"
    hashes = _hashes_for(plaintext)
    out = ecies_sealed_poe_wrap(
        plaintext=plaintext, recipient_public_keys=[pub], hashes=hashes, kem="mlkem768x25519"
    )
    good_slot = out.envelope.slots[0]
    assert good_slot.kem_ct is not None
    for bad_kem_ct in (good_slot.kem_ct[:-1], good_slot.kem_ct + b"\x00"):
        tampered = SealedEnvelope(
            scheme=1,
            aead=out.envelope.aead,
            kem=out.envelope.kem,
            nonce=out.envelope.nonce,
            slots=(SealedSlot(kem_ct=bad_kem_ct, wrap=good_slot.wrap),),
            slots_mac=out.envelope.slots_mac,
        )
        with pytest.raises(EciesSealedPoeError) as exc:
            ecies_sealed_poe_unwrap(
                envelope=tampered,
                ciphertext=out.ciphertext,
                hashes=hashes,
                recipient_secret_key=seed,
            )
        assert exc.value.code == "KEM_CT_LENGTH_MISMATCH"


def test_hybrid_slots_mac_covers_kem_ct() -> None:
    """slots_mac MUST authenticate the hybrid kem_ct: recipient A's slot opens
    cleanly, the flip lands on the untouched sibling slot, so a candidate CEK
    is recovered but the recomputed MAC disagrees → TAMPERED_HEADER."""
    pub_a, seed_a = xwing_keygen(b"\x11" * 32)
    pub_b, _seed_b = xwing_keygen(b"\x22" * 32)
    plaintext = b"hybrid-slots-mac-kem-ct-coverage"
    hashes = _hashes_for(plaintext)
    out = ecies_sealed_poe_wrap(
        plaintext=plaintext,
        recipient_public_keys=[pub_a, pub_b],
        hashes=hashes,
        kem="mlkem768x25519",
        cek=b"\xab" * 32,
        nonce=b"\xcd" * 24,
        eseeds=[b"\xe1" * 64, b"\xe2" * 64],
        skip_shuffle=True,
    )
    clean = ecies_sealed_poe_unwrap(
        envelope=out.envelope, ciphertext=out.ciphertext, hashes=hashes, recipient_secret_key=seed_a
    )
    assert clean.matched is True

    slot1 = out.envelope.slots[1]
    assert slot1.kem_ct is not None
    tampered_kem_ct = bytes([slot1.kem_ct[0] ^ 0x01]) + slot1.kem_ct[1:]
    tampered_env = SealedEnvelope(
        scheme=out.envelope.scheme,
        aead=out.envelope.aead,
        kem=out.envelope.kem,
        nonce=out.envelope.nonce,
        slots=(out.envelope.slots[0], SealedSlot(kem_ct=tampered_kem_ct, wrap=slot1.wrap)),
        slots_mac=out.envelope.slots_mac,
    )
    res = ecies_sealed_poe_unwrap(
        envelope=tampered_env, ciphertext=out.ciphertext, hashes=hashes, recipient_secret_key=seed_a
    )
    assert res.matched is False
    assert res.reason == UNWRAP_REASON_TAMPERED_HEADER


def test_hybrid_garbage_kem_ct_is_not_mine() -> None:
    """A 1120-byte garbage kem_ct passes the length checks; ML-KEM implicit
    rejection yields a pseudorandom shared secret, the wrap fails, and the
    envelope ends in the single generic failure — never a distinct
    decapsulation error."""
    pub, seed = xwing_keygen(b"\x47" * 32)
    plaintext = b"garbage kem_ct"
    hashes = _hashes_for(plaintext)
    out = ecies_sealed_poe_wrap(
        plaintext=plaintext, recipient_public_keys=[pub], hashes=hashes, kem="mlkem768x25519"
    )
    garbage = bytes((i * 7 + 3) & 0xFF for i in range(1120))
    tampered = SealedEnvelope(
        scheme=1,
        aead=out.envelope.aead,
        kem=out.envelope.kem,
        nonce=out.envelope.nonce,
        slots=(SealedSlot(kem_ct=garbage, wrap=out.envelope.slots[0].wrap),),
        slots_mac=out.envelope.slots_mac,
    )
    res = ecies_sealed_poe_unwrap(
        envelope=tampered, ciphertext=out.ciphertext, hashes=hashes, recipient_secret_key=seed
    )
    assert res.matched is False
    assert res.reason == UNWRAP_REASON_WRONG_RECIPIENT_KEY


def test_xwing_invalid_recipient_public_key_rejected_at_seal() -> None:
    """A 1216-byte recipient key whose ML-KEM ek fails the FIPS 203 modulus
    check MUST be rejected before any slot is produced."""
    valid_pub, _seed = xwing_keygen(b"\x4d" * 32)
    invalid_pub = b"\xff\xff\xff" + valid_pub[3:]
    plaintext = b"never sealed"
    with pytest.raises(EciesSealedPoeError) as exc:
        ecies_sealed_poe_wrap(
            plaintext=plaintext,
            recipient_public_keys=[invalid_pub],
            hashes=_hashes_for(plaintext),
            kem="mlkem768x25519",
        )
    assert exc.value.code == "INVALID_RECIPIENT_KEY"


# ---------------------------------------------------------------------------
# Wire-shape pre-checks.
# ---------------------------------------------------------------------------


def test_partitioning_oracle_pre_checks_order() -> None:
    """Length/shape pre-checks run BEFORE any KEM/AEAD primitive."""
    priv = _make_priv(0xAA)
    valid_epk = x25519_public_key(_make_priv(0xBB))
    valid_wrap = b"\xcc" * 48
    valid_nonce = b"\x00" * 24
    valid_mac = b"\xdd" * 32
    valid_ct = b"\xee" * 16
    hashes = _hashes_for(b"probe")

    def env(**overrides: Any) -> SealedEnvelope:
        fields: dict[str, Any] = {
            "scheme": 1,
            "aead": "chacha20-poly1305-stream64k",
            "kem": "x25519",
            "nonce": valid_nonce,
            "slots": (SealedSlot(epk=valid_epk, wrap=valid_wrap),),
            "slots_mac": valid_mac,
        }
        fields.update(overrides)
        return SealedEnvelope(**fields)

    cases: list[tuple[SealedEnvelope, str]] = [
        (env(scheme=2), "UNSUPPORTED_ENVELOPE_SCHEME"),
        (env(aead="xchacha20-poly1305"), "UNSUPPORTED_AEAD_ALG"),
        (env(kem="rsa"), "UNSUPPORTED_KEM_ALG"),
        (env(slots=()), "ENC_SLOTS_EMPTY"),
        (env(nonce=b"\x00" * 12), "NONCE_LENGTH_MISMATCH"),
        (env(slots_mac=b"\xdd" * 16), "ENC_SLOTS_MAC_INVALID_LENGTH"),
        (env(slots=(SealedSlot(epk=b"\xbb" * 16, wrap=valid_wrap),)), "KEM_EPK_LENGTH_MISMATCH"),
        (env(slots=(SealedSlot(epk=valid_epk, wrap=b"\xcc" * 32),)), "WRAP_LENGTH_MISMATCH"),
        (
            env(
                slots=(
                    SealedSlot(epk=valid_epk, wrap=valid_wrap),
                    SealedSlot(epk=valid_epk, wrap=valid_wrap),
                )
            ),
            "ENC_SLOTS_DUPLICATE_KEM_MATERIAL",
        ),
    ]
    for envelope, expected_code in cases:
        with pytest.raises(EciesSealedPoeError) as exc:
            ecies_sealed_poe_unwrap(
                envelope=envelope, ciphertext=valid_ct, hashes=hashes, recipient_secret_key=priv
            )
        assert exc.value.code == expected_code


def test_wrap_unwrap_byte_field_names_match_spec() -> None:
    """Wire field names: scheme, aead, kem, nonce, slots, slots_mac."""
    priv = _make_priv(0x42)
    pub = x25519_public_key(priv)
    plaintext = b"x"
    out = ecies_sealed_poe_wrap(
        plaintext=plaintext, recipient_public_keys=[pub], hashes=_hashes_for(plaintext)
    )
    env = out.envelope
    assert hasattr(env, "scheme") and env.scheme == 1
    assert hasattr(env, "aead") and env.aead == "chacha20-poly1305-stream64k"
    assert hasattr(env, "kem") and env.kem == "x25519"
    assert hasattr(env, "nonce") and len(env.nonce) == 24
    assert hasattr(env, "slots") and len(env.slots) == 1
    assert hasattr(env, "slots_mac") and len(env.slots_mac) == 32
    slot = env.slots[0]
    assert slot.epk is not None
    assert hasattr(slot, "epk") and len(slot.epk) == 32
    assert hasattr(slot, "wrap") and len(slot.wrap) == 48
    assert not hasattr(slot, "kem")


def test_unwrap_reason_constants_match_strings() -> None:
    assert UNWRAP_REASON_WRONG_RECIPIENT_KEY == "WRONG_RECIPIENT_KEY"
    assert UNWRAP_REASON_TAMPERED_HEADER == "TAMPERED_HEADER"
    assert UNWRAP_REASON_TAMPERED_CIPHERTEXT == "TAMPERED_CIPHERTEXT"


# ---------------------------------------------------------------------------
# Multi-priv fixture KATs (pinned cross-SDK vectors; loop-count parity).
# ---------------------------------------------------------------------------


def _multipriv_inputs(
    filename: str,
) -> tuple[SealedEnvelope, bytes, dict[str, bytes], list[bytes], dict[str, Any]]:
    v = _load(filename)["vector"]
    return (
        _envelope_from_fixture(v["envelope"]),
        bytes.fromhex(str(v["ciphertext_hex"])),
        _hashes_from_fixture(v["hashes"]),
        [bytes.fromhex(h) for h in v["recipient_privs_hex"]],
        v,
    )


@pytest.mark.parametrize(
    "filename",
    [
        "unwrap-multipriv-current-match.json",
        "unwrap-multipriv-archived-match.json",
    ],
)
def test_unwrap_multipriv_match_kats(filename: str) -> None:
    envelope, ciphertext, hashes, privs, v = _multipriv_inputs(filename)
    slots_attempted: list[int] = []
    privs_attempted: list[int] = []
    result = ecies_sealed_poe_unwrap(
        envelope=envelope,
        ciphertext=ciphertext,
        hashes=hashes,
        recipient_secret_keys=privs,
        _slots_attempted_out=slots_attempted,
        _privs_attempted_out=privs_attempted,
    )
    assert result.matched is True
    assert result.plaintext is not None
    assert result.plaintext.hex() == v["expected_plaintext_hex"]
    assert privs_attempted[0] == v["expected_outer_loop_count"]
    expected_inner = v["expected_inner_loop_count_per_priv"]
    assert slots_attempted == [expected_inner] * v["expected_outer_loop_count"]


def test_unwrap_multipriv_no_match_kat() -> None:
    envelope, ciphertext, hashes, privs, v = _multipriv_inputs("unwrap-multipriv-no-match.json")
    slots_attempted: list[int] = []
    privs_attempted: list[int] = []
    result = ecies_sealed_poe_unwrap(
        envelope=envelope,
        ciphertext=ciphertext,
        hashes=hashes,
        recipient_secret_keys=privs,
        _slots_attempted_out=slots_attempted,
        _privs_attempted_out=privs_attempted,
    )
    assert result.matched is False
    assert result.reason == UNWRAP_REASON_WRONG_RECIPIENT_KEY
    assert privs_attempted[0] == v["expected_outer_loop_count"]
    expected_inner = v["expected_inner_loop_count_per_priv"]
    assert slots_attempted == [expected_inner] * v["expected_outer_loop_count"]


_MULTIPRIV_LOOP_MATRIX: list[tuple[str, int, list[int], bool]] = [
    ("unwrap-multipriv-ac9-priv0-slot0.json", 1, [32], True),
    ("unwrap-multipriv-ac9-priv0-slot31.json", 1, [32], True),
    ("unwrap-multipriv-ac9-priv4-slot0.json", 5, [32, 32, 32, 32, 32], True),
    ("unwrap-multipriv-ac9-priv4-slot31.json", 5, [32, 32, 32, 32, 32], True),
    ("unwrap-multipriv-ac9-no-match.json", 5, [32, 32, 32, 32, 32], False),
    ("unwrap-multipriv-n32-k10-worst-case.json", 10, [32] * 10, True),
]


@pytest.mark.parametrize(
    "filename, expected_outer, expected_per_priv, matched", _MULTIPRIV_LOOP_MATRIX
)
def test_unwrap_multipriv_loop_count_matrix_kats(
    filename: str,
    expected_outer: int,
    expected_per_priv: list[int],
    matched: bool,
) -> None:
    envelope, ciphertext, hashes, privs, v = _multipriv_inputs(filename)
    slots_attempted: list[int] = []
    privs_attempted: list[int] = []
    result = ecies_sealed_poe_unwrap(
        envelope=envelope,
        ciphertext=ciphertext,
        hashes=hashes,
        recipient_secret_keys=privs,
        _slots_attempted_out=slots_attempted,
        _privs_attempted_out=privs_attempted,
    )
    if matched:
        assert result.matched is True
        assert result.plaintext is not None
        assert result.plaintext.hex() == v["expected_plaintext_hex"]
    else:
        assert result.matched is False
        assert result.reason == UNWRAP_REASON_WRONG_RECIPIENT_KEY
    assert privs_attempted[0] == expected_outer
    assert slots_attempted == expected_per_priv


def test_unwrap_multipriv_mac_fail_kat() -> None:
    corpus = _load("unwrap-negative.json")
    vector = next(v for v in corpus["matched_false_vectors"] if v["name"] == "multipriv-mac-fail")
    result = ecies_sealed_poe_unwrap(
        envelope=_envelope_from_fixture(vector["envelope"]),
        ciphertext=bytes.fromhex(str(vector["ciphertext_hex"])),
        hashes=_hashes_from_fixture(vector["hashes"]),
        recipient_secret_keys=[bytes.fromhex(h) for h in vector["recipient_secret_keys_hex"]],
    )
    assert result.matched is False
    assert result.reason == UNWRAP_REASON_TAMPERED_HEADER
