from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

import pytest

from cardanowall._crypto.aead import chacha20_poly1305_decrypt
from cardanowall._crypto.kdf import hkdf_sha256
from cardanowall._crypto.kem import x25519_ecdh, x25519_public_key
from cardanowall._crypto.mlkem768x25519 import xwing_keygen
from cardanowall._crypto.sealed_poe import (
    CARDANO_POE_HKDF_INFO_KEK,
    UNWRAP_REASON_TAMPERED_CIPHERTEXT,
    UNWRAP_REASON_TAMPERED_HEADER,
    UNWRAP_REASON_WRONG_RECIPIENT_KEY,
    EciesSealedPoeError,
    SealedEnvelope,
    SealedPoeOutput,
    SealedSlot,
    ecies_sealed_poe_unwrap,
    ecies_sealed_poe_wrap,
)

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "sealed-poe"


def _load_positive(filename: str) -> dict[str, Any]:
    return cast(dict[str, Any], json.loads((FIXTURES_DIR / filename).read_text()))


def _load_negative(filename: str) -> list[dict[str, Any]]:
    return cast(
        list[dict[str, Any]],
        json.loads((FIXTURES_DIR / filename).read_text())["vectors"],
    )


def _check_positive(filename: str) -> None:
    corpus = _load_positive(filename)
    vector: dict[str, Any] = corpus["vector"]
    recipient_publics = [bytes.fromhex(h) for h in vector["recipient_publics_hex"]]
    ephemeral_secrets = [bytes.fromhex(h) for h in vector["ephemeral_secrets_hex"]]
    cek = bytes.fromhex(str(vector["cek_hex"]))
    nonce_hex = vector.get("nonce_hex", vector.get("iv_hex"))
    nonce = bytes.fromhex(str(nonce_hex))
    plaintext = bytes.fromhex(str(vector["plaintext_hex"]))

    out = ecies_sealed_poe_wrap(
        plaintext=plaintext,
        recipient_public_keys=recipient_publics,
        cek=cek,
        nonce=nonce,
        ephemeral_secrets=ephemeral_secrets,
        skip_shuffle=True,
    )

    assert out.envelope.scheme == 1
    assert out.envelope.aead == "xchacha20-poly1305"
    assert out.envelope.kem == "x25519"
    assert out.envelope.nonce.hex() == nonce_hex
    expected_slots = vector["expected_slots"]
    assert len(out.envelope.slots) == len(expected_slots)
    for i, slot in enumerate(out.envelope.slots):
        expected_epk = expected_slots[i].get("epk_hex", expected_slots[i].get("eph_hex"))
        # Classical x25519 slots always carry an ephemeral public key (epk);
        # only the hybrid mlkem768x25519 path leaves it None in favour of kem_ct.
        assert slot.epk is not None
        assert slot.epk.hex() == expected_epk
        assert slot.wrap.hex() == expected_slots[i]["wrap_hex"]
    expected_mac = vector.get("expected_slots_mac_hex", vector.get("expected_hdr_mac_hex"))
    assert out.envelope.slots_mac.hex() == expected_mac
    assert out.ciphertext.hex() == vector["expected_ciphertext_hex"]

    epk_set = {s.epk for s in out.envelope.slots}
    wrap_set = {s.wrap for s in out.envelope.slots}
    assert len(epk_set) == len(out.envelope.slots)
    assert len(wrap_set) == len(out.envelope.slots)


def test_wrap_n1_empty_b1() -> None:
    _check_positive("wrap-n1-empty.json")


def test_wrap_n3_b2() -> None:
    _check_positive("wrap-n3.json")


def test_wrap_n32() -> None:
    _check_positive("wrap-n32.json")


def test_wrap_negative_cases() -> None:
    for vector in _load_negative("wrap-negative.json"):
        # The old 32-recipient cap was removed; only the lower bound stays.
        # The "n33" fixture case used to raise ENC_RECIPIENTS_OUT_OF_RANGE
        # and is now a legitimate input.
        if vector["name"] == "n33":
            continue
        recipient_publics = [bytes.fromhex(h) for h in vector["recipient_publics_hex"]]
        ephemeral_secrets = (
            [bytes.fromhex(h) for h in vector["ephemeral_secrets_hex"]]
            if "ephemeral_secrets_hex" in vector
            else None
        )
        cek = bytes.fromhex(str(vector["cek_hex"])) if "cek_hex" in vector else None
        nonce_hex = vector.get("nonce_hex", vector.get("iv_hex"))
        nonce = bytes.fromhex(str(nonce_hex)) if nonce_hex is not None else None
        plaintext = bytes.fromhex(str(vector["plaintext_hex"]))
        with pytest.raises(EciesSealedPoeError) as exc_info:
            ecies_sealed_poe_wrap(
                plaintext=plaintext,
                recipient_public_keys=recipient_publics,
                cek=cek,
                nonce=nonce,
                ephemeral_secrets=ephemeral_secrets,
                skip_shuffle=True,
            )
        expected_code = vector["expected_error_code"]
        # Error-code renames between the legacy and current wire formats.
        if expected_code == "IV_LENGTH_MISMATCH":
            expected_code = "NONCE_LENGTH_MISMATCH"
        if expected_code == "ENC_RECIPIENTS_OUT_OF_RANGE":
            expected_code = "ENC_SLOTS_EMPTY"
        if expected_code == "KEM_EPH_LENGTH_MISMATCH":
            expected_code = "KEM_EPK_LENGTH_MISMATCH"
        assert exc_info.value.code == expected_code, vector["name"]


def _trial_unwrap(slot: SealedSlot, recipient_priv: bytes) -> bytes | None:
    # This trial helper only runs against classical x25519 slots, where epk is
    # always present (the hybrid path uses kem_ct and a different unwrap routine).
    assert slot.epk is not None
    shared = x25519_ecdh(recipient_priv, slot.epk)
    recipient_pub = x25519_public_key(recipient_priv)
    kek = hkdf_sha256(
        ikm=shared,
        salt=slot.epk + recipient_pub,
        info=CARDANO_POE_HKDF_INFO_KEK,
        length=32,
    )
    try:
        return chacha20_poly1305_decrypt(kek, b"\x00" * 12, CARDANO_POE_HKDF_INFO_KEK, slot.wrap)
    except Exception:
        return None


def _unwrap_envelope(out: SealedPoeOutput, recipient_priv: bytes) -> bytes:
    result = ecies_sealed_poe_unwrap(
        envelope=out.envelope,
        ciphertext=out.ciphertext,
        recipient_secret_key=recipient_priv,
    )
    if not result.matched or result.plaintext is None:
        raise AssertionError("no slot decrypted for recipient")
    return result.plaintext


def _recipient_positions(out: SealedPoeOutput, recipient_privs: list[bytes]) -> list[int]:
    positions = [-1] * len(recipient_privs)
    for slot_idx, slot in enumerate(out.envelope.slots):
        for r, priv in enumerate(recipient_privs):
            if positions[r] != -1:
                continue
            if _trial_unwrap(slot, priv) is not None:
                positions[r] = slot_idx
                break
    return positions


def _make_priv(seed: int) -> bytes:
    return bytes((seed + i) & 0xFF for i in range(32))


def test_wrap_roundtrip_every_recipient() -> None:
    recipient_privs = [_make_priv(0x11), _make_priv(0x55), _make_priv(0x99)]
    recipient_publics = [x25519_public_key(p) for p in recipient_privs]
    plaintext = b"AC5 roundtrip - production path"
    out = ecies_sealed_poe_wrap(plaintext=plaintext, recipient_public_keys=recipient_publics)
    for priv in recipient_privs:
        assert _unwrap_envelope(out, priv) == plaintext


def test_wrap_shuffle_recipient_position_property() -> None:
    recipient_privs = [_make_priv(0x11), _make_priv(0x55), _make_priv(0x99)]
    recipient_publics = [x25519_public_key(p) for p in recipient_privs]
    plaintext = b"shuffle-by-recipient-position"
    orderings: set[str] = set()
    for _ in range(200):
        out = ecies_sealed_poe_wrap(
            plaintext=plaintext,
            recipient_public_keys=recipient_publics,
        )
        positions = _recipient_positions(out, recipient_privs)
        orderings.add(",".join(str(p) for p in positions))
        if len(orderings) >= 4:
            break
    assert len(orderings) >= 2


def test_wrap_csprng_distinctness() -> None:
    priv = _make_priv(0xA0)
    pub = x25519_public_key(priv)
    plaintext = b"shuffle-property-csprng-distinctness"
    tuples: set[tuple[str, str]] = set()
    for _ in range(50):
        out = ecies_sealed_poe_wrap(plaintext=plaintext, recipient_public_keys=[pub])
        tuples.add((out.envelope.nonce.hex(), out.envelope.slots_mac.hex()))
    assert len(tuples) == 50


def test_wrap_supports_unbounded_recipient_count() -> None:
    """No fixed upper bound; producer SDK polices byte budget."""
    # 64 recipients exceeds the old MAX_RECIPIENTS=32 — must succeed now.
    recipient_privs = [_make_priv(i * 7) for i in range(64)]
    recipient_publics = [x25519_public_key(p) for p in recipient_privs]
    plaintext = b"unbounded-recipient-count"
    out = ecies_sealed_poe_wrap(plaintext=plaintext, recipient_public_keys=recipient_publics)
    assert len(out.envelope.slots) == 64
    # Sanity-check round-trip for a few recipients.
    for idx in (0, 31, 63):
        assert _unwrap_envelope(out, recipient_privs[idx]) == plaintext


def _envelope_from_hex(env: dict[str, Any]) -> SealedEnvelope:
    # Accept both legacy (v/alg/iv/recipients/hdr_mac) and new wire-name
    # (scheme/aead/nonce/slots/slots_mac) fixture shapes so the test loader
    # works across the wire-name rename transition.
    scheme = int(env.get("scheme", env.get("v", 1)))
    aead = str(env.get("aead", env.get("alg", "xchacha20-poly1305")))
    nonce_hex = env.get("nonce_hex", env.get("iv_hex"))
    nonce = bytes.fromhex(str(nonce_hex))
    slots_raw = env.get("slots", env.get("recipients", []))
    slots = tuple(
        SealedSlot(
            epk=bytes.fromhex(str(s.get("epk_hex", s.get("eph_hex")))),
            wrap=bytes.fromhex(str(s["wrap_hex"])),
        )
        for s in slots_raw
    )
    kem_str = "x25519"
    if slots_raw and "kem" in slots_raw[0]:
        kem_str = str(slots_raw[0]["kem"])
    elif "kem" in env:
        kem_str = str(env["kem"])
    mac_hex = env.get("slots_mac_hex", env.get("hdr_mac_hex"))
    return SealedEnvelope(
        scheme=scheme,
        aead=aead,
        kem=kem_str,
        nonce=nonce,
        slots=slots,
        slots_mac=bytes.fromhex(str(mac_hex)),
    )


def _load_positive_unwrap(filename: str) -> tuple[SealedEnvelope, bytes, list[bytes], bytes]:
    corpus = _load_positive(filename)
    vector: dict[str, Any] = corpus["vector"]
    envelope = _envelope_from_hex(vector["envelope"])
    ciphertext = bytes.fromhex(str(vector["ciphertext_hex"]))
    privs = [bytes.fromhex(h) for h in vector["recipient_secrets_hex"]]
    expected = bytes.fromhex(str(vector["expected_plaintext_hex"]))
    return envelope, ciphertext, privs, expected


def _check_unwrap_positive(filename: str) -> None:
    envelope, ciphertext, privs, expected = _load_positive_unwrap(filename)
    for priv in privs:
        result = ecies_sealed_poe_unwrap(
            envelope=envelope,
            ciphertext=ciphertext,
            recipient_secret_key=priv,
        )
        assert result.matched is True, filename
        assert result.plaintext == expected, filename


def test_unwrap_n1_empty_b1() -> None:
    _check_unwrap_positive("unwrap-n1-empty.json")


def test_unwrap_n3_b2() -> None:
    _check_unwrap_positive("unwrap-n3.json")


def test_unwrap_n32() -> None:
    _check_unwrap_positive("unwrap-n32.json")


def test_unwrap_duplicate_recipient_decrypts() -> None:
    # A1 positive: the same recipient public key in two slots (fresh distinct
    # ephemerals, same CEK) MUST decrypt normally — the CEK-conflict check
    # rejects only DIFFERENT recovered CEKs, never honest recipient padding.
    _check_unwrap_positive("unwrap-duplicate-recipient.json")


def test_cek_conflict_is_rejected() -> None:
    # A1 negative (behavioral): construct an envelope spliced from two single-slot
    # wraps that address the SAME recipient but carry DIFFERENT CEKs, then re-key
    # the slots_mac and content ciphertext to the FIRST slot's CEK so that slot 0
    # passes the MAC and the content opens. The ONLY thing that should reject this
    # is the CEK-conflict check: slot 1 recovers a different CEK. A verifier that
    # selected only the first match and skipped the rest would wrongly ACCEPT it.
    from cardanowall._crypto.aead import xchacha20_poly1305_encrypt
    from cardanowall._crypto.sealed_poe import (
        _ad_content_slots,
        _compute_slots_hash,
        _slots_mac_from_hash,
        _slots_payload_key,
        ecies_sealed_poe_trial_decrypt,
    )

    priv = bytes((0xD0 + i) & 0xFF for i in range(32))
    pub = x25519_public_key(priv)
    cek_a = bytes([0xAA] * 32)
    cek_b = bytes([0xBB] * 32)
    nonce = bytes((0xE0 + i) & 0xFF for i in range(24))

    out_a = ecies_sealed_poe_wrap(
        plaintext=b"x",
        recipient_public_keys=[pub],
        cek=cek_a,
        nonce=nonce,
        ephemeral_secrets=[bytes([0x01] * 32)],
        skip_shuffle=True,
    )
    out_b = ecies_sealed_poe_wrap(
        plaintext=b"x",
        recipient_public_keys=[pub],
        cek=cek_b,
        nonce=nonce,
        ephemeral_secrets=[bytes([0x02] * 32)],
        skip_shuffle=True,
    )
    slots = (out_a.envelope.slots[0], out_b.envelope.slots[0])
    # Distinct epks, so the duplicate-KEM-material gate does not pre-empt the
    # conflict path.
    assert slots[0].epk != slots[1].epk

    slots_hash = _compute_slots_hash(nonce, slots, "x25519")
    slots_mac = _slots_mac_from_hash(cek_a, slots_hash)
    payload_key = _slots_payload_key(cek_a, nonce)
    aad = _ad_content_slots(nonce, "x25519", slots_hash, slots_mac)
    ciphertext = xchacha20_poly1305_encrypt(payload_key, nonce, aad, b"conflict-probe")

    envelope = SealedEnvelope(
        scheme=1,
        aead="xchacha20-poly1305",
        kem="x25519",
        nonce=nonce,
        slots=slots,
        slots_mac=slots_mac,
    )

    # Single-priv path: rejected with the generic TAMPERED_HEADER reason.
    res = ecies_sealed_poe_unwrap(
        envelope=envelope, ciphertext=ciphertext, recipient_secret_key=priv
    )
    assert res.matched is False
    assert res.reason == UNWRAP_REASON_TAMPERED_HEADER

    # Multi-priv path: same rejection.
    res_multi = ecies_sealed_poe_unwrap(
        envelope=envelope, ciphertext=ciphertext, recipient_secret_keys=[priv]
    )
    assert res_multi.matched is False
    assert res_multi.reason == UNWRAP_REASON_TAMPERED_HEADER

    # Trial-decrypt path: a conflict is the generic aead_pass_no_mac_match, never
    # a clean match.
    trial = ecies_sealed_poe_trial_decrypt(envelope=envelope, recipient_secret_keys=[priv])
    assert trial.kind == "aead_pass_no_mac_match"


def test_unwrap_structured_negatives() -> None:
    corpus = cast(
        dict[str, Any],
        json.loads((FIXTURES_DIR / "unwrap-negative.json").read_text()),
    )
    for vector in corpus["matched_false_vectors"]:
        # Multi-priv MAC-fail vector lives in the same fixture but
        # consumes the multi-priv API surface; exercised separately.
        if "recipient_secret_hex" not in vector:
            continue
        envelope = _envelope_from_hex(vector["envelope"])
        ciphertext = bytes.fromhex(str(vector["ciphertext_hex"]))
        priv = bytes.fromhex(str(vector["recipient_secret_hex"]))
        result = ecies_sealed_poe_unwrap(
            envelope=envelope,
            ciphertext=ciphertext,
            recipient_secret_key=priv,
        )
        assert result.matched is False, vector["name"]
        assert result.reason == vector["expected_reason"], vector["name"]


def test_unwrap_raise_cases() -> None:
    corpus = cast(
        dict[str, Any],
        json.loads((FIXTURES_DIR / "unwrap-negative.json").read_text()),
    )
    for vector in corpus["raise_vectors"]:
        # The old 32-recipient cap was removed; only the lower bound stays.
        # The "n33" fixture case is no longer an error.
        if vector["name"] == "n33":
            continue
        # Multi-priv input-validation vectors live in the same
        # fixture but consume the multi-priv API surface; exercised separately.
        if "recipient_secret_hex" not in vector or "recipient_secret_keys_hex" in vector:
            continue
        envelope = _envelope_from_hex(vector["envelope"])
        ciphertext = bytes.fromhex(str(vector["ciphertext_hex"]))
        priv = bytes.fromhex(str(vector["recipient_secret_hex"]))
        with pytest.raises(EciesSealedPoeError) as exc_info:
            ecies_sealed_poe_unwrap(
                envelope=envelope,
                ciphertext=ciphertext,
                recipient_secret_key=priv,
            )
        expected_code = vector["expected_error_code"]
        if expected_code == "IV_LENGTH_MISMATCH":
            expected_code = "NONCE_LENGTH_MISMATCH"
        if expected_code == "ENC_RECIPIENTS_OUT_OF_RANGE":
            expected_code = "ENC_SLOTS_EMPTY"
        if expected_code == "KEM_EPH_LENGTH_MISMATCH":
            expected_code = "KEM_EPK_LENGTH_MISMATCH"
        if expected_code == "HDR_MAC_LENGTH_MISMATCH":
            expected_code = "ENC_SLOTS_MAC_INVALID_LENGTH"
        assert exc_info.value.code == expected_code, vector["name"]


def _hybrid_envelope_from_kat(env: dict[str, Any]) -> SealedEnvelope:
    """Build a hybrid (X-Wing) SealedEnvelope from a rechunked-KAT slot shape.

    The KAT serves each slot's `kem_ct` in arbitrary chunk boundaries; the
    in-memory `SealedSlot.kem_ct` is the reassembled flat byte string. The
    slots_mac is computed over `_chunk_kem_ct(flat)` (canonical 64B chunks),
    so any honest re-chunking yields the SAME MAC — this is exactly what the
    KAT pins.
    """
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


def test_unwrap_hybrid_rechunked_kem_ct_is_chunking_invariant() -> None:
    """Shared KAT: a hybrid kem_ct re-served with non-canonical chunk
    boundaries reassembles identically and carries the same canonical
    slots_mac, so unwrap recovers the plaintext; a byte-flipped twin still
    fails slots_mac (TAMPERED_HEADER)."""
    corpus = cast(
        dict[str, Any],
        json.loads((FIXTURES_DIR / "unwrap-hybrid-rechunked.json").read_text()),
    )

    for vector in corpus["matched_true_vectors"]:
        envelope = _hybrid_envelope_from_kat(vector["envelope"])
        ciphertext = bytes.fromhex(str(vector["ciphertext_hex"]))
        privs = [bytes.fromhex(h) for h in vector["recipient_secrets_hex"]]
        expected_plaintext = bytes.fromhex(str(vector["expected"]["plaintext_hex"]))
        for priv in privs:
            result = ecies_sealed_poe_unwrap(
                envelope=envelope,
                ciphertext=ciphertext,
                recipient_secret_key=priv,
            )
            assert result.matched is True, vector["name"]
            assert result.plaintext == expected_plaintext, vector["name"]

    for vector in corpus["matched_false_vectors"]:
        envelope = _hybrid_envelope_from_kat(vector["envelope"])
        ciphertext = bytes.fromhex(str(vector["ciphertext_hex"]))
        privs = [bytes.fromhex(h) for h in vector["recipient_secrets_hex"]]
        expected_reason = str(vector["expected"]["reason"])
        for priv in privs:
            result = ecies_sealed_poe_unwrap(
                envelope=envelope,
                ciphertext=ciphertext,
                recipient_secret_key=priv,
            )
            assert result.matched is False, vector["name"]
            assert result.reason == expected_reason, vector["name"]


# Multi-priv unwrap test corpus.
def _load_multipriv(filename: str) -> dict[str, Any]:
    corpus = cast(
        dict[str, Any],
        json.loads((FIXTURES_DIR / filename).read_text()),
    )
    return cast(dict[str, Any], corpus["vector"])


def _multipriv_envelope_and_inputs(
    filename: str,
) -> tuple[SealedEnvelope, bytes, list[bytes], dict[str, Any]]:
    v = _load_multipriv(filename)
    envelope = _envelope_from_hex(v["envelope"])
    ciphertext = bytes.fromhex(str(v["ciphertext_hex"]))
    privs = [bytes.fromhex(h) for h in v["recipient_privs_hex"]]
    return envelope, ciphertext, privs, v


def test_unwrap_multipriv_current_match() -> None:
    envelope, ciphertext, privs, v = _multipriv_envelope_and_inputs(
        "unwrap-multipriv-current-match.json"
    )
    slots_attempted: list[int] = []
    privs_attempted: list[int] = []
    result = ecies_sealed_poe_unwrap(
        envelope=envelope,
        ciphertext=ciphertext,
        recipient_secret_keys=privs,
        _slots_attempted_out=slots_attempted,
        _privs_attempted_out=privs_attempted,
    )
    assert result.matched is True
    assert result.plaintext is not None
    assert result.plaintext.hex() == v["expected_plaintext_hex"]
    assert privs_attempted[0] == v["expected_outer_loop_count"]
    assert slots_attempted == [v["expected_inner_loop_count_per_priv"]]


def test_unwrap_multipriv_archived_match() -> None:
    envelope, ciphertext, privs, v = _multipriv_envelope_and_inputs(
        "unwrap-multipriv-archived-match.json"
    )
    slots_attempted: list[int] = []
    privs_attempted: list[int] = []
    result = ecies_sealed_poe_unwrap(
        envelope=envelope,
        ciphertext=ciphertext,
        recipient_secret_keys=privs,
        _slots_attempted_out=slots_attempted,
        _privs_attempted_out=privs_attempted,
    )
    assert result.matched is True
    assert result.plaintext is not None
    assert result.plaintext.hex() == v["expected_plaintext_hex"]
    assert privs_attempted[0] == v["expected_outer_loop_count"]
    expected_inner = v["expected_inner_loop_count_per_priv"]
    assert slots_attempted == [expected_inner, expected_inner, expected_inner]


def test_unwrap_multipriv_no_match() -> None:
    envelope, ciphertext, privs, v = _multipriv_envelope_and_inputs(
        "unwrap-multipriv-no-match.json"
    )
    slots_attempted: list[int] = []
    privs_attempted: list[int] = []
    result = ecies_sealed_poe_unwrap(
        envelope=envelope,
        ciphertext=ciphertext,
        recipient_secret_keys=privs,
        _slots_attempted_out=slots_attempted,
        _privs_attempted_out=privs_attempted,
    )
    assert result.matched is False
    assert result.reason == UNWRAP_REASON_WRONG_RECIPIENT_KEY
    assert privs_attempted[0] == v["expected_outer_loop_count"]
    expected_inner = v["expected_inner_loop_count_per_priv"]
    assert slots_attempted == [expected_inner] * 4


def test_unwrap_multipriv_n32_k10_worst_case() -> None:
    envelope, ciphertext, privs, v = _multipriv_envelope_and_inputs(
        "unwrap-multipriv-n32-k10-worst-case.json"
    )
    slots_attempted: list[int] = []
    privs_attempted: list[int] = []
    result = ecies_sealed_poe_unwrap(
        envelope=envelope,
        ciphertext=ciphertext,
        recipient_secret_keys=privs,
        _slots_attempted_out=slots_attempted,
        _privs_attempted_out=privs_attempted,
    )
    assert result.matched is True
    assert result.plaintext is not None
    assert result.plaintext.hex() == v["expected_plaintext_hex"]
    assert privs_attempted[0] == 10
    assert len(slots_attempted) == 10
    for c in slots_attempted:
        assert c == 32
    assert sum(slots_attempted) == 320


def test_unwrap_multipriv_mac_fail() -> None:
    corpus = cast(
        dict[str, Any],
        json.loads((FIXTURES_DIR / "unwrap-negative.json").read_text()),
    )
    vector = next(v for v in corpus["matched_false_vectors"] if v["name"] == "multipriv-mac-fail")
    envelope = _envelope_from_hex(vector["envelope"])
    ciphertext = bytes.fromhex(str(vector["ciphertext_hex"]))
    privs = [bytes.fromhex(h) for h in vector["recipient_secret_keys_hex"]]
    result = ecies_sealed_poe_unwrap(
        envelope=envelope,
        ciphertext=ciphertext,
        recipient_secret_keys=privs,
    )
    assert result.matched is False
    assert result.reason == UNWRAP_REASON_TAMPERED_HEADER


def test_unwrap_multipriv_negative_empty() -> None:
    envelope, ciphertext, _, _ = _multipriv_envelope_and_inputs(
        "unwrap-multipriv-current-match.json"
    )
    with pytest.raises(EciesSealedPoeError) as exc_info:
        ecies_sealed_poe_unwrap(
            envelope=envelope,
            ciphertext=ciphertext,
            recipient_secret_keys=[],
        )
    assert exc_info.value.code == "INVALID_RECIPIENT_KEY"


def test_unwrap_multipriv_negative_both_forms() -> None:
    envelope, ciphertext, privs, _ = _multipriv_envelope_and_inputs(
        "unwrap-multipriv-current-match.json"
    )
    with pytest.raises(EciesSealedPoeError) as exc_info:
        ecies_sealed_poe_unwrap(
            envelope=envelope,
            ciphertext=ciphertext,
            recipient_secret_key=privs[0],
            recipient_secret_keys=privs,
        )
    assert exc_info.value.code == "INVALID_RECIPIENT_KEY"


def test_unwrap_multipriv_negative_neither_form() -> None:
    envelope, ciphertext, _, _ = _multipriv_envelope_and_inputs(
        "unwrap-multipriv-current-match.json"
    )
    with pytest.raises(EciesSealedPoeError) as exc_info:
        ecies_sealed_poe_unwrap(
            envelope=envelope,
            ciphertext=ciphertext,
        )
    assert exc_info.value.code == "INVALID_RECIPIENT_KEY"


def test_unwrap_multipriv_negative_wrong_length() -> None:
    envelope, ciphertext, privs, _ = _multipriv_envelope_and_inputs(
        "unwrap-multipriv-current-match.json"
    )
    short_priv = b"\x11" * 31
    with pytest.raises(EciesSealedPoeError) as exc_info:
        ecies_sealed_poe_unwrap(
            envelope=envelope,
            ciphertext=ciphertext,
            recipient_secret_keys=[privs[0], short_priv, privs[0]],
        )
    assert exc_info.value.code == "INVALID_RECIPIENT_KEY"


def test_unwrap_property_roundtrip_n1_n3_n32() -> None:
    for n in (1, 3, 32):
        recipient_privs = [_make_priv(0x10 + i * 3) for i in range(n)]
        recipient_publics = [x25519_public_key(p) for p in recipient_privs]
        plaintext = f"unwrap-property-N{n}".encode()
        out = ecies_sealed_poe_wrap(plaintext=plaintext, recipient_public_keys=recipient_publics)
        for priv in recipient_privs:
            result = ecies_sealed_poe_unwrap(
                envelope=out.envelope,
                ciphertext=out.ciphertext,
                recipient_secret_key=priv,
            )
            assert result.matched is True
            assert result.plaintext == plaintext


def test_unwrap_constant_time_n_enters_all_slots() -> None:
    n = 8
    recipient_privs = [_make_priv(0x10 + i * 3) for i in range(n)]
    recipient_publics = [x25519_public_key(p) for p in recipient_privs]
    plaintext = b"constant-time-N enters all slots"
    out = ecies_sealed_poe_wrap(plaintext=plaintext, recipient_public_keys=recipient_publics)
    for idx in (0, n // 2, n - 1):
        slots_attempted: list[int] = []
        result = ecies_sealed_poe_unwrap(
            envelope=out.envelope,
            ciphertext=out.ciphertext,
            recipient_secret_key=recipient_privs[idx],
            _slots_attempted_out=slots_attempted,
        )
        assert result.matched is True
        assert slots_attempted[0] == n


def test_unwrap_variable_time_short_circuits() -> None:
    n = 8
    recipient_privs = [_make_priv(0x10 + i * 3) for i in range(n)]
    recipient_publics = [x25519_public_key(p) for p in recipient_privs]
    plaintext = b"variable-time short-circuit"
    out = ecies_sealed_poe_wrap(plaintext=plaintext, recipient_public_keys=recipient_publics)
    variable_counts: list[int] = []
    for idx in (0, n // 2, n - 1):
        slots_attempted: list[int] = []
        result = ecies_sealed_poe_unwrap(
            envelope=out.envelope,
            ciphertext=out.ciphertext,
            recipient_secret_key=recipient_privs[idx],
            constant_time_n=False,
            _slots_attempted_out=slots_attempted,
        )
        assert result.matched is True
        assert 1 <= slots_attempted[0] <= n
        variable_counts.append(slots_attempted[0])
    # With n distinct privs the shuffle places at least one match earlier than the last slot.
    assert min(variable_counts) < n


def test_unwrap_reason_constants_match_strings() -> None:
    assert UNWRAP_REASON_WRONG_RECIPIENT_KEY == "WRONG_RECIPIENT_KEY"
    assert UNWRAP_REASON_TAMPERED_HEADER == "TAMPERED_HEADER"
    assert UNWRAP_REASON_TAMPERED_CIPHERTEXT == "TAMPERED_CIPHERTEXT"


def test_partitioning_oracle_pre_checks_order() -> None:
    """Five length pre-checks BEFORE any AEAD primitive runs."""
    priv = _make_priv(0xAA)
    valid_pub = x25519_public_key(priv)
    valid_epk = x25519_public_key(_make_priv(0xBB))
    valid_wrap = b"\xcc" * 48
    valid_nonce = b"\x00" * 24
    valid_mac = b"\xdd" * 32
    valid_ct = b"\xee" * 16

    # 1. slots empty → ENC_SLOTS_EMPTY
    env = SealedEnvelope(
        scheme=1,
        aead="xchacha20-poly1305",
        kem="x25519",
        nonce=valid_nonce,
        slots=(),
        slots_mac=valid_mac,
    )
    with pytest.raises(EciesSealedPoeError) as exc:
        ecies_sealed_poe_unwrap(envelope=env, ciphertext=valid_ct, recipient_secret_key=priv)
    assert exc.value.code == "ENC_SLOTS_EMPTY"

    # 2. nonce wrong length → NONCE_LENGTH_MISMATCH
    env = SealedEnvelope(
        scheme=1,
        aead="xchacha20-poly1305",
        kem="x25519",
        nonce=b"\x00" * 12,  # wrong length
        slots=(SealedSlot(epk=valid_epk, wrap=valid_wrap),),
        slots_mac=valid_mac,
    )
    with pytest.raises(EciesSealedPoeError) as exc:
        ecies_sealed_poe_unwrap(envelope=env, ciphertext=valid_ct, recipient_secret_key=priv)
    assert exc.value.code == "NONCE_LENGTH_MISMATCH"

    # 3. slots_mac wrong length → ENC_SLOTS_MAC_INVALID_LENGTH
    env = SealedEnvelope(
        scheme=1,
        aead="xchacha20-poly1305",
        kem="x25519",
        nonce=valid_nonce,
        slots=(SealedSlot(epk=valid_epk, wrap=valid_wrap),),
        slots_mac=b"\xdd" * 16,  # wrong length
    )
    with pytest.raises(EciesSealedPoeError) as exc:
        ecies_sealed_poe_unwrap(envelope=env, ciphertext=valid_ct, recipient_secret_key=priv)
    assert exc.value.code == "ENC_SLOTS_MAC_INVALID_LENGTH"

    # 4. slot.epk wrong length → KEM_EPK_LENGTH_MISMATCH
    env = SealedEnvelope(
        scheme=1,
        aead="xchacha20-poly1305",
        kem="x25519",
        nonce=valid_nonce,
        slots=(SealedSlot(epk=b"\xbb" * 16, wrap=valid_wrap),),
        slots_mac=valid_mac,
    )
    with pytest.raises(EciesSealedPoeError) as exc:
        ecies_sealed_poe_unwrap(envelope=env, ciphertext=valid_ct, recipient_secret_key=priv)
    assert exc.value.code == "KEM_EPK_LENGTH_MISMATCH"

    # 5. slot.wrap wrong length → WRAP_LENGTH_MISMATCH
    env = SealedEnvelope(
        scheme=1,
        aead="xchacha20-poly1305",
        kem="x25519",
        nonce=valid_nonce,
        slots=(SealedSlot(epk=valid_epk, wrap=b"\xcc" * 32),),
        slots_mac=valid_mac,
    )
    with pytest.raises(EciesSealedPoeError) as exc:
        ecies_sealed_poe_unwrap(envelope=env, ciphertext=valid_ct, recipient_secret_key=priv)
    assert exc.value.code == "WRAP_LENGTH_MISMATCH"

    # Use valid_pub to silence unused-variable lint without changing imports.
    assert len(valid_pub) == 32


def test_wrap_unwrap_byte_field_names_match_spec() -> None:
    """Wire field names: scheme, aead, kem, nonce, slots, slots_mac."""
    priv = _make_priv(0x42)
    pub = x25519_public_key(priv)
    out = ecies_sealed_poe_wrap(plaintext=b"x", recipient_public_keys=[pub])
    env = out.envelope
    # Field names mirror the wire shape exactly.
    assert hasattr(env, "scheme") and env.scheme == 1
    assert hasattr(env, "aead") and env.aead == "xchacha20-poly1305"
    assert hasattr(env, "kem") and env.kem == "x25519"
    assert hasattr(env, "nonce") and len(env.nonce) == 24
    assert hasattr(env, "slots") and len(env.slots) == 1
    assert hasattr(env, "slots_mac") and len(env.slots_mac) == 32
    # Per-slot: epk + wrap only (no per-slot `kem` field).
    slot = env.slots[0]
    assert slot.epk is not None
    assert hasattr(slot, "epk") and len(slot.epk) == 32
    assert hasattr(slot, "wrap") and len(slot.wrap) == 48
    assert not hasattr(slot, "kem")


# Python sibling for the constant-time-N matrix.
# Mirrors the @cardanowall/crypto-core multi-priv unwrap test
# `describe('multi-priv constant-time-N matrix')` against
# the byte-identical Python fixture mirrors.
_AC9_SCENARIOS: list[tuple[str, int, list[int], bool]] = [
    ("unwrap-multipriv-ac9-priv0-slot0.json", 1, [32], True),
    ("unwrap-multipriv-ac9-priv0-slot31.json", 1, [32], True),
    ("unwrap-multipriv-ac9-priv4-slot0.json", 5, [32, 32, 32, 32, 32], True),
    ("unwrap-multipriv-ac9-priv4-slot31.json", 5, [32, 32, 32, 32, 32], True),
    ("unwrap-multipriv-ac9-no-match.json", 5, [32, 32, 32, 32, 32], False),
]


@pytest.mark.parametrize("filename, expected_outer, expected_per_priv, matched", _AC9_SCENARIOS)
def test_unwrap_multipriv_ac9_constant_time_n_matrix(
    filename: str,
    expected_outer: int,
    expected_per_priv: list[int],
    matched: bool,
) -> None:
    envelope, ciphertext, privs, v = _multipriv_envelope_and_inputs(filename)
    slots_attempted: list[int] = []
    privs_attempted: list[int] = []
    result = ecies_sealed_poe_unwrap(
        envelope=envelope,
        ciphertext=ciphertext,
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


# X-Wing hybrid KEM (ML-KEM-768 + X25519) byte-identical parity twin of the
# crypto-core wrap-hybrid KAT fixtures. The TS side authored and mirrored these
# fixtures; the Python wrap MUST reproduce every slot byte, the slots_mac, and
# the ciphertext exactly, then unwrap them back to the CEK + plaintext.
def _check_hybrid_positive(filename: str) -> None:
    corpus = _load_positive(filename)
    vector: dict[str, Any] = corpus["vector"]
    recipient_publics = [bytes.fromhex(h) for h in vector["recipient_publics_hex"]]
    eseeds = [bytes.fromhex(h) for h in vector["eseeds_hex"]]
    cek = bytes.fromhex(str(vector["cek_hex"]))
    nonce = bytes.fromhex(str(vector["nonce_hex"]))
    plaintext = bytes.fromhex(str(vector["plaintext_hex"]))

    out = ecies_sealed_poe_wrap(
        plaintext=plaintext,
        recipient_public_keys=recipient_publics,
        kem="mlkem768x25519",
        cek=cek,
        nonce=nonce,
        eseeds=eseeds,
        skip_shuffle=True,
    )

    assert out.envelope.scheme == 1
    assert out.envelope.aead == "xchacha20-poly1305"
    assert out.envelope.kem == "mlkem768x25519"
    assert out.envelope.nonce.hex() == vector["nonce_hex"]

    expected_slots = vector["expected_slots"]
    assert len(out.envelope.slots) == len(expected_slots)
    for i, slot in enumerate(out.envelope.slots):
        # No per-slot epk on the hybrid path; kem_ct is the flat 1120-byte enc.
        assert slot.epk is None
        assert slot.kem_ct is not None
        assert slot.kem_ct.hex() == expected_slots[i]["kem_ct_hex"]
        assert slot.wrap.hex() == expected_slots[i]["wrap_hex"]

    assert out.envelope.slots_mac.hex() == vector["expected_slots_mac_hex"]
    assert out.ciphertext.hex() == vector["expected_ciphertext_hex"]

    # Unwrap with each recipient's X-Wing secret seed recovers the plaintext.
    expected_plaintext = bytes.fromhex(str(vector["expected_plaintext_hex"]))
    for seed_hex in vector["recipient_seeds_hex"]:
        _public, secret_seed = xwing_keygen(bytes.fromhex(seed_hex))
        result = ecies_sealed_poe_unwrap(
            envelope=out.envelope,
            ciphertext=out.ciphertext,
            recipient_secret_key=secret_seed,
        )
        assert result.matched is True, (filename, seed_hex)
        assert result.plaintext == expected_plaintext, (filename, seed_hex)


def test_wrap_hybrid_n1_empty() -> None:
    _check_hybrid_positive("wrap-hybrid-n1.json")


def test_wrap_hybrid_n3() -> None:
    _check_hybrid_positive("wrap-hybrid-n3.json")


def test_unwrap_hybrid_wrong_recipient() -> None:
    """A recipient not in the slot set recovers no CEK → WRONG_RECIPIENT_KEY."""
    corpus = _load_positive("wrap-hybrid-n3.json")
    vector = corpus["vector"]
    recipient_publics = [bytes.fromhex(h) for h in vector["recipient_publics_hex"]]
    eseeds = [bytes.fromhex(h) for h in vector["eseeds_hex"]]
    cek = bytes.fromhex(str(vector["cek_hex"]))
    nonce = bytes.fromhex(str(vector["nonce_hex"]))
    plaintext = bytes.fromhex(str(vector["plaintext_hex"]))
    out = ecies_sealed_poe_wrap(
        plaintext=plaintext,
        recipient_public_keys=recipient_publics,
        kem="mlkem768x25519",
        cek=cek,
        nonce=nonce,
        eseeds=eseeds,
        skip_shuffle=True,
    )
    # A seed never used to wrap any slot.
    _stranger_pub, stranger_seed = xwing_keygen(b"\x99" * 32)
    result = ecies_sealed_poe_unwrap(
        envelope=out.envelope,
        ciphertext=out.ciphertext,
        recipient_secret_key=stranger_seed,
    )
    assert result.matched is False
    assert result.reason == UNWRAP_REASON_WRONG_RECIPIENT_KEY


def test_unwrap_hybrid_kem_ct_length_mismatch() -> None:
    """A kem_ct that reassembles to != 1120 bytes raises KEM_CT_LENGTH_MISMATCH,
    for both under- and over-length, before any decapsulation."""
    corpus = _load_positive("wrap-hybrid-n1.json")
    vector = corpus["vector"]
    recipient_publics = [bytes.fromhex(h) for h in vector["recipient_publics_hex"]]
    eseeds = [bytes.fromhex(h) for h in vector["eseeds_hex"]]
    cek = bytes.fromhex(str(vector["cek_hex"]))
    nonce = bytes.fromhex(str(vector["nonce_hex"]))
    out = ecies_sealed_poe_wrap(
        plaintext=b"",
        recipient_public_keys=recipient_publics,
        kem="mlkem768x25519",
        cek=cek,
        nonce=nonce,
        eseeds=eseeds,
        skip_shuffle=True,
    )
    _public, secret_seed = xwing_keygen(bytes.fromhex(vector["recipient_seeds_hex"][0]))
    good_slot = out.envelope.slots[0]
    assert good_slot.kem_ct is not None

    for bad_kem_ct in (good_slot.kem_ct[:-1], good_slot.kem_ct + b"\x00"):
        tampered = SealedEnvelope(
            scheme=out.envelope.scheme,
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
                recipient_secret_key=secret_seed,
            )
        assert exc.value.code == "KEM_CT_LENGTH_MISMATCH"


def test_unwrap_hybrid_slots_mac_covers_kem_ct() -> None:
    """Regression: slots_mac MUST authenticate the hybrid kem_ct.

    Build a two-slot hybrid envelope. Recipient A opens slot 0 cleanly, so a
    candidate CEK is always recovered. Flip one byte of slot 1's kem_ct (an
    untouched slot). Because slots_mac was computed over the ORIGINAL slot-set
    CBOR (including slot 1's kem_ct), the recomputed MAC no longer matches →
    matched=False reason=TAMPERED_HEADER (NOT TAMPERED_CIPHERTEXT — the content
    AEAD is never reached; NOT WRONG_RECIPIENT_KEY — the CEK IS recovered from
    the clean slot 0). Mirrors the crypto-core
    unwrap-hybrid-slots-mac.regression test byte-for-byte.
    """
    pub_a, seed_a = xwing_keygen(b"\x11" * 32)
    pub_b, _seed_b = xwing_keygen(b"\x22" * 32)
    plaintext = b"hybrid-slots-mac-kem-ct-coverage"
    out = ecies_sealed_poe_wrap(
        plaintext=plaintext,
        recipient_public_keys=[pub_a, pub_b],
        kem="mlkem768x25519",
        cek=b"\xab" * 32,
        nonce=b"\xcd" * 24,
        eseeds=[b"\xe1" * 64, b"\xe2" * 64],
        skip_shuffle=True,
    )

    # Sanity: recipient A opens cleanly before tampering.
    clean = ecies_sealed_poe_unwrap(
        envelope=out.envelope, ciphertext=out.ciphertext, recipient_secret_key=seed_a
    )
    assert clean.matched is True

    # Flip one byte of slot 1's kem_ct. Slot 0 (recipient A's) is untouched, so
    # the CEK is still recovered — but the MAC over the slot-set now disagrees.
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
        envelope=tampered_env, ciphertext=out.ciphertext, recipient_secret_key=seed_a
    )
    assert res.matched is False
    assert res.reason == UNWRAP_REASON_TAMPERED_HEADER
