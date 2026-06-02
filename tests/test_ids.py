"""Tests for cardanowall.ids — parity twin of sdk-ts src/ids.

Mirrors crockford-base32.test.ts and prefixed-id.test.ts, plus a
cross-language fixture sweep whose encoded values are byte-identical to the
TypeScript encoder.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from cardanowall.ids import (
    CROCKFORD_ENCODED_LENGTH_FOR_UUID,
    decode_crockford_base32,
    decode_prefixed_id,
    encode_crockford_base32,
    encode_prefixed_id,
    is_prefixed_id,
)

KNOWN_ZERO = bytes(16)
KNOWN_FF = b"\xff" * 16
NIL_UUID = "00000000-0000-0000-0000-000000000000"
MAX_UUID = "ffffffff-ffff-ffff-ffff-ffffffffffff"
SAMPLE_UUIDV7 = "01977c4a-0066-7777-aaaa-bbbbbbbbbbbb"

_CROCKFORD_BODY = re.compile(r"^[0-9a-hjkmnp-tv-z]{26}$")


# --- crockford-base32 ---


def test_encode_zero_bytes_to_26_zeros() -> None:
    assert encode_crockford_base32(KNOWN_ZERO) == "0" * CROCKFORD_ENCODED_LENGTH_FOR_UUID


def test_encode_ff_bytes_25z_then_w() -> None:
    out = encode_crockford_base32(KNOWN_FF)
    assert len(out) == 26
    assert out[:25] == "z" * 25
    assert out[25] == "w"


def test_encode_rejects_non_16_byte_input() -> None:
    with pytest.raises(ValueError, match="16 bytes"):
        encode_crockford_base32(bytes(15))
    with pytest.raises(ValueError, match="16 bytes"):
        encode_crockford_base32(bytes(17))


def test_round_trip_zero_and_ff() -> None:
    assert decode_crockford_base32(encode_crockford_base32(KNOWN_ZERO)) == KNOWN_ZERO
    assert decode_crockford_base32(encode_crockford_base32(KNOWN_FF)) == KNOWN_FF


def test_round_trip_uuidv7_payload() -> None:
    data = bytes.fromhex("01977c4a00667777aaaabbbbbbbbbbbb")
    encoded = encode_crockford_base32(data)
    assert len(encoded) == 26
    assert decode_crockford_base32(encoded) == data


def test_accepts_uppercase_input() -> None:
    encoded = encode_crockford_base32(KNOWN_FF)
    assert decode_crockford_base32(encoded.upper()) == KNOWN_FF


def test_accepts_i_l_to_1_o_to_0_aliases() -> None:
    encoded = encode_crockford_base32(KNOWN_ZERO)  # all '0'
    massaged = "O" + encoded[1:13] + "o" + encoded[14:]
    assert decode_crockford_base32(massaged) == KNOWN_ZERO

    bit_one = bytearray(16)
    bit_one[0] = 0b00001000  # top symbol '1'
    e2 = encode_crockford_base32(bytes(bit_one))
    assert e2.startswith("1")
    assert decode_crockford_base32("I" + e2[1:])[0] == 0b00001000


def test_rejects_u_as_invalid() -> None:
    encoded = encode_crockford_base32(KNOWN_ZERO)
    with pytest.raises(ValueError, match="invalid character"):
        decode_crockford_base32("u" + encoded[1:])


def test_rejects_wrong_length() -> None:
    with pytest.raises(ValueError, match="26-char input"):
        decode_crockford_base32("0" * 25)
    with pytest.raises(ValueError, match="26-char input"):
        decode_crockford_base32("0" * 27)
    with pytest.raises(ValueError, match="26-char input"):
        decode_crockford_base32("")


def test_rejects_non_base32_char() -> None:
    encoded = encode_crockford_base32(KNOWN_ZERO)
    with pytest.raises(ValueError, match="invalid character"):
        decode_crockford_base32("!" + encoded[1:])


def test_rejects_non_zero_pad_bits() -> None:
    encoded = encode_crockford_base32(KNOWN_ZERO)
    tampered = encoded[:25] + "z"
    with pytest.raises(ValueError, match="non-zero pad bits"):
        decode_crockford_base32(tampered)


# --- prefixed-id ---


def test_encode_produces_prefix_underscore_26() -> None:
    encoded = encode_prefixed_id("poe", SAMPLE_UUIDV7)
    assert encoded.startswith("poe_")
    body = encoded[4:]
    assert len(body) == 26
    assert _CROCKFORD_BODY.match(body)


def test_round_trip_nil_max_arbitrary() -> None:
    assert encode_prefixed_id("acct", NIL_UUID) == "acct_" + "0" * 26
    assert decode_prefixed_id("acct", encode_prefixed_id("acct", NIL_UUID)) == NIL_UUID
    assert decode_prefixed_id("inv", encode_prefixed_id("inv", MAX_UUID)) == MAX_UUID
    assert (
        decode_prefixed_id("apikey", encode_prefixed_id("apikey", SAMPLE_UUIDV7)) == SAMPLE_UUIDV7
    )


def test_rejects_malformed_uuids() -> None:
    with pytest.raises(ValueError, match="canonical hyphenated UUID"):
        encode_prefixed_id("poe", "not-a-uuid")
    with pytest.raises(ValueError):
        encode_prefixed_id("poe", "01977c4a00667777aaaabbbbbbbbbbbb")  # no hyphens
    with pytest.raises(ValueError):
        encode_prefixed_id("poe", "01977c4a-0066-7777-aaaa-bbbbbbbbbbb")  # wrong width


def test_decode_rejects_mismatched_prefix() -> None:
    encoded = encode_prefixed_id("poe", SAMPLE_UUIDV7)
    with pytest.raises(ValueError, match="expected prefix"):
        decode_prefixed_id("acct", encoded)


def test_decode_rejects_missing_separator() -> None:
    with pytest.raises(ValueError, match="missing prefix separator"):
        decode_prefixed_id("poe", "poenoseparatorhere00000000000000")


def test_decode_rejects_wrong_body_length() -> None:
    with pytest.raises(ValueError, match="26-char input"):
        decode_prefixed_id("poe", "poe_tooshort")
    with pytest.raises(ValueError, match="26-char input"):
        decode_prefixed_id("poe", "poe_" + "a" * 27)


def test_decode_rejects_invalid_base32() -> None:
    with pytest.raises(ValueError, match="invalid character"):
        decode_prefixed_id("poe", "poe_" + "!" * 26)


def test_decode_rejects_non_string() -> None:
    with pytest.raises(ValueError, match="expected string"):
        decode_prefixed_id("poe", 42)  # type: ignore[arg-type]


def test_is_prefixed_id_accepts_canonical_lowercase() -> None:
    assert is_prefixed_id("poe", encode_prefixed_id("poe", SAMPLE_UUIDV7)) is True


def test_is_prefixed_id_rejects_mismatched_prefix() -> None:
    assert is_prefixed_id("acct", encode_prefixed_id("poe", SAMPLE_UUIDV7)) is False


def test_is_prefixed_id_rejects_bare_uuid() -> None:
    assert is_prefixed_id("poe", SAMPLE_UUIDV7) is False


def test_is_prefixed_id_rejects_uppercase_body() -> None:
    assert is_prefixed_id("poe", encode_prefixed_id("poe", SAMPLE_UUIDV7).upper()) is False


def test_is_prefixed_id_rejects_aliases() -> None:
    body = "0" * 26
    assert is_prefixed_id("poe", f"poe_{body[:5]}I{body[6:]}") is False
    assert is_prefixed_id("poe", f"poe_{body[:5]}o{body[6:]}") is False
    assert is_prefixed_id("poe", f"poe_{body[:5]}u{body[6:]}") is False


def test_is_prefixed_id_rejects_non_string() -> None:
    assert is_prefixed_id("poe", 42) is False
    assert is_prefixed_id("poe", None) is False


def test_is_prefixed_id_rejects_trailing_newline() -> None:
    # Regression: Python's regex ``$`` matches just before a final ``\n``, so an
    # un-anchored ``re.match`` over-accepts a valid body with a trailing newline
    # that the TS guard (``^…$`` + ``length === 26``) rejects. ``fullmatch``
    # closes the accept/reject flip.
    valid = encode_prefixed_id("poe", SAMPLE_UUIDV7)
    assert is_prefixed_id("poe", valid) is True
    assert is_prefixed_id("poe", valid + "\n") is False


def test_cross_language_parity_fixture() -> None:
    fixture = Path(__file__).parent / "fixtures" / "ids" / "cases.json"
    cases = json.loads(fixture.read_text())
    assert len(cases) >= 4
    for case in cases:
        cid = case["id"]
        kind = case.get("kind", "roundtrip")
        if kind == "roundtrip":
            prefix, uuid, encoded = case["prefix"], case["uuid"], case["encoded"]
            assert encode_prefixed_id(prefix, uuid) == encoded, f"case {cid}"
            assert decode_prefixed_id(prefix, encoded) == uuid, f"case {cid}"
        elif kind == "reject_is_prefixed_id":
            # A candidate that differs from the canonical wire form ONLY by a
            # trailing newline must be rejected. Python's ``$`` would match just
            # before a final ``\n``; ``fullmatch`` keeps the guard identical to
            # the TS ``^…$`` + length check, which already rejects.
            assert is_prefixed_id(case["prefix"], case["candidate"]) is False, f"case {cid}"
        else:  # pragma: no cover - guards against an unknown fixture kind
            raise AssertionError(f"unknown fixture kind {kind!r} in case {cid}")
