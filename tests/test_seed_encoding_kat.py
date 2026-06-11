"""Byte-exact known-answer test for the identity-seed codec.

Driven by the shared conformance fixture ``seed-derive/seed-encoding-kat.json``
(the same JSON the TypeScript and Rust SDKs consume), which pins, for each
seed, the exact UPPERCASE display string encode must emit and the lowercase
form parse must equally accept; hex-tolerance inputs (0x prefix, whitespace,
uppercase digits) that must parse to the same seed; and rejected inputs with
the exact error code. Passing this proves the Python codec emits and accepts
the same seed strings as the reference implementation, byte for byte.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from cardanowall.seed_encoding import (
    SeedEncodingError,
    encode_identity_seed,
    parse_identity_seed,
)

_FIXTURE = Path(__file__).parent / "fixtures" / "seed-derive" / "seed-encoding-kat.json"
_CORPUS = json.loads(_FIXTURE.read_text())
_VECTORS = _CORPUS["vectors"]
_PARSE_VECTORS = _CORPUS["parse_vectors"]
_NEGATIVE_VECTORS = _CORPUS["negative_vectors"]


@pytest.mark.parametrize("vector", _VECTORS, ids=lambda v: v["name"])
def test_encodes_pinned_seed_to_exact_uppercase_string(vector: dict[str, str]) -> None:
    assert encode_identity_seed(bytes.fromhex(vector["seed_hex"])) == vector["encoded"]


@pytest.mark.parametrize("vector", _VECTORS, ids=lambda v: v["name"])
def test_parses_both_single_case_forms_back_to_seed(vector: dict[str, str]) -> None:
    # The two pinned forms are the same string in the two valid cases.
    assert vector["encoded_lowercase"] == vector["encoded"].lower()
    assert parse_identity_seed(vector["encoded"]).hex() == vector["seed_hex"]
    assert parse_identity_seed(vector["encoded_lowercase"]).hex() == vector["seed_hex"]


@pytest.mark.parametrize("vector", _VECTORS, ids=lambda v: v["name"])
def test_parses_raw_hex_form(vector: dict[str, str]) -> None:
    assert parse_identity_seed(vector["seed_hex"]).hex() == vector["seed_hex"]


@pytest.mark.parametrize("vector", _PARSE_VECTORS, ids=lambda v: v["name"])
def test_accepts_tolerated_hex_input(vector: dict[str, str]) -> None:
    assert parse_identity_seed(vector["input"]).hex() == vector["expected_seed_hex"]


@pytest.mark.parametrize("vector", _NEGATIVE_VECTORS, ids=lambda v: v["name"])
def test_rejects_with_pinned_error_code(vector: dict[str, str]) -> None:
    with pytest.raises(SeedEncodingError) as excinfo:
        parse_identity_seed(vector["input"])
    assert excinfo.value.code == vector["expected_error_code"]


@pytest.mark.parametrize("length", [0, 31, 33])
def test_encode_rejects_wrong_seed_length(length: int) -> None:
    with pytest.raises(SeedEncodingError) as excinfo:
        encode_identity_seed(b"\x00" * length)
    assert excinfo.value.code == SeedEncodingError.INVALID_SEED_LENGTH
