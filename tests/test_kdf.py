from __future__ import annotations

import json
from pathlib import Path

import pytest

from cardanowall._crypto.kdf import (
    PBKDF2_SHA256_ITERATIONS_FLOOR,
    argon2id_v13,
    hkdf_sha256,
    pbkdf2_sha256,
)

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "kdf"


def _load_json(name: str) -> dict[str, object]:
    data: dict[str, object] = json.loads((FIXTURES_DIR / name).read_text())
    return data


def test_hkdf_sha256_kat() -> None:
    corpus = _load_json("hkdf-sha256-kat.json")
    vectors = corpus["vectors"]
    assert isinstance(vectors, list)
    for vector in vectors:
        assert isinstance(vector, dict)
        ikm_hex = vector["ikm_hex"]
        salt_hex = vector["salt_hex"]
        info_hex = vector["info_hex"]
        length = vector["length"]
        expected_hex = vector["expected_hex"]
        assert isinstance(ikm_hex, str)
        assert isinstance(salt_hex, str)
        assert isinstance(info_hex, str)
        assert isinstance(length, int)
        assert isinstance(expected_hex, str)
        actual = hkdf_sha256(
            bytes.fromhex(ikm_hex),
            bytes.fromhex(salt_hex),
            bytes.fromhex(info_hex),
            length,
        ).hex()
        assert actual == expected_hex, vector["name"]


def test_argon2id_v13_kat() -> None:
    corpus = _load_json("argon2id-v13-kat.json")
    vectors = corpus["vectors"]
    assert isinstance(vectors, list)
    for vector in vectors:
        assert isinstance(vector, dict)
        password_hex = vector["password_hex"]
        salt_hex = vector["salt_hex"]
        mem_size_kb = vector["mem_size_kb"]
        iterations = vector["iterations"]
        parallelism = vector["parallelism"]
        out_bytes = vector["out_bytes"]
        expected_hex = vector["expected_hex"]
        assert isinstance(password_hex, str)
        assert isinstance(salt_hex, str)
        assert isinstance(mem_size_kb, int)
        assert isinstance(iterations, int)
        assert isinstance(parallelism, int)
        assert isinstance(out_bytes, int)
        assert isinstance(expected_hex, str)
        actual = argon2id_v13(
            bytes.fromhex(password_hex),
            bytes.fromhex(salt_hex),
            mem_size_kb,
            iterations,
            parallelism,
            out_bytes,
        ).hex()
        assert actual == expected_hex, vector["name"]


def test_pbkdf2_sha256_floor_enforced() -> None:
    with pytest.raises(ValueError, match="below floor"):
        pbkdf2_sha256(b"pw", b"\x00" * 16, PBKDF2_SHA256_ITERATIONS_FLOOR - 1, 32)


def test_pbkdf2_sha256_deterministic_default_out() -> None:
    salt = b"\x01" * 16
    a = pbkdf2_sha256(b"passphrase", salt, PBKDF2_SHA256_ITERATIONS_FLOOR)
    b = pbkdf2_sha256(b"passphrase", salt, PBKDF2_SHA256_ITERATIONS_FLOOR)
    assert a == b
    assert len(a) == 32


def test_pbkdf2_sha256_differs_on_different_inputs() -> None:
    salt = b"\x02" * 16
    a = pbkdf2_sha256(b"pw1", salt, PBKDF2_SHA256_ITERATIONS_FLOOR)
    b = pbkdf2_sha256(b"pw2", salt, PBKDF2_SHA256_ITERATIONS_FLOOR)
    c = pbkdf2_sha256(b"pw1", b"\x03" * 16, PBKDF2_SHA256_ITERATIONS_FLOOR)
    assert a != b
    assert a != c
