from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from pathlib import Path

import pytest

from cardanowall._crypto.aead import (
    AeadVerificationError,
    chacha20_poly1305_decrypt,
    chacha20_poly1305_encrypt,
    xchacha20_poly1305_decrypt,
    xchacha20_poly1305_encrypt,
)

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "aead"


def _load_json(name: str) -> dict[str, object]:
    data: dict[str, object] = json.loads((FIXTURES_DIR / name).read_text())
    return data


def _run_chacha20_kat(corpus_name: str) -> None:
    corpus = _load_json(corpus_name)
    vectors = corpus["vectors"]
    assert isinstance(vectors, list)
    for vector in vectors:
        assert isinstance(vector, dict)
        name = vector["name"]
        key_hex = vector["key_hex"]
        nonce_hex = vector["nonce_hex"]
        aad_hex = vector["aad_hex"]
        plaintext_hex = vector["plaintext_hex"]
        expected_hex = vector["expected_ciphertext_with_tag_hex"]
        assert isinstance(name, str)
        assert isinstance(key_hex, str)
        assert isinstance(nonce_hex, str)
        assert isinstance(aad_hex, str)
        assert isinstance(plaintext_hex, str)
        assert isinstance(expected_hex, str)

        key = bytes.fromhex(key_hex)
        nonce = bytes.fromhex(nonce_hex)
        aad = bytes.fromhex(aad_hex)
        plaintext = bytes.fromhex(plaintext_hex)
        expected = bytes.fromhex(expected_hex)

        ct = chacha20_poly1305_encrypt(key, nonce, aad, plaintext)
        assert ct.hex() == expected_hex, name

        recovered = chacha20_poly1305_decrypt(key, nonce, aad, expected)
        assert recovered.hex() == plaintext_hex, name


def _run_xchacha20_kat(corpus_name: str) -> None:
    corpus = _load_json(corpus_name)
    vectors = corpus["vectors"]
    assert isinstance(vectors, list)
    for vector in vectors:
        assert isinstance(vector, dict)
        name = vector["name"]
        key_hex = vector["key_hex"]
        nonce_hex = vector["nonce_hex"]
        aad_hex = vector["aad_hex"]
        plaintext_hex = vector["plaintext_hex"]
        expected_hex = vector["expected_ciphertext_with_tag_hex"]
        assert isinstance(name, str)
        assert isinstance(key_hex, str)
        assert isinstance(nonce_hex, str)
        assert isinstance(aad_hex, str)
        assert isinstance(plaintext_hex, str)
        assert isinstance(expected_hex, str)

        key = bytes.fromhex(key_hex)
        nonce = bytes.fromhex(nonce_hex)
        aad = bytes.fromhex(aad_hex)
        plaintext = bytes.fromhex(plaintext_hex)
        expected = bytes.fromhex(expected_hex)

        ct = xchacha20_poly1305_encrypt(key, nonce, aad, plaintext)
        assert ct.hex() == expected_hex, name

        recovered = xchacha20_poly1305_decrypt(key, nonce, aad, expected)
        assert recovered.hex() == plaintext_hex, name


def test_chacha20_poly1305_rfc8439_kat() -> None:
    _run_chacha20_kat("chacha20-poly1305-rfc8439-kat.json")


def test_chacha20_poly1305_roundtrip() -> None:
    _run_chacha20_kat("chacha20-poly1305-roundtrip.json")


def test_xchacha20_poly1305_draft_kat() -> None:
    _run_xchacha20_kat("xchacha20-poly1305-draft-irtf-cfrg-xchacha-03-kat.json")


def test_xchacha20_poly1305_roundtrip() -> None:
    _run_xchacha20_kat("xchacha20-poly1305-roundtrip.json")


def _seed_bytes(label: str, length: int) -> bytes:
    return hashlib.sha256(label.encode("utf-8")).digest()[:length]


def _flip_byte(b: bytes, index: int) -> bytes:
    arr = bytearray(b)
    arr[index] = arr[index] ^ 0x01
    return bytes(arr)


def test_chacha20_poly1305_tamper_raises() -> None:
    key = _seed_bytes("cardanowall-aead-tamper-key-2-5", 32)
    nonce = _seed_bytes("cardanowall-aead-tamper-nonce-2-5", 12)
    aad = b"cardano-poe-kek-v1"
    plaintext = b"sealed-poe tamper-test plaintext - 2-5 - deterministic"

    ct = chacha20_poly1305_encrypt(key, nonce, aad, plaintext)
    assert chacha20_poly1305_decrypt(key, nonce, aad, ct) == plaintext

    mutations: list[tuple[str, Callable[[], bytes]]] = [
        (
            "ciphertext body byte 0",
            lambda: chacha20_poly1305_decrypt(key, nonce, aad, _flip_byte(ct, 0)),
        ),
        (
            "tag last byte",
            lambda: chacha20_poly1305_decrypt(key, nonce, aad, _flip_byte(ct, len(ct) - 1)),
        ),
        ("nonce mutated", lambda: chacha20_poly1305_decrypt(key, _flip_byte(nonce, 5), aad, ct)),
        ("aad mutated", lambda: chacha20_poly1305_decrypt(key, nonce, _flip_byte(aad, 0), ct)),
        ("key mutated", lambda: chacha20_poly1305_decrypt(_flip_byte(key, 0), nonce, aad, ct)),
        ("truncated ciphertext", lambda: chacha20_poly1305_decrypt(key, nonce, aad, ct[:-1])),
    ]

    for description, call in mutations:
        with pytest.raises(AeadVerificationError) as exc_info:
            call()
        assert exc_info.value.code == "aead_verification_failed", description


def test_xchacha20_poly1305_tamper_raises() -> None:
    key = _seed_bytes("cardanowall-aead-tamper-key-2-5", 32)
    nonce = _seed_bytes("cardanowall-aead-tamper-nonce-2-5-xchacha", 24)
    aad = b"cardano-poe-kek-v1"
    plaintext = b"sealed-poe tamper-test plaintext - 2-5 - deterministic - xchacha variant"

    ct = xchacha20_poly1305_encrypt(key, nonce, aad, plaintext)
    assert xchacha20_poly1305_decrypt(key, nonce, aad, ct) == plaintext

    mutations: list[tuple[str, Callable[[], bytes]]] = [
        (
            "ciphertext body byte 0",
            lambda: xchacha20_poly1305_decrypt(key, nonce, aad, _flip_byte(ct, 0)),
        ),
        (
            "tag last byte",
            lambda: xchacha20_poly1305_decrypt(key, nonce, aad, _flip_byte(ct, len(ct) - 1)),
        ),
        ("nonce mutated", lambda: xchacha20_poly1305_decrypt(key, _flip_byte(nonce, 5), aad, ct)),
        ("aad mutated", lambda: xchacha20_poly1305_decrypt(key, nonce, _flip_byte(aad, 0), ct)),
        ("key mutated", lambda: xchacha20_poly1305_decrypt(_flip_byte(key, 0), nonce, aad, ct)),
        ("truncated ciphertext", lambda: xchacha20_poly1305_decrypt(key, nonce, aad, ct[:-1])),
    ]

    for description, call in mutations:
        with pytest.raises(AeadVerificationError) as exc_info:
            call()
        assert exc_info.value.code == "aead_verification_failed", description
