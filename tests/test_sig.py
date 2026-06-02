from __future__ import annotations

import json
from pathlib import Path

from cardanowall._crypto.sig import (
    get_public_key_ed25519,
    sign_ed25519,
    verify_ed25519,
)

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "sig"


def _load_json(name: str) -> dict[str, object]:
    data: dict[str, object] = json.loads((FIXTURES_DIR / name).read_text())
    return data


def test_ed25519_kat() -> None:
    corpus = _load_json("ed25519-kat.json")
    vectors = corpus["vectors"]
    assert isinstance(vectors, list)
    for vector in vectors:
        assert isinstance(vector, dict)
        seed_hex = vector["seed_hex"]
        message_hex = vector["message_hex"]
        expected_public_key_hex = vector["expected_public_key_hex"]
        expected_signature_hex = vector["expected_signature_hex"]
        name = vector["name"]
        assert isinstance(seed_hex, str)
        assert isinstance(message_hex, str)
        assert isinstance(expected_public_key_hex, str)
        assert isinstance(expected_signature_hex, str)
        assert isinstance(name, str)

        seed = bytes.fromhex(seed_hex)
        message = bytes.fromhex(message_hex)

        pubkey = get_public_key_ed25519(seed)
        assert pubkey.hex() == expected_public_key_hex, name

        signature = sign_ed25519(seed, message)
        assert signature.hex() == expected_signature_hex, name

        assert verify_ed25519(pubkey, message, signature) is True, name


def test_ed25519_roundtrip() -> None:
    corpus = _load_json("ed25519-roundtrip.json")
    vectors = corpus["vectors"]
    assert isinstance(vectors, list)
    for vector in vectors:
        assert isinstance(vector, dict)
        seed_hex = vector["seed_hex"]
        message_hex = vector["message_hex"]
        expected_public_key_hex = vector["expected_public_key_hex"]
        expected_signature_hex = vector["expected_signature_hex"]
        name = vector["name"]
        assert isinstance(seed_hex, str)
        assert isinstance(message_hex, str)
        assert isinstance(expected_public_key_hex, str)
        assert isinstance(expected_signature_hex, str)
        assert isinstance(name, str)

        seed = bytes.fromhex(seed_hex)
        message = bytes.fromhex(message_hex)

        pubkey = get_public_key_ed25519(seed)
        assert pubkey.hex() == expected_public_key_hex, name

        signature = sign_ed25519(seed, message)
        assert signature.hex() == expected_signature_hex, name

        assert verify_ed25519(pubkey, message, signature) is True, name


def test_ed25519_zip215_strict_rejection() -> None:
    corpus = _load_json("ed25519-zip215.json")
    vectors = corpus["vectors"]
    assert isinstance(vectors, list)
    for vector in vectors:
        assert isinstance(vector, dict)
        public_key_hex = vector["public_key_hex"]
        message_hex = vector["message_hex"]
        signature_hex = vector["signature_hex"]
        expected_valid = vector["expected_valid"]
        name = vector["name"]
        assert isinstance(public_key_hex, str)
        assert isinstance(message_hex, str)
        assert isinstance(signature_hex, str)
        assert isinstance(expected_valid, bool)
        assert isinstance(name, str)

        result = verify_ed25519(
            bytes.fromhex(public_key_hex),
            bytes.fromhex(message_hex),
            bytes.fromhex(signature_hex),
        )
        assert result == expected_valid, name


def test_ed25519_torsion_cctv() -> None:
    """Shared KAT: the full C2SP/CCTV ed25519vectors corpus (914 vectors).

    `expected_valid` is the strict (non-cofactored, RFC 8032 §5.1.7)
    consensus shared by PyNaCl/libsodium and ed25519-dalek's verify_strict.
    Python's verify_ed25519 routes through PyNaCl, so every vector must match
    the strict verdict — torsion / small-order / non-canonical points reject.
    """
    corpus = _load_json("ed25519-torsion-cctv.json")
    vectors = corpus["vectors"]
    assert isinstance(vectors, list)
    assert len(vectors) == 914
    for vector in vectors:
        assert isinstance(vector, dict)
        public_key_hex = vector["public_key_hex"]
        message_hex = vector["message_hex"]
        signature_hex = vector["signature_hex"]
        expected_valid = vector["expected_valid"]
        name = vector["name"]
        assert isinstance(public_key_hex, str)
        assert isinstance(message_hex, str)
        assert isinstance(signature_hex, str)
        assert isinstance(expected_valid, bool)
        assert isinstance(name, str)

        result = verify_ed25519(
            bytes.fromhex(public_key_hex),
            bytes.fromhex(message_hex),
            bytes.fromhex(signature_hex),
        )
        assert result == expected_valid, name
