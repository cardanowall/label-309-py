from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import cast

import pytest

from cardanowall._crypto.kem import x25519_ecdh, x25519_public_key
from cardanowall._crypto.mlkem768x25519 import (
    xwing_decapsulate,
    xwing_encapsulate,
    xwing_keygen,
)

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "kem"


def _load_json(name: str) -> dict[str, object]:
    data: dict[str, object] = json.loads((FIXTURES_DIR / name).read_text())
    return data


def _vectors(name: str) -> list[dict[str, str]]:
    corpus = _load_json(name)
    vectors = corpus["vectors"]
    assert isinstance(vectors, list)
    out: list[dict[str, str]] = []
    for vector in vectors:
        assert isinstance(vector, dict)
        out.append(cast(dict[str, str], vector))
    return out


def test_x25519_rfc7748_kat() -> None:
    corpus = _load_json("x25519-rfc7748-kat.json")
    vectors = corpus["vectors"]
    assert isinstance(vectors, list)
    for vector in vectors:
        assert isinstance(vector, dict)
        alice_secret_hex = vector["alice_secret_hex"]
        expected_alice_public_hex = vector["expected_alice_public_hex"]
        bob_secret_hex = vector["bob_secret_hex"]
        expected_bob_public_hex = vector["expected_bob_public_hex"]
        expected_shared_secret_hex = vector["expected_shared_secret_hex"]
        name = vector["name"]
        assert isinstance(alice_secret_hex, str)
        assert isinstance(expected_alice_public_hex, str)
        assert isinstance(bob_secret_hex, str)
        assert isinstance(expected_bob_public_hex, str)
        assert isinstance(expected_shared_secret_hex, str)
        assert isinstance(name, str)

        alice_secret = bytes.fromhex(alice_secret_hex)
        bob_secret = bytes.fromhex(bob_secret_hex)

        alice_pub = x25519_public_key(alice_secret)
        assert alice_pub.hex() == expected_alice_public_hex, name

        bob_pub = x25519_public_key(bob_secret)
        assert bob_pub.hex() == expected_bob_public_hex, name

        shared_from_alice = x25519_ecdh(alice_secret, bob_pub)
        assert shared_from_alice.hex() == expected_shared_secret_hex, name

        shared_from_bob = x25519_ecdh(bob_secret, alice_pub)
        assert shared_from_bob.hex() == expected_shared_secret_hex, name


def test_x25519_roundtrip() -> None:
    corpus = _load_json("x25519-roundtrip.json")
    vectors = corpus["vectors"]
    assert isinstance(vectors, list)
    for vector in vectors:
        assert isinstance(vector, dict)
        alice_secret_hex = vector["alice_secret_hex"]
        expected_alice_public_hex = vector["expected_alice_public_hex"]
        bob_secret_hex = vector["bob_secret_hex"]
        expected_bob_public_hex = vector["expected_bob_public_hex"]
        expected_shared_secret_hex = vector["expected_shared_secret_hex"]
        name = vector["name"]
        assert isinstance(alice_secret_hex, str)
        assert isinstance(expected_alice_public_hex, str)
        assert isinstance(bob_secret_hex, str)
        assert isinstance(expected_bob_public_hex, str)
        assert isinstance(expected_shared_secret_hex, str)
        assert isinstance(name, str)

        alice_secret = bytes.fromhex(alice_secret_hex)
        bob_secret = bytes.fromhex(bob_secret_hex)

        alice_pub = x25519_public_key(alice_secret)
        assert alice_pub.hex() == expected_alice_public_hex, name

        bob_pub = x25519_public_key(bob_secret)
        assert bob_pub.hex() == expected_bob_public_hex, name

        shared_from_alice = x25519_ecdh(alice_secret, bob_pub)
        assert shared_from_alice.hex() == expected_shared_secret_hex, name

        shared_from_bob = x25519_ecdh(bob_secret, alice_pub)
        assert shared_from_bob.hex() == expected_shared_secret_hex, name


def test_x25519_validation_rejects_small_order() -> None:
    corpus = _load_json("x25519-validation.json")
    vectors = corpus["vectors"]
    assert isinstance(vectors, list)
    for vector in vectors:
        assert isinstance(vector, dict)
        secret_key_hex = vector["secret_key_hex"]
        peer_public_key_hex = vector["peer_public_key_hex"]
        expected_rejection = vector["expected_rejection"]
        name = vector["name"]
        assert isinstance(secret_key_hex, str)
        assert isinstance(peer_public_key_hex, str)
        assert isinstance(expected_rejection, bool)
        assert isinstance(name, str)
        assert expected_rejection is True, name

        with pytest.raises(Exception):  # noqa: B017 — cryptography raises ValueError on small-order peer pubkeys; broad-scope kept for OpenSSL-version portability
            x25519_ecdh(
                bytes.fromhex(secret_key_hex),
                bytes.fromhex(peer_public_key_hex),
            )


def test_mlkem768x25519_shake_expand_kat() -> None:
    for vector in _vectors("mlkem768x25519-shake-expand-kat.json"):
        seed = bytes.fromhex(vector["seed_hex"])
        expanded = hashlib.shake_256(seed).digest(96)
        assert expanded.hex() == vector["expected_expanded_hex"], vector["name"]


def test_mlkem768x25519_keygen_kat() -> None:
    for vector in _vectors("mlkem768x25519-keygen-kat.json"):
        seed = bytes.fromhex(vector["seed_hex"])
        public_key, secret_seed = xwing_keygen(seed)
        assert public_key.hex() == vector["expected_pk_hex"], vector["name"]
        assert secret_seed.hex() == vector["expected_sk_seed_hex"], vector["name"]
        # V06 secret key IS the 32-byte root seed.
        assert secret_seed == seed, vector["name"]


def test_mlkem768x25519_encapsulate_kat() -> None:
    for vector in _vectors("mlkem768x25519-encaps-kat.json"):
        public_key = bytes.fromhex(vector["pk_hex"])
        eseed = bytes.fromhex(vector["eseed_hex"])
        enc, shared_secret = xwing_encapsulate(public_key, eseed)
        assert enc.hex() == vector["expected_enc_hex"], vector["name"]
        assert shared_secret.hex() == vector["expected_ss_hex"], vector["name"]


def test_mlkem768x25519_decapsulate_kat() -> None:
    for vector in _vectors("mlkem768x25519-decaps-kat.json"):
        secret_seed = bytes.fromhex(vector["sk_seed_hex"])
        enc = bytes.fromhex(vector["enc_hex"])
        shared_secret = xwing_decapsulate(secret_seed, enc)
        assert shared_secret.hex() == vector["expected_ss_hex"], vector["name"]


def test_mlkem768x25519_decapsulate_implicit_rejection_never_raises() -> None:
    # A corrupted ciphertext must NOT raise: ML-KEM-768 implicit rejection
    # returns a pseudorandom but deterministic secret, which the combiner mixes
    # into a (wrong, but well-formed) 32-byte shared secret. This constant-work
    # behaviour is the security property — decapsulation reveals nothing about
    # whether the ciphertext was valid.
    vector = _vectors("mlkem768x25519-decaps-kat.json")[0]
    secret_seed = bytes.fromhex(vector["sk_seed_hex"])
    good_enc = bytes.fromhex(vector["enc_hex"])

    tampered = bytearray(good_enc)
    tampered[0] ^= 0x01
    bad_secret = xwing_decapsulate(secret_seed, bytes(tampered))

    assert len(bad_secret) == 32
    assert bad_secret.hex() != vector["expected_ss_hex"]
    # Deterministic under implicit rejection: same bad ct -> same secret.
    assert bad_secret == xwing_decapsulate(secret_seed, bytes(tampered))


def test_mlkem768x25519_roundtrip_encapsulate_decapsulate() -> None:
    seed = bytes.fromhex(
        "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26"
    )
    public_key, secret_seed = xwing_keygen(seed)
    enc, shared_secret = xwing_encapsulate(public_key)
    recovered = xwing_decapsulate(secret_seed, enc)
    assert recovered == shared_secret
