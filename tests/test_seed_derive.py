from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

import pytest

from cardanowall._crypto.seed_derive import (
    SeedDeriveError,
    derive_ed25519_keypair_from_seed,
    derive_mlkem768x25519_keypair_from_seed,
    derive_x25519_keypair_from_seed,
)

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "seed-derive"


def _load_corpus(name: str) -> list[dict[str, Any]]:
    data = json.loads((FIXTURES_DIR / name).read_text())
    return cast(list[dict[str, Any]], data["vectors"])


def _hamming(a: bytes, b: bytes) -> int:
    assert len(a) == len(b), "hamming length mismatch"
    return sum(bin(x ^ y).count("1") for x, y in zip(a, b, strict=True))


def _check_seed_corpus(corpus_name: str) -> None:
    vectors = _load_corpus(corpus_name)
    assert len(vectors) >= 1
    for vector in vectors:
        seed = bytes.fromhex(str(vector["seed_hex"]))

        ed = derive_ed25519_keypair_from_seed(seed)
        assert ed["secret_key"].hex() == vector["expected_ed25519_secret_hex"], vector["name"]
        assert ed["public_key"].hex() == vector["expected_ed25519_public_hex"], vector["name"]

        x = derive_x25519_keypair_from_seed(seed)
        assert x["secret_key"].hex() == vector["expected_x25519_secret_hex"], vector["name"]
        assert x["public_key"].hex() == vector["expected_x25519_public_hex"], vector["name"]

        mlkem = derive_mlkem768x25519_keypair_from_seed(seed)
        assert mlkem["secret_seed"].hex() == vector["expected_mlkem768x25519_secret_seed_hex"], (
            vector["name"]
        )
        assert mlkem["public_key"].hex() == vector["expected_mlkem768x25519_public_key_hex"], (
            vector["name"]
        )


def test_seed_derive_kat_zero() -> None:
    _check_seed_corpus("seed-from-zero.json")


def test_seed_derive_kat_ff() -> None:
    _check_seed_corpus("seed-from-ff.json")


def test_seed_derive_kat_deadbeef() -> None:
    _check_seed_corpus("seed-from-deadbeef.json")


def test_seed_derive_negative_invalid_length() -> None:
    vectors = _load_corpus("seed-derive-negative.json")
    assert len(vectors) >= 6
    for vector in vectors:
        seed = bytes.fromhex(str(vector["seed_hex"]))
        for fn in (
            derive_ed25519_keypair_from_seed,
            derive_x25519_keypair_from_seed,
        ):
            with pytest.raises(SeedDeriveError) as exc_info:
                fn(seed)
            assert exc_info.value.code == vector["expected_error_code"], (
                f"{vector['name']}: {fn.__name__}"
            )


def test_seed_derive_avalanche() -> None:
    for corpus_name in ("seed-from-zero.json", "seed-from-ff.json", "seed-from-deadbeef.json"):
        vectors = _load_corpus(corpus_name)
        for vector in vectors:
            seed = bytes.fromhex(str(vector["seed_hex"]))
            seed_flipped = bytes([seed[0] ^ 0x01]) + seed[1:]

            ed_a = derive_ed25519_keypair_from_seed(seed)
            ed_b = derive_ed25519_keypair_from_seed(seed_flipped)
            x_a = derive_x25519_keypair_from_seed(seed)
            x_b = derive_x25519_keypair_from_seed(seed_flipped)

            pairs = [
                (ed_a["secret_key"], ed_b["secret_key"]),
                (ed_a["public_key"], ed_b["public_key"]),
                (x_a["secret_key"], x_b["secret_key"]),
                (x_a["public_key"], x_b["public_key"]),
            ]
            for a, b in pairs:
                distance = _hamming(a, b)
                assert 96 <= distance <= 160, (
                    f"{vector['name']}: hamming {distance} out of [96, 160]"
                )
