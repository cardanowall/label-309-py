from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING

from cardanowall._crypto.hash import (
    blake2b_256,
    dual_hash,
    dual_hash_stream,
    sha256,
)

if TYPE_CHECKING:
    from collections.abc import Iterator


FIXTURES_DIR = Path(__file__).parent / "fixtures" / "hash"


def _load_json(name: str) -> dict[str, object]:
    data: dict[str, object] = json.loads((FIXTURES_DIR / name).read_text())
    return data


def test_sha256_kat() -> None:
    corpus = _load_json("sha256-kat.json")
    vectors = corpus["vectors"]
    assert isinstance(vectors, list)
    for vector in vectors:
        assert isinstance(vector, dict)
        input_hex = vector["input_hex"]
        expected_hex = vector["expected_hex"]
        assert isinstance(input_hex, str)
        assert isinstance(expected_hex, str)
        actual = sha256(bytes.fromhex(input_hex)).hex()
        assert actual == expected_hex, vector["name"]


def test_blake2b256_kat() -> None:
    corpus = _load_json("blake2b256-kat.json")
    vectors = corpus["vectors"]
    assert isinstance(vectors, list)
    for vector in vectors:
        assert isinstance(vector, dict)
        input_hex = vector["input_hex"]
        expected_hex = vector["expected_hex"]
        assert isinstance(input_hex, str)
        assert isinstance(expected_hex, str)
        actual = blake2b_256(bytes.fromhex(input_hex)).hex()
        assert actual == expected_hex, vector["name"]


def test_dual_hash_in_memory() -> None:
    corpus = _load_json("dual-hash-equivalence.json")
    vectors = corpus["vectors"]
    assert isinstance(vectors, list)
    for vector in vectors:
        assert isinstance(vector, dict)
        input_hex = vector["input_hex"]
        expected_sha256_hex = vector["expected_sha256_hex"]
        expected_blake2b256_hex = vector["expected_blake2b256_hex"]
        assert isinstance(input_hex, str)
        assert isinstance(expected_sha256_hex, str)
        assert isinstance(expected_blake2b256_hex, str)
        result = dual_hash(bytes.fromhex(input_hex))
        assert result["sha256"].hex() == expected_sha256_hex, vector["name"]
        assert result["blake2b256"].hex() == expected_blake2b256_hex, vector["name"]


def _chunkify(data: bytes, chunk_size: int) -> Iterator[bytes]:
    for off in range(0, len(data), chunk_size):
        yield data[off : off + chunk_size]


def test_dual_hash_stream() -> None:
    corpus = _load_json("dual-hash-equivalence.json")
    vectors = corpus["vectors"]
    assert isinstance(vectors, list)
    for vector in vectors:
        assert isinstance(vector, dict)
        input_hex = vector["input_hex"]
        expected_sha256_hex = vector["expected_sha256_hex"]
        expected_blake2b256_hex = vector["expected_blake2b256_hex"]
        assert isinstance(input_hex, str)
        assert isinstance(expected_sha256_hex, str)
        assert isinstance(expected_blake2b256_hex, str)
        data = bytes.fromhex(input_hex)
        result = dual_hash_stream(_chunkify(data, 64))
        assert result["sha256"].hex() == expected_sha256_hex, vector["name"]
        assert result["blake2b256"].hex() == expected_blake2b256_hex, vector["name"]
