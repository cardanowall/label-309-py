from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

import cbor2
import pytest

from cardanowall._crypto.cbor import (
    CanonicalCborError,
    CanonicalCborValue,
    decode_canonical_cbor,
    decode_cbor_permissive,
    encode_canonical_cbor,
)

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "cbor"


def _load_corpus(name: str) -> list[dict[str, Any]]:
    data = json.loads((FIXTURES_DIR / name).read_text())
    vectors = cast(list[dict[str, Any]], data["vectors"])
    return vectors


def _reify_value(vector: dict[str, Any]) -> Any:
    spec = vector.get("input_value_spec")
    if isinstance(spec, dict):
        if spec.get("type") == "bytes":
            return bytes.fromhex(str(spec["hex"]))
        if spec.get("type") == "bigint":
            return int(str(spec["decimal"]))
    return json.loads(str(vector["input_json"]))


def test_canonical_encode_rfc8949_kat() -> None:
    vectors = _load_corpus("canonical-encode-rfc8949-kat.json")
    assert len(vectors) > 0
    for vector in vectors:
        value = _reify_value(vector)
        encoded = encode_canonical_cbor(value)
        assert encoded.hex() == vector["expected_cbor_hex"], (
            f"{vector['name']}: encoded hex mismatch"
        )


def test_canonical_encode_roundtrip() -> None:
    vectors = _load_corpus("canonical-encode-roundtrip.json")
    assert len(vectors) > 0
    for vector in vectors:
        value = _reify_value(vector)
        encoded = encode_canonical_cbor(value)
        assert encoded.hex() == vector["expected_cbor_hex"]
        decoded = decode_canonical_cbor(bytes.fromhex(str(vector["expected_cbor_hex"])))
        recovered = cast(CanonicalCborValue, decoded)
        assert encode_canonical_cbor(recovered).hex() == vector["expected_cbor_hex"]


def test_decode_indefinite_length_rejected() -> None:
    # Indefinite-length items reject under the single public taxonomy code
    # MALFORMED_CBOR; the specific cause survives in the human-readable message.
    vectors = [
        v
        for v in _load_corpus("canonical-decode-negative.json")
        if str(v.get("name", "")).startswith("indefinite-")
    ]
    assert len(vectors) >= 4
    for vector in vectors:
        with pytest.raises(CanonicalCborError) as exc_info:
            decode_canonical_cbor(bytes.fromhex(str(vector["cbor_hex"])))
        assert exc_info.value.code == "MALFORMED_CBOR", f"{vector['name']}: wrong error code"
        assert "indefinite" in str(exc_info.value).lower(), (
            f"{vector['name']}: message should name the indefinite-length cause"
        )


def test_decode_noncanonical_map_rejected() -> None:
    # A canonical decoder MUST reject BOTH duplicate keys AND non-canonical
    # (distinct-but-unsorted) key ordering (RFC 8949 §4.2.1). Both fold into the
    # single MALFORMED_CBOR code; the unsorted-distinct case is the one the
    # prior `MAP_DUPLICATE_KEY` pre-scan silently let through.
    vectors = [
        v
        for v in _load_corpus("canonical-decode-negative.json")
        if v.get("expected_error_code") == "MALFORMED_CBOR"
        and (
            str(v.get("name", "")).startswith("duplicate-keys")
            or str(v.get("name", "")).startswith("unsorted-distinct-keys")
        )
    ]
    dup = [v for v in vectors if str(v["name"]).startswith("duplicate-keys")]
    unsorted = [v for v in vectors if str(v["name"]).startswith("unsorted-distinct-keys")]
    assert len(dup) >= 3
    assert len(unsorted) >= 2
    for vector in vectors:
        with pytest.raises(CanonicalCborError) as exc_info:
            decode_canonical_cbor(bytes.fromhex(str(vector["cbor_hex"])))
        assert exc_info.value.code == "MALFORMED_CBOR", f"{vector['name']}: wrong error code"


def test_decode_malformed_rejected() -> None:
    vectors = [
        v
        for v in _load_corpus("canonical-decode-negative.json")
        if v.get("expected_error_code") == "MALFORMED_CBOR"
    ]
    assert len(vectors) >= 1
    for vector in vectors:
        with pytest.raises(CanonicalCborError) as exc_info:
            decode_canonical_cbor(bytes.fromhex(str(vector["cbor_hex"])))
        assert exc_info.value.code == "MALFORMED_CBOR", f"{vector['name']}: wrong error code"


def test_decode_cbor_permissive_canonical_shape() -> None:
    tx_like: list[Any] = [{"a": 1}, {"b": 2}, True, {0: {309: b"\x01\x02"}}]
    encoded = cbor2.dumps(tx_like)
    decoded = decode_cbor_permissive(encoded)
    assert isinstance(decoded, list)
    assert len(decoded) == 4
    assert decoded[2] is True
    assert decoded[3][0][309] == b"\x01\x02"


def test_decode_cbor_permissive_equals_canonical_when_canonical() -> None:
    value: CanonicalCborValue = {"a": 1, "b": [1, 2, 3]}
    encoded = encode_canonical_cbor(value)
    permissive = decode_cbor_permissive(encoded)
    canonical = decode_canonical_cbor(encoded)
    assert permissive == canonical


def test_decode_cbor_permissive_accepts_indefinite_length() -> None:
    # 0x9f ... 0xff = indefinite-length array — canonical decoder rejects, permissive accepts.
    indefinite = bytes.fromhex("9f0102ff")
    permissive = decode_cbor_permissive(indefinite)
    assert permissive == [1, 2]


def test_decode_cbor_permissive_propagates_malformed() -> None:
    # 0x5b = bytes with 8-byte length prefix; not enough following bytes -> decode error.
    with pytest.raises(cbor2.CBORDecodeError):
        decode_cbor_permissive(b"\x5b\x00\x00")
