from __future__ import annotations

from cardanowall._crypto.cbor import decode_canonical_cbor
from cardanowall.poe_standard import (
    PoeRecord,
    ValidateOk,
    chunk_bytes,
    encode_poe_record,
    validate,
)


def _minimal() -> PoeRecord:
    return {"v": 1, "items": [{"hashes": {"sha2-256": b"\x00" * 32}}]}


def test_encode_minimal_roundtrip_via_validator() -> None:
    record = _minimal()
    encoded = encode_poe_record(record)
    res = validate(encoded)
    assert isinstance(res, ValidateOk)
    assert res.record == record


def test_encode_with_uri_chunks() -> None:
    record: PoeRecord = {
        "v": 1,
        "items": [
            {
                "hashes": {"sha2-256": b"\x11" * 32},
                "uris": [
                    ["ar://", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],
                ],
            }
        ],
    }
    encoded = encode_poe_record(record)
    decoded = decode_canonical_cbor(encoded)
    assert isinstance(decoded, dict)
    items = decoded["items"]
    assert isinstance(items, list) and len(items) == 1
    assert items[0]["uris"] == [["ar://", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]]


def test_encode_with_sigs_chunked_bytes() -> None:
    long_blob = b"\xee" * 200
    record: PoeRecord = {
        "v": 1,
        "items": [{"hashes": {"sha2-256": b"\x22" * 32}}],
        "sigs": [{"cose_sign1": chunk_bytes(long_blob)}],
    }
    encoded = encode_poe_record(record)
    decoded = decode_canonical_cbor(encoded)
    assert isinstance(decoded, dict)
    sigs = decoded["sigs"]
    assert isinstance(sigs, list) and len(sigs) == 1
    chunks = sigs[0]["cose_sign1"]
    flat = b"".join(c for c in chunks if isinstance(c, bytes))
    assert flat == long_blob


def test_encode_with_cose_key_sidecar() -> None:
    cose_key_blob = b"\xa4\x01\x01\x03\x27\x20\x06\x21\x58\x20" + b"\xab" * 32
    record: PoeRecord = {
        "v": 1,
        "items": [{"hashes": {"sha2-256": b"\x33" * 32}}],
        "sigs": [
            {
                "cose_sign1": [b"\x00" * 64],
                "cose_key": chunk_bytes(cose_key_blob),
            }
        ],
    }
    encoded = encode_poe_record(record)
    decoded = decode_canonical_cbor(encoded)
    assert isinstance(decoded, dict)
    assert "cose_key" in decoded["sigs"][0]
    assert b"".join(decoded["sigs"][0]["cose_key"]) == cose_key_blob


def test_encode_omits_optional_fields_when_absent() -> None:
    encoded = encode_poe_record(_minimal())
    decoded = decode_canonical_cbor(encoded)
    assert isinstance(decoded, dict)
    for absent in ("sigs", "supersedes", "merkle", "crit"):
        assert absent not in decoded


def test_encode_with_merkle_commit() -> None:
    record: PoeRecord = {
        "v": 1,
        "merkle": [
            {
                "alg": "rfc9162-sha256",
                "root": b"\x00" * 32,
                "leaf_count": 4,
            }
        ],
    }
    encoded = encode_poe_record(record)
    res = validate(encoded)
    assert isinstance(res, ValidateOk)
    assert res.record == record
