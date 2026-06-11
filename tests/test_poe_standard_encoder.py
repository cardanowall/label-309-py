from __future__ import annotations

from cardanowall._crypto.cbor import decode_canonical_cbor
from cardanowall.poe_standard import (
    PoeRecord,
    ValidateOk,
    encode_poe_record,
    encode_record_body_for_signing,
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


def test_encode_uri_as_single_text_string() -> None:
    # A URI longer than 64 bytes is still ONE text string in the record body —
    # the ledger's per-string cap applies to the transport chunk array, never
    # to fields inside the reassembled body.
    long_uri = "ipfs://QmbFMke1KXqnYyBBWxB74N4c5SBnJMVAiMNRcGu6x1AwQH/release/artifacts/file.bin"
    record: PoeRecord = {
        "v": 1,
        "items": [
            {
                "hashes": {"sha2-256": b"\x11" * 32},
                "uris": [long_uri],
            }
        ],
    }
    encoded = encode_poe_record(record)
    decoded = decode_canonical_cbor(encoded)
    assert isinstance(decoded, dict)
    assert decoded["items"][0]["uris"] == [long_uri]
    assert isinstance(validate(encoded), ValidateOk)


def test_encode_sigs_entry_as_single_byte_string() -> None:
    blob = b"\xee" * 200
    record: PoeRecord = {
        "v": 1,
        "items": [{"hashes": {"sha2-256": b"\x22" * 32}}],
        "sigs": [{"cose_sign1": blob}],
    }
    encoded = encode_poe_record(record)
    decoded = decode_canonical_cbor(encoded)
    assert isinstance(decoded, dict)
    sigs = decoded["sigs"]
    assert isinstance(sigs, list) and len(sigs) == 1
    assert sigs[0]["cose_sign1"] == blob


def test_encode_with_cose_key_sidecar() -> None:
    cose_key_blob = b"\xa4\x01\x01\x03\x27\x20\x06\x21\x58\x20" + b"\xab" * 32
    record: PoeRecord = {
        "v": 1,
        "items": [{"hashes": {"sha2-256": b"\x33" * 32}}],
        "sigs": [
            {
                "cose_sign1": b"\x00" * 64,
                "cose_key": cose_key_blob,
            }
        ],
    }
    encoded = encode_poe_record(record)
    decoded = decode_canonical_cbor(encoded)
    assert isinstance(decoded, dict)
    assert decoded["sigs"][0]["cose_key"] == cose_key_blob


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


def test_signing_body_strips_sigs_and_nothing_else() -> None:
    record: PoeRecord = {
        "v": 1,
        "items": [{"hashes": {"sha2-256": b"\x22" * 32}}],
        "sigs": [{"cose_sign1": b"\x00" * 64}],
    }
    body = decode_canonical_cbor(encode_record_body_for_signing(record))
    assert isinstance(body, dict)
    assert "sigs" not in body
    assert body["v"] == 1
    assert body["items"][0]["hashes"]["sha2-256"] == b"\x22" * 32
