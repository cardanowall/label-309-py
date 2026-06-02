from __future__ import annotations

from cardanowall._crypto.cbor import encode_canonical_cbor
from cardanowall._crypto.cose_key import parse_cose_key_ed25519

PUB = b"\xab" * 32


def test_canonical_cose_key_returns_x() -> None:
    blob = encode_canonical_cbor({1: 1, 3: -8, -1: 6, -2: PUB})
    assert parse_cose_key_ed25519(blob) == PUB


def test_alg_optional_when_omitted() -> None:
    blob = encode_canonical_cbor({1: 1, -1: 6, -2: PUB})
    assert parse_cose_key_ed25519(blob) == PUB


def test_rejects_wrong_kty_ec2_instead_of_okp() -> None:
    blob = encode_canonical_cbor({1: 2, 3: -8, -1: 6, -2: PUB})
    assert parse_cose_key_ed25519(blob) is None


def test_rejects_wrong_crv_x25519_instead_of_ed25519() -> None:
    blob = encode_canonical_cbor({1: 1, 3: -8, -1: 4, -2: PUB})
    assert parse_cose_key_ed25519(blob) is None


def test_rejects_wrong_alg_es256_instead_of_eddsa() -> None:
    blob = encode_canonical_cbor({1: 1, 3: -7, -1: 6, -2: PUB})
    assert parse_cose_key_ed25519(blob) is None


def test_rejects_missing_x() -> None:
    blob = encode_canonical_cbor({1: 1, 3: -8, -1: 6})
    assert parse_cose_key_ed25519(blob) is None


def test_rejects_wrong_x_length() -> None:
    blob = encode_canonical_cbor({1: 1, 3: -8, -1: 6, -2: b"\xab" * 31})
    assert parse_cose_key_ed25519(blob) is None


def test_rejects_garbage_cbor() -> None:
    assert parse_cose_key_ed25519(b"\xff\xff\xff") is None


def test_rejects_non_map() -> None:
    blob = encode_canonical_cbor([1, 2, 3])
    assert parse_cose_key_ed25519(blob) is None
