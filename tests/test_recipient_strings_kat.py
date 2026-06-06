"""Byte-exact known-answer test for the age recipient codec.

Driven by the shared conformance fixture
``seed-derive/recipient-strings-kat.json`` (the same JSON the TypeScript and Rust
SDKs consume), which pins, for both KEMs, a raw public key and the exact Bech32
string it must encode to and decode back from. Passing this proves the Python
codec addresses the same identities with the same strings on the wire, and that
it validates the HRP exactly: HRP ``age`` renders the visible ``age1...`` prefix
and HRP ``age1pqc`` renders ``age1pqc1...`` (the leading ``1`` is the Bech32
separator, not part of the HRP).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from cardanowall.recipient import (
    bech32_encode_no_limit,
    encode_age_x25519_recipient,
    encode_age_xwing_recipient,
    parse_age_recipient,
)

_FIXTURE = Path(__file__).parent / "fixtures" / "seed-derive" / "recipient-strings-kat.json"
_VECTORS = json.loads(_FIXTURE.read_text())["vectors"]


def _encode(kem: str, public_key: bytes) -> str:
    if kem == "x25519":
        return encode_age_x25519_recipient(public_key)
    return encode_age_xwing_recipient(public_key)


def test_fixture_carries_both_kems() -> None:
    kems = {v["kem"] for v in _VECTORS}
    assert "x25519" in kems
    assert "mlkem768x25519" in kems


@pytest.mark.parametrize("vector", _VECTORS, ids=lambda v: v["name"])
def test_encodes_pinned_key_to_exact_string(vector: dict[str, str]) -> None:
    public_key = bytes.fromhex(vector["public_key_hex"])
    assert _encode(vector["kem"], public_key) == vector["recipient"]


@pytest.mark.parametrize("vector", _VECTORS, ids=lambda v: v["name"])
def test_decodes_pinned_string_to_exact_key_and_kem(vector: dict[str, str]) -> None:
    parsed = parse_age_recipient(vector["recipient"])
    assert parsed.kem == vector["kem"]
    assert parsed.public_key.hex() == vector["public_key_hex"]


@pytest.mark.parametrize("vector", _VECTORS, ids=lambda v: v["name"])
def test_renders_visible_prefix_the_hrp_implies(vector: dict[str, str]) -> None:
    visible_prefix = "age1" if vector["kem"] == "x25519" else "age1pqc1"
    assert vector["recipient"].startswith(visible_prefix)


def test_rejects_age1pqc_string_carrying_x25519_length_key() -> None:
    # HRP is validated exactly: a checksum-valid string under the hybrid HRP that
    # carries a 32-byte payload must be rejected, not mis-routed to x25519.
    x25519_vector = next(v for v in _VECTORS if v["kem"] == "x25519")
    x25519_key = bytes.fromhex(x25519_vector["public_key_hex"])
    hybrid_hrp_short_key = bech32_encode_no_limit("age1pqc", x25519_key)
    assert hybrid_hrp_short_key.startswith("age1pqc1")
    with pytest.raises(ValueError, match="1216-byte"):
        parse_age_recipient(hybrid_hrp_short_key)


def test_rejects_unrecognized_hrp() -> None:
    x25519_vector = next(v for v in _VECTORS if v["kem"] == "x25519")
    x25519_key = bytes.fromhex(x25519_vector["public_key_hex"])
    unknown_hrp = bech32_encode_no_limit("xyz", x25519_key)
    with pytest.raises(ValueError, match="unrecognized recipient prefix"):
        parse_age_recipient(unknown_hrp)
