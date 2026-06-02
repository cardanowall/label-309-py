"""Parser parity for age-style recipient strings (twin of the TS parse test).

Decoding must be the exact inverse of the encoders. Parsing the canonical ``age``
strings pinned in the shared cross-language fixture must recover the exact raw
public key + the KEM the HRP implies. The fixture stores the X-Wing recipient
only as a prefix (the full string is ~1960 chars), so the X-Wing case is pinned
by re-deriving the key from the seed, encoding it, asserting it extends the
pinned prefix, and round-tripping it back through the parser.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from cardanowall import derive_mlkem768x25519_keypair_from_seed
from cardanowall.recipient import (
    bech32_encode_no_limit,
    encode_age_x25519_recipient,
    encode_age_xwing_recipient,
    parse_age_recipient,
)

_FIXTURE = Path(__file__).parent / "fixtures" / "seed-derive" / "recipients.json"
_VECTORS = json.loads(_FIXTURE.read_text())["vectors"]


def test_round_trips_encode_then_parse_for_both_kems() -> None:
    x_pub = bytes([7]) * 32
    q_pub = bytes([9]) * 1216

    x = parse_age_recipient(encode_age_x25519_recipient(x_pub))
    assert x.kem == "x25519" and x.public_key == x_pub

    q = parse_age_recipient(encode_age_xwing_recipient(q_pub))
    assert q.kem == "mlkem768x25519" and q.public_key == q_pub


@pytest.mark.parametrize("vector", _VECTORS, ids=lambda v: v["name"])
def test_decodes_pinned_age_strings_to_x25519_key(vector: dict[str, str]) -> None:
    parsed = parse_age_recipient(vector["age"])
    assert parsed.kem == "x25519"
    assert parsed.public_key.hex() == vector["x25519_public_hex"]


@pytest.mark.parametrize("vector", _VECTORS, ids=lambda v: v["name"])
def test_decodes_real_derived_xwing_key_matching_pinned_prefix(vector: dict[str, str]) -> None:
    public_key = derive_mlkem768x25519_keypair_from_seed(bytes.fromhex(vector["seed_hex"]))[
        "public_key"
    ]
    assert len(public_key) == 1216
    recipient = encode_age_xwing_recipient(public_key)
    assert recipient.startswith(vector["age1pqc_prefix"])
    parsed = parse_age_recipient(recipient)
    assert parsed.kem == "mlkem768x25519"
    assert parsed.public_key == public_key


def test_tolerates_surrounding_whitespace() -> None:
    s = encode_age_x25519_recipient(bytes([1]) * 32)
    assert parse_age_recipient(f"  {s}\n").public_key == bytes([1]) * 32


def test_rejects_empty_string() -> None:
    with pytest.raises(ValueError):
        parse_age_recipient("")


def test_rejects_corrupted_checksum() -> None:
    s = encode_age_x25519_recipient(bytes([2]) * 32)
    broken = s[:-1] + ("p" if s.endswith("q") else "q")
    with pytest.raises(ValueError):
        parse_age_recipient(broken)


def test_rejects_mixed_case() -> None:
    s = encode_age_x25519_recipient(bytes([3]) * 32)
    mixed = s[:12].upper() + s[12:]
    with pytest.raises(ValueError, match="mixed-case"):
        parse_age_recipient(mixed)


def test_rejects_unrecognized_hrp() -> None:
    s = bech32_encode_no_limit("xyz", bytes([4]) * 32)
    with pytest.raises(ValueError, match="unrecognized recipient prefix"):
        parse_age_recipient(s)


def test_rejects_correct_hrp_with_wrong_key_length() -> None:
    wrong = bech32_encode_no_limit("age1pqc", bytes([5]) * 32)
    with pytest.raises(ValueError, match="1216-byte"):
        parse_age_recipient(wrong)
