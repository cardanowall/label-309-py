"""Byte oracle for the co-hash content-item producer path.

Loads the byte-identical mirror of the language-neutral fixture (a single
hash-only item co-hashed under ``sha2-256`` AND ``blake2b-256``) and asserts
the Python encoder reproduces the frozen ``cbor_hex`` — for BOTH input
orderings, because canonical CBOR sorts the ``hashes`` map length-first
(``sha2-256`` (8B) before ``blake2b-256`` (11B)) regardless of the order the
caller supplied. The SDK ``publish_content`` / ``publish_prehashed`` / seal
co-hash helpers build the identical item.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

from cardanowall._crypto.hash import blake2b_256, sha256
from cardanowall.poe_standard import PoeRecord, encode_poe_record

_FIXTURE_PATH = (
    Path(__file__).resolve().parent / "fixtures" / "poe-record" / "cohash-item-record.json"
)


def _load() -> dict[str, Any]:
    return cast("dict[str, Any]", json.loads(_FIXTURE_PATH.read_text(encoding="utf-8")))


def _single_item_record(hashes: dict[str, bytes]) -> PoeRecord:
    return cast("PoeRecord", {"v": 1, "items": [{"hashes": hashes}]})


def test_cohash_digests_derive_from_content() -> None:
    fixture = _load()
    content = bytes.fromhex(fixture["content_hex"])
    assert sha256(content).hex() == fixture["hashes"]["sha2-256"]
    assert blake2b_256(content).hex() == fixture["hashes"]["blake2b-256"]


def test_cohash_item_record_is_order_independent() -> None:
    fixture = _load()
    sha = bytes.fromhex(fixture["hashes"]["sha2-256"])
    blake = bytes.fromhex(fixture["hashes"]["blake2b-256"])
    sha_first = encode_poe_record(_single_item_record({"sha2-256": sha, "blake2b-256": blake}))
    blake_first = encode_poe_record(_single_item_record({"blake2b-256": blake, "sha2-256": sha}))
    # Both orderings must encode to the one frozen byte string.
    assert sha_first.hex() == fixture["cbor_hex"]
    assert blake_first.hex() == fixture["cbor_hex"]
