"""Pins the prepared-seal cross-SDK parity vectors
(``tests/fixtures/prepared-seal/``): the exact ``prepared_seal_json_v1``
serialization, the fingerprint, the per-item derivations, and the record
bytes a deterministic ``seal_prepare`` run produces. The Rust and TypeScript
SDKs assert byte-identical values from mirrored copies of the same fixtures,
so the portable artifact cannot drift between implementations.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any, cast

import pytest

from cardanowall._crypto.seed_derive import (
    derive_mlkem768x25519_keypair_from_seed,
    derive_x25519_keypair_from_seed,
)
from cardanowall.client.sealed import (
    PreparedSeal,
    RngFill,
    encode_sealed_record,
    seal_prepare_with_rng,
)

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "prepared-seal"


def counter_rng(start: int) -> RngFill:
    """The counter byte source the fixtures declare: byte ``n`` of the stream
    is ``(start + n) mod 256``."""
    state = start

    def fill(count: int) -> bytes:
        nonlocal state
        out = bytes((state + i) & 0xFF for i in range(count))
        state += count
        return out

    return fill


@pytest.mark.parametrize(
    "name",
    [
        "single-item-mlkem768x25519.json",
        "multi-item-x25519.json",
        # The only vector that drives the n >= 3 slot shuffle (rejection-sampled
        # draws) together with per-slot X-Wing eseeds; a shuffle or eseed
        # divergence surfaces as a serialization mismatch here.
        "multi-item-hybrid.json",
    ],
)
def test_prepared_seal_vector_is_pinned(name: str) -> None:
    vector: dict[str, Any] = json.loads((FIXTURES_DIR / name).read_text(encoding="utf-8"))
    assert vector["deterministic_rng"]["type"] == "counter-u8"
    assert vector["hash_alg"] == "sha2-256"

    # Recipient keys derive from the pinned seeds — both are in the fixture
    # so a twin without the derivation helpers can use the keys directly.
    kem = vector["kem"]
    assert kem in ("x25519", "mlkem768x25519")
    recipients: list[bytes] = []
    for seed_hex in vector["recipient_seeds_hex"]:
        seed = bytes.fromhex(seed_hex)
        if kem == "x25519":
            recipients.append(derive_x25519_keypair_from_seed(seed)["public_key"])
        else:
            recipients.append(derive_mlkem768x25519_keypair_from_seed(seed)["public_key"])
    assert [r.hex() for r in recipients] == vector["recipient_public_keys_hex"], (
        "derived recipient keys must match the pinned keys"
    )

    plaintexts = [bytes.fromhex(p) for p in vector["plaintexts_hex"]]
    prepared = seal_prepare_with_rng(
        items=plaintexts,
        recipients=recipients,
        kem=cast("Any", kem),
        rng=counter_rng(vector["deterministic_rng"]["start"]),
    )

    expected = vector["expected"]
    assert prepared.to_json() == expected["prepared_seal_json"], (
        "the portable serialization must match byte-for-byte"
    )
    assert prepared.prepared_sha256 == expected["prepared_sha256"]
    assert [item.item_id for item in prepared.items] == expected["item_ids"]
    assert [
        prepared.upload_idempotency_key(index) for index in range(len(prepared.items))
    ] == expected["upload_idempotency_keys"]

    # The record bytes for the pinned uris, unsigned, no supersedes.
    assert vector["supersedes"] is None
    assert vector["signers"] is None
    record = asyncio.run(encode_sealed_record(prepared, vector["uris"]))
    assert record.hex() == expected["record_hex"]

    # The pinned serialization also round-trips through the parser with its
    # fingerprint verified.
    parsed = PreparedSeal.from_json(expected["prepared_seal_json"])
    assert parsed == prepared
