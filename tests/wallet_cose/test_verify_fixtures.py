"""Python parity verifier test for per-wallet COSE_Sign1 fixtures.

Mirrors the @cardanowall/sdk-ts wallet-cose verify-fixtures KAT test.
Loads the SAME 24 fixtures from the Python mirror tree at
`tests/fixtures/wallet-cose/`, drives them through
`verify_record_signatures`, normalises the result via
`to_normalized_sig_verdict`, and asserts deep-equal against the fixture's
`expected_normalized_verdict` field. The cross-language parity gate enforces
byte-equality between the TypeScript canonical tree and this Python mirror in
CI.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

import pytest

from cardanowall.poe_standard import PoeRecord
from cardanowall.verifier import verify_record_signatures

from ._normalized_verdict import NormalizedSigVerdict, to_normalized_sig_verdict

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures" / "wallet-cose"

WALLETS = ("eternl", "lace", "nami", "typhon", "yoroi", "nufi")
TAMPER_VARIANTS = ("tampered-address", "missing-address", "wrong-network-header")


def _positive_id(wallet: str) -> tuple[str, str]:
    return (f"{wallet}-positive", f"{wallet}-cose.json")


def _tamper_id(wallet: str, variant: str) -> tuple[str, str]:
    return (f"{wallet}-{variant}", f"{wallet}-cose-{variant}.json")


FIXTURE_CASES: list[tuple[str, str]] = []
for _w in WALLETS:
    FIXTURE_CASES.append(_positive_id(_w))
    for _v in TAMPER_VARIANTS:
        FIXTURE_CASES.append(_tamper_id(_w, _v))


def _load_fixture(filename: str) -> dict[str, Any]:
    raw: Any = json.loads((FIXTURES_DIR / filename).read_text(encoding="utf-8"))
    return cast(dict[str, Any], raw)


def _build_record(cose_sign1_hex: str, cose_key_hex: str) -> PoeRecord:
    record: PoeRecord = cast(
        PoeRecord,
        {
            "v": 1,
            "items": [{"hashes": {"sha2-256": b"\x00" * 32}}],
            "sigs": [
                {
                    "cose_sign1": bytes.fromhex(cose_sign1_hex),
                    "cose_key": bytes.fromhex(cose_key_hex),
                }
            ],
        },
    )
    return record


@pytest.mark.parametrize(
    ("fixture_id", "filename"),
    FIXTURE_CASES,
    ids=lambda v: v if isinstance(v, str) else "",
)
def test_wallet_cose_verifies(fixture_id: str, filename: str) -> None:
    fixture = _load_fixture(filename)
    record = _build_record(
        cast(str, fixture["cose_sign1_bytes_hex"]),
        cast(str, fixture["cose_key_bytes_hex"]),
    )
    results = verify_record_signatures(record)
    assert len(results) == 1, fixture_id
    actual: NormalizedSigVerdict = to_normalized_sig_verdict(results[0])
    expected = cast(dict[str, Any], fixture["expected_normalized_verdict"])
    assert actual == expected, fixture_id
