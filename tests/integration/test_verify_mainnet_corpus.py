"""Integration test: Python verifier produces canonical VerifyReport per corpus record.

The captured mainnet corpus is regenerated synthetically against the Label 309
wire schema (items/merkle/sigs[].cose_sign1/...) via the mainnet-corpus refresh
pipeline (MODE=synthetic, the default CI-safe path). The per-tx
expected-report fixtures in `tests/fixtures/verify-reports/<tx_hash>.json` are
byte-identical to their TypeScript twin in @cardanowall/sdk-ts — this test
asserts that contract at runtime.
"""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
from urllib.parse import urlparse

import pytest

from cardanowall.verifier import (
    DecryptionRecipient,
    VerifyTxInput,
    verify_report_to_dict,
    verify_tx,
)

from ._corpus_schema import CorpusRecord, validate_corpus
from ._stub_fetch import stub_fetch_from_record

# Synthetic mainnet corpus — built by the TypeScript corpus generator.

CORPUS_PATH = Path(
    os.environ.get(
        "CARDANOWALL_NXDOMAIN_CORPUS_PATH",
        str(Path(__file__).resolve().parents[1] / "fixtures" / "mainnet-corpus.json"),
    )
)
FIXTURES_DIR = Path(__file__).resolve().parents[2] / "tests" / "fixtures" / "verify-reports"

CONFORMANCE_DENY: tuple[str, ...] = (
    "operator.example",
    "*.operator.example",
    "localhost",
    "127.0.0.1",
)


def _load_corpus() -> list[CorpusRecord]:
    if not CORPUS_PATH.exists():
        return []
    return validate_corpus(json.loads(CORPUS_PATH.read_text(encoding="utf-8")))["records"]


CORPUS: list[CorpusRecord] = _load_corpus()


def _is_denied_operator_host(url: str) -> bool:
    host = (urlparse(url).hostname or "").strip("[]").rstrip(".").lower()
    return host == "operator.example" or host.endswith(".operator.example")


def test_corpus_has_at_least_100_records() -> None:
    assert len(CORPUS) >= 100, f"mainnet corpus has {len(CORPUS)} records; require >= 100"


_PARAMETRIZED_CORPUS = CORPUS or [{"tx_hash": "0" * 64}]


def _verify_input(record: CorpusRecord) -> VerifyTxInput:
    # Replay the verifier against one corpus record exactly as the golden writer
    # does: route Blockfrost-provider records through the Blockfrost resolver and
    # plumb any recipient secret keys into `decryption`.
    use_blockfrost = record.get("provider") == "blockfrost"
    decryption = tuple(
        DecryptionRecipient(recipient_secret_key=bytes.fromhex(r["secret_key"]))
        for r in record.get("recipient_secret_keys", [])
    )
    return VerifyTxInput(
        tx_hash=record["tx_hash"],
        cardano_gateway_chain=() if use_blockfrost else ("https://api.koios.rest/api/v1",),
        blockfrost_project_id="corpus" if use_blockfrost else None,
        decryption=decryption if len(decryption) > 0 else None,
        deny_hosts=CONFORMANCE_DENY,
        fetch_outbound=stub_fetch_from_record(record),
    )


@pytest.mark.parametrize(
    "record", _PARAMETRIZED_CORPUS, ids=[r["tx_hash"] for r in _PARAMETRIZED_CORPUS]
)
def test_verify_report_matches_expected_fixture(record: CorpusRecord) -> None:
    result = asyncio.run(verify_tx(_verify_input(record)))
    actual = (
        json.dumps(
            verify_report_to_dict(result),
            sort_keys=True,
            indent=2,
            ensure_ascii=False,
        )
        + "\n"
    )
    expected = (FIXTURES_DIR / f"{record['tx_hash']}.json").read_text(encoding="utf-8")
    assert actual == expected, (
        f"VerifyReport diverged from expected fixture for tx {record['tx_hash']}"
    )
    assert result.verdict == record["expected_verdict"]
    assert all(not _is_denied_operator_host(c.url) for c in result.audit_trail)
