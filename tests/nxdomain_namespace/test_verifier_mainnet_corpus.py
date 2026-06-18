"""Layer 1 + Layer 2 NXDOMAIN proof against the synthetic mainnet corpus.

Layer 1 (the parametrised tests): the verifier MUST emit no HTTP call
to an operator.example host when given the conformance deny-list AND when
given an empty deny-list. Asserts service-independence is a property of
the verifier, not a function of the operator's deny-list.

Layer 2 (the optional Docker-only test below): with a real DNS resolver
configured to NXDOMAIN operator.example, the default `fetch_outbound`
MUST error rather than reach the network.
"""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
from urllib.parse import urlparse

import httpx
import pytest

from cardanowall.verifier import (
    DecryptionRecipient,
    FetchOutboundOptions,
    VerifyTxInput,
    default_fetch_outbound,
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

_PLACEHOLDER: list[CorpusRecord] = [{"tx_hash": "0" * 64}]
_CORPUS_OR_PLACEHOLDER = CORPUS or _PLACEHOLDER


def _is_denied_operator_host(url: str) -> bool:
    host = (urlparse(url).hostname or "").strip("[]").rstrip(".").lower()
    return host == "operator.example" or host.endswith(".operator.example")


def _verify_input(record: CorpusRecord, deny_hosts: tuple[str, ...]) -> VerifyTxInput:
    # Route Blockfrost-provider records through the Blockfrost resolver and plumb
    # any recipient secret keys into `decryption`, matching the golden writer.
    use_blockfrost = record.get("provider") == "blockfrost"
    decryption = tuple(
        DecryptionRecipient(recipient_secret_key=bytes.fromhex(r["secret_key"]))
        for r in record.get("recipient_secret_keys", [])
    )
    return VerifyTxInput(
        tx_hash=record["tx_hash"],
        cardano_gateway_chain=() if use_blockfrost else ("https://api.koios.rest/api/v1",),
        # Pin the Arweave chain to the single gateway the corpus stub serves
        # (the default rotation's membership/order is asserted separately in
        # test_verifier_fetch.py); otherwise the verifier tries the default
        # chain's first gateway, which this stub does not serve.
        arweave_gateway_chain=("https://arweave.net",),
        blockfrost_project_id="corpus" if use_blockfrost else None,
        decryption=decryption if len(decryption) > 0 else None,
        deny_hosts=deny_hosts,
        fetch_outbound=stub_fetch_from_record(record),
    )


@pytest.mark.nxdomain
@pytest.mark.parametrize(
    "record", _CORPUS_OR_PLACEHOLDER, ids=[r["tx_hash"] for r in _CORPUS_OR_PLACEHOLDER]
)
def test_verifies_record_with_conformance_deny_hosts(record: CorpusRecord) -> None:
    result = asyncio.run(verify_tx(_verify_input(record, CONFORMANCE_DENY)))
    assert result.verdict == record["expected_verdict"]
    assert all(not _is_denied_operator_host(c.url) for c in result.audit_trail)


@pytest.mark.nxdomain
@pytest.mark.parametrize(
    "record", _CORPUS_OR_PLACEHOLDER, ids=[r["tx_hash"] for r in _CORPUS_OR_PLACEHOLDER]
)
def test_verifies_record_with_empty_deny_hosts(record: CorpusRecord) -> None:
    result = asyncio.run(verify_tx(_verify_input(record, ())))
    assert result.verdict == record["expected_verdict"]
    assert all(not _is_denied_operator_host(c.url) for c in result.audit_trail)


@pytest.mark.nxdomain
@pytest.mark.skipif(
    not os.environ.get("CARDANOWALL_NXDOMAIN_LAYER2"),
    reason="Layer 2 requires Docker container with NXDOMAIN resolver",
)
def test_rejects_direct_fetch_to_cardanowall_via_dns_nxdomain() -> None:
    async def go() -> None:
        try:
            await default_fetch_outbound(
                "https://operator.example/probe",
                FetchOutboundOptions(method="GET", purpose="cardano"),
            )
        except (httpx.HTTPError, OSError):
            return
        raise AssertionError("expected DNS-resolution-class error for operator.example")

    asyncio.run(go())
