"""Stubbed FetchOutbound that replays captured gateway responses.

Routes URL -> captured response from the corpus record. Raises on miss so the
test fails with an informative diagnostic.

Two confirmation paths are supported:
  * Koios       — `/tx_cbor` + `/tx_info` (block_height) + `/tip` (block_height).
  * Blockfrost  — `/txs/{hash}/cbor` + `/txs/{hash}` + `/blocks/latest`.
The verifier derives confirmations as `max(0, tipHeight - txHeight + 1)`
(blocks + 1) on both paths.

JSON is serialised with compact separators so the byte counts surfaced in
`auditTrail[].bytes` match the TypeScript twin (`JSON.stringify`) byte-for-byte.
"""

from __future__ import annotations

import json
from typing import Any

from cardanowall.verifier import (
    FetchOutbound,
    FetchOutboundOptions,
    FetchOutboundResult,
)

from ._corpus_schema import CorpusRecord


def _json_response(value: Any) -> FetchOutboundResult:
    body = json.dumps(value, separators=(",", ":")).encode("utf-8")
    return FetchOutboundResult(status=200, bytes=body, duration_ms=1)


def stub_fetch_from_record(record: CorpusRecord) -> FetchOutbound:
    captures = record["captured_gateway_responses"]
    arweave = captures.get("arweave_responses", {})

    async def stub(url: str, opts: FetchOutboundOptions) -> FetchOutboundResult:
        # Koios confirmation path.
        if url.endswith("/tx_cbor"):
            return _json_response(captures.get("koios_tx_cbor", []))
        if url.endswith("/tx_info"):
            return _json_response(captures.get("koios_tx_info", []))
        if url.endswith("/tip"):
            return _json_response(captures.get("koios_tip", []))
        # Blockfrost confirmation path.
        if url.endswith("/blocks/latest"):
            return _json_response(captures.get("blockfrost_blocks_latest", {}))
        if url.endswith("/cbor") and "/txs/" in url:
            return _json_response(captures.get("blockfrost_tx_cbor", {}))
        if "/txs/" in url:
            return _json_response(captures.get("blockfrost_tx", {}))
        # Captured Arweave content (item bytes, leaves-lists, sealed ciphertext).
        for ar_tx_id, hex_str in arweave.items():
            if url == f"https://arweave.net/{ar_tx_id}":
                return FetchOutboundResult(status=200, bytes=bytes.fromhex(hex_str), duration_ms=1)
        raise RuntimeError(f"stub_fetch: no captured response for {opts.method} {url}")

    return stub
