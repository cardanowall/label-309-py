"""TypedDict + light validation for the bundled mainnet-corpus shape."""

from __future__ import annotations

from typing import TypedDict


class KoiosTxInfo(TypedDict, total=False):
    tx_hash: str
    block_height: int
    tx_timestamp: int
    absolute_slot: int


class KoiosTxCbor(TypedDict):
    tx_hash: str
    cbor: str


class KoiosTip(TypedDict, total=False):
    block_height: int


class BlockfrostTx(TypedDict, total=False):
    block_time: int
    slot: int
    block_height: int


class BlockfrostBlocksLatest(TypedDict, total=False):
    height: int
    slot: int


class BlockfrostTxCbor(TypedDict, total=False):
    cbor: str


class CapturedGatewayResponses(TypedDict, total=False):
    koios_tx_info: list[KoiosTxInfo]
    koios_tx_cbor: list[KoiosTxCbor]
    koios_tip: list[KoiosTip]
    blockfrost_tx_cbor: BlockfrostTxCbor
    blockfrost_tx: BlockfrostTx
    blockfrost_blocks_latest: BlockfrostBlocksLatest
    arweave_responses: dict[str, str]


class RecipientSecretKey(TypedDict):
    item_index: int
    secret_key: str


class CorpusRecord(TypedDict, total=False):
    tx_hash: str
    expected_verdict: str
    provider: str
    recipient_secret_keys: list[RecipientSecretKey]
    captured_gateway_responses: CapturedGatewayResponses
    notes: str


class MainnetCorpus(TypedDict, total=False):
    records: list[CorpusRecord]


def validate_corpus(raw: object) -> MainnetCorpus:
    if not isinstance(raw, dict):
        raise ValueError("corpus root must be an object")
    records = raw.get("records")
    if not isinstance(records, list) or len(records) < 1:
        raise ValueError("corpus.records must be a non-empty list")
    for i, rec in enumerate(records):
        if not isinstance(rec, dict):
            raise ValueError(f"records[{i}] must be an object")
        for field in ("tx_hash", "expected_verdict", "captured_gateway_responses"):
            if field not in rec:
                raise ValueError(f"records[{i}] missing field: {field}")
        tx_hash = rec["tx_hash"]
        if not isinstance(tx_hash, str) or len(tx_hash) != 64:
            raise ValueError(f"records[{i}].tx_hash must be a 64-char hex string")
    return raw  # type: ignore[return-value]
