from __future__ import annotations

import asyncio
import json

import cbor2
import pytest

from cardanowall._crypto.cbor import encode_canonical_cbor
from cardanowall.verifier import (
    FetchOutboundOptions,
    FetchOutboundResult,
    NotALabel309RecordError,
    VerifyTxInput,
    extract_label_309_metadata,
    resolve_cardano_tx,
)


def _mk_routes(routes: dict[str, FetchOutboundResult]) -> object:
    async def stub(url: str, opts: FetchOutboundOptions) -> FetchOutboundResult:
        for prefix, result in routes.items():
            if url.startswith(prefix):
                return result
        raise RuntimeError(f"unexpected url: {url}")

    return stub


def test_resolve_via_koios_happy_path() -> None:
    tx_hash = "a" * 64
    tx_cbor = bytes.fromhex("aa" * 10)
    routes = {
        "https://api.koios.rest/api/v1/tx_cbor": FetchOutboundResult(
            status=200,
            bytes=json.dumps([{"tx_hash": tx_hash, "cbor": tx_cbor.hex()}]).encode("utf-8"),
            duration_ms=5,
        ),
        "https://api.koios.rest/api/v1/tx_info": FetchOutboundResult(
            status=200,
            bytes=json.dumps(
                [
                    {
                        "tx_hash": tx_hash,
                        "num_confirmations": 100,
                        "tx_timestamp": 1700000000,
                        "absolute_slot": 12345,
                    }
                ]
            ).encode("utf-8"),
            duration_ms=5,
        ),
    }
    fetch_fn = _mk_routes(routes)
    result = asyncio.run(
        resolve_cardano_tx(
            input=VerifyTxInput(tx_hash=tx_hash),
            fetch_fn=fetch_fn,  # type: ignore[arg-type]
        )
    )
    assert result.provider == "koios"
    assert result.num_confirmations == 100
    assert result.tx_cbor == tx_cbor


def test_resolve_via_koios_empty_array_raises_not_a_record() -> None:
    tx_hash = "b" * 64
    routes = {
        "https://api.koios.rest/api/v1/tx_cbor": FetchOutboundResult(
            status=200, bytes=b"[]", duration_ms=5
        ),
    }
    fetch_fn = _mk_routes(routes)
    with pytest.raises(NotALabel309RecordError):
        asyncio.run(
            resolve_cardano_tx(
                input=VerifyTxInput(tx_hash=tx_hash),
                fetch_fn=fetch_fn,  # type: ignore[arg-type]
            )
        )


def test_resolve_via_koios_503_falls_to_blockfrost() -> None:
    tx_hash = "c" * 64
    tx_cbor = bytes.fromhex("cc" * 10)
    routes = {
        "https://api.koios.rest/api/v1/tx_cbor": FetchOutboundResult(
            status=503, bytes=b"err", duration_ms=5
        ),
        "https://cardano-mainnet.blockfrost.io/api/v0/txs/" + tx_hash + "/cbor": (
            FetchOutboundResult(
                status=200,
                bytes=json.dumps({"cbor": tx_cbor.hex()}).encode("utf-8"),
                duration_ms=5,
            )
        ),
        "https://cardano-mainnet.blockfrost.io/api/v0/txs/" + tx_hash: FetchOutboundResult(
            status=200,
            bytes=json.dumps(
                {"block_time": 1700000000, "slot": 100, "block_height": 1000}
            ).encode("utf-8"),
            duration_ms=5,
        ),
        "https://cardano-mainnet.blockfrost.io/api/v0/blocks/latest": FetchOutboundResult(
            status=200,
            bytes=json.dumps({"height": 1100, "slot": 200}).encode("utf-8"),
            duration_ms=5,
        ),
    }
    fetch_fn = _mk_routes(routes)
    result = asyncio.run(
        resolve_cardano_tx(
            input=VerifyTxInput(tx_hash=tx_hash, blockfrost_project_id="mainnet01abc"),
            fetch_fn=fetch_fn,  # type: ignore[arg-type]
        )
    )
    assert result.provider == "blockfrost"
    # Confirmations are counted in BLOCKS: max(0, tipHeight - txHeight + 1).
    assert result.num_confirmations == 101  # 1100 - 1000 + 1
    assert result.block_slot == 100


def test_resolve_definitive_empty_does_not_fall_through() -> None:
    tx_hash = "d" * 64
    routes = {
        "https://api.koios.rest/api/v1/tx_cbor": FetchOutboundResult(
            status=200, bytes=b"[]", duration_ms=5
        ),
    }
    fetch_fn = _mk_routes(routes)
    with pytest.raises(NotALabel309RecordError):
        asyncio.run(
            resolve_cardano_tx(
                input=VerifyTxInput(tx_hash=tx_hash, blockfrost_project_id="mainnet01abc"),
                fetch_fn=fetch_fn,  # type: ignore[arg-type]
            )
        )


def test_extract_label_309_metadata_happy() -> None:
    inner: dict[str | int, object] = {"t": "poe", "v": 1}
    aux = {0: {309: inner}}
    tx = cbor2.dumps([{}, {}, True, aux])
    result = extract_label_309_metadata(tx)
    assert result is not None
    assert result == encode_canonical_cbor(inner)  # type: ignore[arg-type]


def test_extract_label_309_metadata_no_aux() -> None:
    tx = cbor2.dumps([{}, {}, True, None])
    assert extract_label_309_metadata(tx) is None


def test_extract_label_309_metadata_no_label_309() -> None:
    tx = cbor2.dumps([{}, {}, True, {0: {0: "other"}}])
    assert extract_label_309_metadata(tx) is None


def test_extract_label_309_non_list_tx_raises() -> None:
    tx = cbor2.dumps({"a": 1})
    with pytest.raises(ValueError, match="MALFORMED_CBOR: tx CBOR is not a CBOR array"):
        extract_label_309_metadata(tx)
