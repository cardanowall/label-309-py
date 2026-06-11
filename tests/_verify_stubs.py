"""Shared binding-correct transaction stubs for verifier pipeline tests.

The verifier reads nothing out of a fetched transaction until blake2b-256 of
the body equals the requested hash and blake2b-256 of the auxiliary data
equals the body's ``auxiliary_data_hash`` (key 7), so a hermetic pipeline
test must serve a synthetic transaction satisfying both bindings. The bodies
built here are minimal canonical CBOR maps — not ledger-valid transactions;
the hashing inputs/outputs and the label-309 carriage are what is exercised.
"""

from __future__ import annotations

import json
from typing import Any, cast

from cardanowall._crypto.cbor import CanonicalCborValue, encode_canonical_cbor
from cardanowall._crypto.hash import blake2b_256
from cardanowall.verifier import FetchOutbound, FetchOutboundOptions, FetchOutboundResult
from cardanowall.verifier.carriage import chunk_record_body

KOIOS_URL = "https://koios.test/api/v1"


def make_bound_tx(record_body: bytes | None) -> tuple[str, bytes]:
    """Build ``(tx_hash_hex, tx_cbor)`` for a post-Alonzo transaction whose
    auxiliary data carries ``record_body`` as the label-309 chunk array (or no
    label-309 entry at all when ``record_body`` is None), with both integrity
    bindings satisfied."""
    if record_body is None:
        metadata: dict[int, object] = {674: {"msg": ["hello"]}}
    else:
        metadata = {309: chunk_record_body(record_body)}
    aux = encode_canonical_cbor(cast(CanonicalCborValue, metadata))
    body = encode_canonical_cbor(cast(CanonicalCborValue, {7: blake2b_256(aux)}))
    # [body, witness_set, is_valid, auxiliary_data] — hand-assembled so the
    # component slices stay byte-faithful.
    tx_cbor = b"\x84" + body + b"\xa0\xf5" + aux
    return blake2b_256(body).hex(), tx_cbor


def koios_routes(
    tx_hash: str,
    tx_cbor: bytes,
    *,
    num_confirmations: int | None = 100,
    block_height: int | None = None,
    tip_height: int | None = None,
    block_time: int = 1_700_000_000,
    absolute_slot: int = 12_345,
) -> dict[str, FetchOutboundResult]:
    """Stub Koios responses for one transaction. Either ``num_confirmations``
    is served directly, or ``block_height`` + ``tip_height`` exercise the
    depth = tip - block + 1 computation."""
    info: dict[str, Any] = {
        "tx_hash": tx_hash,
        "tx_timestamp": block_time,
        "absolute_slot": absolute_slot,
    }
    if num_confirmations is not None:
        info["num_confirmations"] = num_confirmations
    if block_height is not None:
        info["block_height"] = block_height
    routes = {
        f"{KOIOS_URL}/tx_cbor": _json_result([{"tx_hash": tx_hash, "cbor": tx_cbor.hex()}]),
        f"{KOIOS_URL}/tx_info": _json_result([info]),
    }
    if tip_height is not None:
        routes[f"{KOIOS_URL}/tip"] = _json_result([{"block_height": tip_height}])
    return routes


def _json_result(payload: object) -> FetchOutboundResult:
    return FetchOutboundResult(status=200, bytes=json.dumps(payload).encode("utf-8"), duration_ms=5)


def route_fetch(routes: dict[str, FetchOutboundResult]) -> FetchOutbound:
    """A FetchOutbound stub serving exact-URL routes; any other URL raises."""

    async def stub(url: str, opts: FetchOutboundOptions) -> FetchOutboundResult:
        result = routes.get(url)
        if result is None:
            raise RuntimeError(f"unexpected url: {url}")
        return result

    return stub
