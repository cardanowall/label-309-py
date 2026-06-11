"""Explorer-chain resolution tests.

Covers provider ordering, the per-response integrity binding, the three
terminal negatives and their evidence precedence, and the block-counted
confirmation-depth computation.
"""

from __future__ import annotations

import asyncio
import json

from cardanowall.poe_standard import encode_poe_record
from cardanowall.verifier import (
    FetchOutbound,
    FetchOutboundOptions,
    FetchOutboundResult,
    ResolvedTx,
    ResolveFailure,
    VerifyTxInput,
    resolve_cardano_tx,
)

from ._verify_stubs import KOIOS_URL, koios_routes, make_bound_tx, route_fetch

BLOCKFROST = "https://cardano-mainnet.blockfrost.io/api/v0"


def _record_body() -> bytes:
    return encode_poe_record({"v": 1, "items": [{"hashes": {"sha2-256": b"\x07" * 32}}]})


def _resolve(tx_hash: str, fetch_fn: FetchOutbound, **input_kwargs: object) -> object:
    return asyncio.run(
        resolve_cardano_tx(
            input=VerifyTxInput(
                tx_hash=tx_hash,
                cardano_gateway_chain=(KOIOS_URL,),
                fetch_outbound=fetch_fn,
                **input_kwargs,  # type: ignore[arg-type]
            ),
            fetch_fn=fetch_fn,
        )
    )


def test_koios_happy_path_resolves_with_chain_facts() -> None:
    tx_hash, tx_cbor = make_bound_tx(_record_body())
    outcome = _resolve(tx_hash, route_fetch(koios_routes(tx_hash, tx_cbor)))
    assert isinstance(outcome, ResolvedTx)
    assert outcome.tx_cbor == tx_cbor
    assert outcome.provider == "koios"
    assert outcome.confirmation_depth == 100
    assert outcome.block_time == 1_700_000_000
    assert outcome.block_slot == 12_345
    assert outcome.components.auxiliary_data is not None


def test_depth_computed_from_heights_when_no_native_confirmations() -> None:
    tx_hash, tx_cbor = make_bound_tx(_record_body())
    routes = koios_routes(
        tx_hash, tx_cbor, num_confirmations=None, block_height=1000, tip_height=1014
    )
    outcome = _resolve(tx_hash, route_fetch(routes))
    assert isinstance(outcome, ResolvedTx)
    # depth = tip - block + 1.
    assert outcome.confirmation_depth == 15


def test_tip_block_transaction_has_depth_exactly_1() -> None:
    tx_hash, tx_cbor = make_bound_tx(_record_body())
    routes = koios_routes(
        tx_hash, tx_cbor, num_confirmations=None, block_height=1000, tip_height=1000
    )
    outcome = _resolve(tx_hash, route_fetch(routes))
    assert isinstance(outcome, ResolvedTx)
    assert outcome.confirmation_depth == 1


def test_tip_below_block_discards_the_provider_as_inconsistent() -> None:
    # The provider's tip height is below the height of the block it itself
    # reports for the transaction: the snapshot contradicts itself, so the
    # provider contributes no chain facts, and with no further provider the
    # run ends in the network-class end state — a depth is never fabricated
    # by flooring.
    tx_hash, tx_cbor = make_bound_tx(_record_body())
    routes = koios_routes(
        tx_hash, tx_cbor, num_confirmations=None, block_height=1000, tip_height=999
    )
    outcome = _resolve(tx_hash, route_fetch(routes))
    assert isinstance(outcome, ResolveFailure)
    assert outcome.code == "PROVIDER_UNAVAILABLE"
    assert "inconsistent provider snapshot" in outcome.message


def test_inconsistent_provider_falls_through_to_the_next_provider() -> None:
    # Koios contradicts its own snapshot; Blockfrost is consistent →
    # resolution proceeds per the existing precedence with Blockfrost's
    # honest facts.
    tx_hash, tx_cbor = make_bound_tx(_record_body())
    routes = koios_routes(
        tx_hash, tx_cbor, num_confirmations=None, block_height=1000, tip_height=999
    )
    routes.update(
        {
            f"{BLOCKFROST}/txs/{tx_hash}/cbor": FetchOutboundResult(
                status=200, bytes=json.dumps({"cbor": tx_cbor.hex()}).encode(), duration_ms=1
            ),
            f"{BLOCKFROST}/txs/{tx_hash}": FetchOutboundResult(
                status=200,
                bytes=json.dumps(
                    {"block_time": 1_700_000_777, "slot": 999, "block_height": 1000}
                ).encode(),
                duration_ms=1,
            ),
            f"{BLOCKFROST}/blocks/latest": FetchOutboundResult(
                status=200, bytes=json.dumps({"height": 1004}).encode(), duration_ms=1
            ),
        }
    )
    outcome = _resolve(tx_hash, route_fetch(routes), blockfrost_project_id="proj")
    assert isinstance(outcome, ResolvedTx)
    assert outcome.provider == "blockfrost"
    assert outcome.confirmation_depth == 5


def test_blockfrost_tip_below_block_discards_the_provider_as_inconsistent() -> None:
    tx_hash, tx_cbor = make_bound_tx(_record_body())
    routes = {
        f"{KOIOS_URL}/tx_cbor": FetchOutboundResult(status=503, bytes=b"", duration_ms=1),
        f"{BLOCKFROST}/txs/{tx_hash}/cbor": FetchOutboundResult(
            status=200, bytes=json.dumps({"cbor": tx_cbor.hex()}).encode(), duration_ms=1
        ),
        f"{BLOCKFROST}/txs/{tx_hash}": FetchOutboundResult(
            status=200,
            bytes=json.dumps(
                {"block_time": 1_700_000_777, "slot": 999, "block_height": 1000}
            ).encode(),
            duration_ms=1,
        ),
        f"{BLOCKFROST}/blocks/latest": FetchOutboundResult(
            status=200, bytes=json.dumps({"height": 999}).encode(), duration_ms=1
        ),
    }
    outcome = _resolve(tx_hash, route_fetch(routes), blockfrost_project_id="proj")
    assert isinstance(outcome, ResolveFailure)
    assert outcome.code == "PROVIDER_UNAVAILABLE"
    assert "inconsistent provider snapshot" in outcome.message


def test_served_num_confirmations_of_0_is_the_same_inconsistency() -> None:
    # A count of 0 for a transaction the provider itself reports as on-chain
    # carries depth < 1: unusable, never a report fact.
    tx_hash, tx_cbor = make_bound_tx(_record_body())
    routes = koios_routes(tx_hash, tx_cbor, num_confirmations=0)
    outcome = _resolve(tx_hash, route_fetch(routes))
    assert isinstance(outcome, ResolveFailure)
    assert outcome.code == "PROVIDER_UNAVAILABLE"
    assert "inconsistent provider snapshot" in outcome.message


def test_koios_empty_result_set_is_tx_not_found() -> None:
    tx_hash, _ = make_bound_tx(_record_body())
    routes = {f"{KOIOS_URL}/tx_cbor": FetchOutboundResult(status=200, bytes=b"[]", duration_ms=1)}
    outcome = _resolve(tx_hash, route_fetch(routes))
    assert isinstance(outcome, ResolveFailure)
    assert outcome.code == "TX_NOT_FOUND"


def test_unreachable_chain_is_provider_unavailable() -> None:
    async def unreachable(url: str, opts: FetchOutboundOptions) -> FetchOutboundResult:
        raise RuntimeError("connection refused")

    outcome = _resolve("ab" * 32, unreachable)
    assert isinstance(outcome, ResolveFailure)
    assert outcome.code == "PROVIDER_UNAVAILABLE"


def test_binding_failure_is_tx_integrity_mismatch() -> None:
    # The provider serves a well-formed transaction whose body hashes to a
    # DIFFERENT id than requested: provably wrong bytes, the strongest
    # negative signal.
    _, tx_cbor = make_bound_tx(_record_body())
    requested = "11" * 32
    outcome = _resolve(requested, route_fetch(koios_routes(requested, tx_cbor)))
    assert isinstance(outcome, ResolveFailure)
    assert outcome.code == "TX_INTEGRITY_MISMATCH"


def test_wrong_bytes_bind_before_any_further_provider_call() -> None:
    # The provider serves a well-formed transaction that does not hash to the
    # requested reference, and every later endpoint of it errors. The binding
    # runs the moment the tx bytes arrive, so the run reports the stronger
    # TX_INTEGRITY_MISMATCH evidence — never the later provider failure — and
    # spends no further calls on a provider already proven to serve wrong
    # bytes.
    _, tx_cbor = make_bound_tx(_record_body())
    requested = "22" * 32
    calls: list[str] = []

    async def fetch(url: str, opts: FetchOutboundOptions) -> FetchOutboundResult:
        calls.append(url)
        if url == f"{KOIOS_URL}/tx_cbor":
            payload = json.dumps([{"cbor": tx_cbor.hex()}]).encode()
            return FetchOutboundResult(status=200, bytes=payload, duration_ms=1)
        return FetchOutboundResult(status=500, bytes=b"", duration_ms=1)

    outcome = _resolve(requested, fetch)
    assert isinstance(outcome, ResolveFailure)
    assert outcome.code == "TX_INTEGRITY_MISMATCH"
    assert calls == [f"{KOIOS_URL}/tx_cbor"]


def test_koios_5xx_falls_through_to_blockfrost() -> None:
    tx_hash, tx_cbor = make_bound_tx(_record_body())
    routes = {
        f"{KOIOS_URL}/tx_cbor": FetchOutboundResult(status=503, bytes=b"", duration_ms=1),
        f"{BLOCKFROST}/txs/{tx_hash}/cbor": FetchOutboundResult(
            status=200, bytes=json.dumps({"cbor": tx_cbor.hex()}).encode(), duration_ms=1
        ),
        f"{BLOCKFROST}/txs/{tx_hash}": FetchOutboundResult(
            status=200,
            bytes=json.dumps(
                {"block_time": 1_700_000_777, "slot": 999, "block_height": 5_000}
            ).encode(),
            duration_ms=1,
        ),
        f"{BLOCKFROST}/blocks/latest": FetchOutboundResult(
            status=200, bytes=json.dumps({"height": 5_099}).encode(), duration_ms=1
        ),
    }
    outcome = _resolve(tx_hash, route_fetch(routes), blockfrost_project_id="proj")
    assert isinstance(outcome, ResolvedTx)
    assert outcome.provider == "blockfrost"
    assert outcome.confirmation_depth == 100
    assert outcome.block_time == 1_700_000_777
    assert outcome.block_slot == 999


def test_blockfrost_404_is_definitive_not_found() -> None:
    tx_hash, _ = make_bound_tx(_record_body())
    routes = {
        f"{KOIOS_URL}/tx_cbor": FetchOutboundResult(status=503, bytes=b"", duration_ms=1),
        f"{BLOCKFROST}/txs/{tx_hash}/cbor": FetchOutboundResult(
            status=404, bytes=b"", duration_ms=1
        ),
    }
    outcome = _resolve(tx_hash, route_fetch(routes), blockfrost_project_id="proj")
    assert isinstance(outcome, ResolveFailure)
    assert outcome.code == "TX_NOT_FOUND"


def test_empty_gateway_chain_without_blockfrost_is_provider_unavailable() -> None:
    async def never_called(url: str, opts: FetchOutboundOptions) -> FetchOutboundResult:
        raise AssertionError("no provider should be contacted")

    outcome = asyncio.run(
        resolve_cardano_tx(
            input=VerifyTxInput(tx_hash="ab" * 32, cardano_gateway_chain=()),
            fetch_fn=never_called,
        )
    )
    assert isinstance(outcome, ResolveFailure)
    assert outcome.code == "PROVIDER_UNAVAILABLE"
