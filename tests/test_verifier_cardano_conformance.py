"""Cardano-semantics conformance replay.

Replays the frozen fixtures mirrored under ``tests/fixtures/cardano/``:

  - ``tx-binding.json`` — the transaction-reference integrity binding:
    blake2b-256 over the fetched body vs the requested hash, blake2b-256 over
    the fetched auxiliary data vs the verified body's ``auxiliary_data_hash``
    (both over the bytes exactly as fetched). A failed binding is the
    ``TX_INTEGRITY_MISMATCH`` outcome; a bound transaction without label-309
    metadata is the record-attributable ``METADATA_NOT_FOUND`` outcome.
  - ``confirmation-depth.json`` — depth = tip - block + 1 counted in blocks
    (a transaction in the tip block has depth exactly 1), with the
    pending/confirmed threshold gate pinned on both sides of the boundary,
    replayed through the full ``verify_tx`` pipeline against a stub explorer.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any, cast

import pytest

from cardanowall._crypto.hash import blake2b_256
from cardanowall.poe_standard import encode_poe_record
from cardanowall.verifier import (
    Label309ReassemblyOk,
    TxBindingFail,
    TxBindingOk,
    VerifyTxInput,
    auxiliary_data_hash_from_tx_body,
    bind_transaction_bytes,
    reassemble_label_309_value,
    unwrap_auxiliary_data,
    verify_tx,
)

from ._verify_stubs import KOIOS_URL, koios_routes, make_bound_tx, route_fetch

_FIXTURES = Path(__file__).parent / "fixtures" / "cardano"


def _vectors(filename: str) -> list[dict[str, Any]]:
    doc = json.loads((_FIXTURES / filename).read_text(encoding="utf-8"))
    return cast(list[dict[str, Any]], doc["vectors"])


_TX_BINDING = _vectors("tx-binding.json")
_CONFIRMATION_DEPTH = _vectors("confirmation-depth.json")


@pytest.mark.parametrize("vector", _TX_BINDING, ids=lambda v: cast(str, v["name"]))
def test_tx_binding(vector: dict[str, Any]) -> None:
    tx_body = bytes.fromhex(vector["transaction_body_cbor_hex"])
    auxiliary_data = bytes.fromhex(vector["auxiliary_data_cbor_hex"])
    expected = cast(dict[str, Any], vector["expected"])

    binding = bind_transaction_bytes(
        requested_tx_hash_hex=vector["requested_tx_hash_hex"],
        tx_body=tx_body,
        auxiliary_data=auxiliary_data,
    )

    if expected.get("error_code") == "TX_INTEGRITY_MISMATCH":
        assert isinstance(binding, TxBindingFail), vector["name"]
        return

    # Binding holds: the pinned digests recompute over the bytes as fetched.
    assert isinstance(binding, TxBindingOk), vector["name"]
    assert blake2b_256(tx_body).hex() == vector["requested_tx_hash_hex"]
    committed = auxiliary_data_hash_from_tx_body(tx_body)
    assert committed is not None
    assert blake2b_256(auxiliary_data) == committed

    unwrapped = unwrap_auxiliary_data(auxiliary_data)
    if expected.get("error_code") == "METADATA_NOT_FOUND":
        # Both bindings hold but the bound transaction carries no label-309
        # metadata: the verifier-layer METADATA_NOT_FOUND outcome.
        assert unwrapped.label_309 is None, vector["name"]
        return

    assert expected["ok"] is True
    assert expected["computed_tx_hash_hex"] == blake2b_256(tx_body).hex()
    assert expected["computed_auxiliary_data_hash_hex"] == blake2b_256(auxiliary_data).hex()
    assert unwrapped.label_309 is not None
    reassembly = reassemble_label_309_value(unwrapped.label_309)
    assert isinstance(reassembly, Label309ReassemblyOk)
    assert reassembly.body.hex() == expected["record_body_hex"]


@pytest.mark.parametrize("vector", _CONFIRMATION_DEPTH, ids=lambda v: cast(str, v["name"]))
def test_confirmation_depth(vector: dict[str, Any]) -> None:
    record_body = encode_poe_record({"v": 1, "items": [{"hashes": {"sha2-256": b"\x11" * 32}}]})
    tx_hash, tx_cbor = make_bound_tx(record_body)
    routes = koios_routes(
        tx_hash,
        tx_cbor,
        num_confirmations=None,
        block_height=vector["block_height"],
        tip_height=vector["tip_height"],
    )
    report = asyncio.run(
        verify_tx(
            VerifyTxInput(
                tx_hash=tx_hash,
                cardano_gateway_chain=(KOIOS_URL,),
                fetch_outbound=route_fetch(routes),
                confirmation_depth_threshold=vector["threshold"],
            )
        )
    )
    assert report.confirmation_depth == vector["expected_depth"], vector["name"]
    expected = cast(dict[str, Any], vector["expected"])
    if expected["status"] == "pending":
        assert report.verdict == "pending"
        assert report.exit_code == 3
        assert any(i.code == expected["code"] for i in report.issues)
    else:
        assert report.verdict == "valid"
        assert report.exit_code == 0
        assert not any(i.code == "INSUFFICIENT_CONFIRMATIONS" for i in report.issues)
