"""Transaction-reference integrity binding.

Before reading anything out of a fetched transaction, the verifier MUST bind
the fetched bytes to the caller-supplied transaction reference:

  1. blake2b-256 over the transaction-body bytes — by ledger definition, the
     transaction id — must equal the requested transaction hash;
  2. blake2b-256 over the auxiliary-data bytes must equal the
     ``auxiliary_data_hash`` field of the now-verified body.

Both digests are computed over the bytes EXACTLY as fetched, never over a
re-encoding. A response that fails either check carries provably wrong bytes:
the caller discards it and tries the next provider; if no provider survives,
the run reports ``TX_INTEGRITY_MISMATCH`` — provider-attributable, verdict
``unverifiable``, because no record bytes were ever obtained and the record
cannot be condemned by bytes a provider fabricated.

After the binding holds, every byte of the record body and of the surrounding
transaction is cryptographically committed to the requested transaction hash;
no explorer can substitute, amend, or truncate the record without producing a
blake2b-256 second preimage. The chain facts the binding does NOT establish —
inclusion, height, depth, slot, time — stay explorer-asserted.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from cardanowall._crypto.hash import blake2b_256

from .cbor_walker import MalformedTxCborError, auxiliary_data_hash_from_tx_body


@dataclass(frozen=True, kw_only=True)
class TxBindingOk:
    ok: Literal[True] = True


@dataclass(frozen=True, kw_only=True)
class TxBindingFail:
    ok: Literal[False] = False
    check: Literal["tx_hash", "auxiliary_data_hash"] = "tx_hash"
    message: str = ""


TxBindingResult = TxBindingOk | TxBindingFail


def bind_transaction_bytes(
    *,
    requested_tx_hash_hex: str,
    tx_body: bytes,
    auxiliary_data: bytes | None,
) -> TxBindingResult:
    """Bind fetched transaction components to the requested reference.

    ``tx_body`` and ``auxiliary_data`` are the byte-faithful slices of the
    fetched transaction (``slice_tx_components``); ``requested_tx_hash_hex``
    is the 32-byte transaction hash, either hex case accepted.
    """
    # Both sides are public values, so a plain comparison leaks nothing.
    requested = requested_tx_hash_hex.lower()
    computed_tx_hash = blake2b_256(tx_body).hex()
    if computed_tx_hash != requested:
        return TxBindingFail(
            check="tx_hash",
            message=(
                f"blake2b-256 of the fetched transaction body is {computed_tx_hash}, "
                f"not the requested {requested}"
            ),
        )

    try:
        committed = auxiliary_data_hash_from_tx_body(tx_body)
    except MalformedTxCborError as e:
        return TxBindingFail(check="auxiliary_data_hash", message=str(e))

    if auxiliary_data is None:
        if committed is not None:
            # The verified body commits to auxiliary data the response does
            # not carry: the provider served a provably incomplete
            # transaction.
            return TxBindingFail(
                check="auxiliary_data_hash",
                message=(
                    "the verified transaction body carries auxiliary_data_hash but the "
                    "response carries no auxiliary data"
                ),
            )
        return TxBindingOk()

    if committed is None:
        # Auxiliary data present but the body never committed to it — such a
        # transaction cannot exist on chain.
        return TxBindingFail(
            check="auxiliary_data_hash",
            message=(
                "auxiliary data is present but the verified transaction body carries no "
                "auxiliary_data_hash"
            ),
        )
    computed_aux_hash = blake2b_256(auxiliary_data)
    if computed_aux_hash != committed:
        return TxBindingFail(
            check="auxiliary_data_hash",
            message=(
                f"blake2b-256 of the fetched auxiliary data is {computed_aux_hash.hex()}, "
                f"not the body-committed {committed.hex()}"
            ),
        )
    return TxBindingOk()


__all__ = ["TxBindingFail", "TxBindingOk", "TxBindingResult", "bind_transaction_bytes"]
