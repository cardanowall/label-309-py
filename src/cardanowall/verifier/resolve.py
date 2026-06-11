"""Cardano transaction resolution over the configured explorer chain.

Resolution fetches the RAW on-chain transaction CBOR — never an explorer's
metadata-JSON projection, which is lossy (it discards map-key ordering,
definite-vs-indefinite length, integer/float discrimination, and
bytes-vs-text discrimination), so a verifier re-encoding from it could not
reproduce the byte-exact signing input.

Every provider response passes the transaction-reference integrity binding
BEFORE anything is read out of it; a response that fails the binding is
discarded and the next provider is tried. Resolution distinguishes three
terminal negatives, in evidence order:

  - ``TX_INTEGRITY_MISMATCH`` — at least one provider actively served bytes
    that fail the blake2b-256 binding to the requested reference, and no
    provider's response survived it. Provider-attributable; verdict
    ``unverifiable`` (no record bytes were ever obtained).
  - ``TX_NOT_FOUND`` — at least one provider answered definitively that it
    knows no such transaction, and none had it. A single provider's negative
    is not chain-authoritative, so every remaining provider is consulted
    first. Network class; verdict ``unverifiable``.
  - ``PROVIDER_UNAVAILABLE`` — every provider was unreachable or returned no
    usable response. Network class; verdict ``unverifiable``.

A resolve-path call to a ``denyHosts`` entry is different in kind: it is
TERMINAL for the whole chain (``SERVICE_INDEPENDENCE_VIOLATION``, verdict
``failed``) — rotating providers must not mask a service-independence
violation.

Chain facts (tip height, block height, block time, block slot) are
explorer-asserted; the binding cannot establish them. Confirmation depth is
counted in blocks: ``depth = tip - block + 1``, so a transaction in the tip
block has depth exactly 1.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Final, Literal, cast

from .cbor_walker import MalformedTxCborError, TxComponents, slice_tx_components
from .fetch import DenyHostError
from .tx_binding import TxBindingFail, bind_transaction_bytes
from .types import FetchOutbound, FetchOutboundOptions, VerifyTxInput

KOIOS_MAINNET_URL: Final[str] = "https://api.koios.rest/api/v1"
BLOCKFROST_MAINNET_HOST: Final[str] = "https://cardano-mainnet.blockfrost.io/api/v0"


@dataclass(frozen=True, kw_only=True)
class ResolvedTx:
    tx_cbor: bytes
    components: TxComponents
    confirmation_depth: int
    block_time: int  # POSIX seconds UTC
    block_slot: int
    provider: Literal["koios", "blockfrost"]
    provider_url: str


@dataclass(frozen=True, kw_only=True)
class ResolveFailure:
    code: Literal[
        "TX_NOT_FOUND",
        "TX_INTEGRITY_MISMATCH",
        "PROVIDER_UNAVAILABLE",
        "SERVICE_INDEPENDENCE_VIOLATION",
    ]
    message: str


ResolveOutcome = ResolvedTx | ResolveFailure


class _ProviderNegative(Exception):
    """The provider answered definitively that it knows no such transaction."""


class _ProviderBindingFailed(Exception):
    """The provider served transaction bytes that failed the integrity
    binding against the requested reference."""


async def resolve_cardano_tx(*, input: VerifyTxInput, fetch_fn: FetchOutbound) -> ResolveOutcome:
    # `None` means "use the default Koios chain"; an EMPTY tuple means "no
    # Koios gateways" (caller routes straight to Blockfrost) — distinct from
    # None.
    koios_chain = (
        (KOIOS_MAINNET_URL,) if input.cardano_gateway_chain is None else input.cardano_gateway_chain
    )

    saw_negative: str | None = None
    saw_binding_failure: str | None = None
    last_unusable: str | None = None

    for koios_url in koios_chain:
        try:
            return await _resolve_via_koios(input.tx_hash, koios_url, fetch_fn)
        except _ProviderNegative as e:
            saw_negative = str(e)
        except _ProviderBindingFailed as e:
            saw_binding_failure = str(e)
        except DenyHostError as e:
            # A resolve-path call targeted a denyHosts entry: terminal for the
            # whole chain — rotating providers must not mask a
            # service-independence violation.
            return ResolveFailure(code="SERVICE_INDEPENDENCE_VIOLATION", message=str(e))
        except Exception as e:
            last_unusable = f"{koios_url}: {e}"

    if input.blockfrost_project_id is not None:
        try:
            return await _resolve_via_blockfrost(
                input.tx_hash, input.blockfrost_project_id, fetch_fn
            )
        except _ProviderNegative as e:
            saw_negative = str(e)
        except _ProviderBindingFailed as e:
            saw_binding_failure = str(e)
        except DenyHostError as e:
            return ResolveFailure(code="SERVICE_INDEPENDENCE_VIOLATION", message=str(e))
        except Exception as e:
            last_unusable = f"{BLOCKFROST_MAINNET_HOST}: {e}"

    # Evidence precedence: a provider that actively served wrong bytes is the
    # strongest signal, then a definitive negative answer, then plain
    # unreachability.
    if saw_binding_failure is not None:
        return ResolveFailure(
            code="TX_INTEGRITY_MISMATCH",
            message=(
                "no provider response survived the transaction-reference binding: "
                f"{saw_binding_failure}"
            ),
        )
    if saw_negative is not None:
        return ResolveFailure(
            code="TX_NOT_FOUND",
            message=f"no consulted provider knows transaction {input.tx_hash}: {saw_negative}",
        )
    return ResolveFailure(
        code="PROVIDER_UNAVAILABLE",
        message=last_unusable if last_unusable is not None else "no provider configured",
    )


# Bind a fetched transaction's bytes to the requested reference. Runs the
# moment the bytes arrive — BEFORE any further chain-fact call against the
# same provider, so a provider serving wrong bytes is identified without
# spending more calls on it, and a later tip/info failure can never mask the
# stronger integrity evidence.
def _bind_fetched_tx(*, tx_hash: str, tx_cbor: bytes, provider_url: str) -> TxComponents:
    try:
        components = slice_tx_components(tx_cbor)
    except MalformedTxCborError as e:
        raise RuntimeError(f"response is not parseable transaction CBOR ({e})") from e
    binding = bind_transaction_bytes(
        requested_tx_hash_hex=tx_hash,
        tx_body=components.tx_body,
        auxiliary_data=components.auxiliary_data,
    )
    if isinstance(binding, TxBindingFail):
        raise _ProviderBindingFailed(f"{provider_url}: {binding.message}")
    return components


async def _resolve_via_koios(tx_hash: str, koios_url: str, fetch_fn: FetchOutbound) -> ResolvedTx:
    cbor_res = await fetch_fn(
        f"{koios_url}/tx_cbor",
        FetchOutboundOptions(
            method="POST",
            purpose="cardano",
            headers={"content-type": "application/json", "accept": "application/json"},
            body=json.dumps({"_tx_hashes": [tx_hash]}),
        ),
    )
    if cbor_res.status != 200:
        raise RuntimeError(f"tx_cbor returned HTTP {cbor_res.status}")
    cbor_json = _parse_json(cbor_res.bytes)
    if not isinstance(cbor_json, list):
        raise RuntimeError("tx_cbor returned a non-array body")
    if len(cbor_json) == 0:
        # An empty result set is Koios's definitive "I know no such tx".
        raise _ProviderNegative(f"{koios_url} returned an empty tx_cbor result set")
    cbor_entry_raw = cbor_json[0]
    if not isinstance(cbor_entry_raw, dict):
        raise RuntimeError("tx_cbor entry is not an object")
    cbor_field = cast(dict[str, object], cbor_entry_raw).get("cbor")
    if not isinstance(cbor_field, str):
        raise RuntimeError("tx_cbor entry carries no cbor field")
    tx_cbor = _hex_to_bytes(cbor_field)
    components = _bind_fetched_tx(tx_hash=tx_hash, tx_cbor=tx_cbor, provider_url=koios_url)

    info_res = await fetch_fn(
        f"{koios_url}/tx_info",
        FetchOutboundOptions(
            method="POST",
            purpose="cardano",
            headers={"content-type": "application/json", "accept": "application/json"},
            body=json.dumps({"_tx_hashes": [tx_hash]}),
        ),
    )
    if info_res.status != 200:
        raise RuntimeError(f"tx_info returned HTTP {info_res.status}")
    info_json = _parse_json(info_res.bytes)
    if not isinstance(info_json, list) or len(info_json) == 0:
        raise RuntimeError("tx_info returned no entry")
    info_entry_raw = info_json[0]
    if not isinstance(info_entry_raw, dict):
        raise RuntimeError("tx_info entry is not an object")
    info_entry = cast(dict[str, object], info_entry_raw)

    # Koios v1 `/tx_info` carries `block_height` but (on current deployments)
    # no `num_confirmations`; depth is computed as tip - block + 1, with a
    # direct read kept for older deployments that still serve the field.
    num_confirmations_raw = info_entry.get("num_confirmations")
    if isinstance(num_confirmations_raw, int) and not isinstance(num_confirmations_raw, bool):
        confirmation_depth = _require_non_negative_int(num_confirmations_raw, "num_confirmations")
        # A served count of 0 for a transaction the provider itself reports as
        # on-chain is the same self-contradiction as a lagging tip (see
        # _depth_from_heights): the snapshot is unusable.
        if confirmation_depth < 1:
            raise RuntimeError(
                "inconsistent provider snapshot: num_confirmations is 0 for an on-chain transaction"
            )
    else:
        tx_block_height = _require_non_negative_int(info_entry.get("block_height"), "block_height")
        tip_res = await fetch_fn(
            f"{koios_url}/tip",
            FetchOutboundOptions(
                method="GET", purpose="cardano", headers={"accept": "application/json"}
            ),
        )
        if tip_res.status != 200:
            raise RuntimeError(f"tip returned HTTP {tip_res.status}")
        tip_json = _parse_json(tip_res.bytes)
        if not isinstance(tip_json, list) or len(tip_json) == 0:
            raise RuntimeError("tip returned no entry")
        tip_entry_raw = tip_json[0]
        if not isinstance(tip_entry_raw, dict):
            raise RuntimeError("tip entry is not an object")
        tip_height = _require_non_negative_int(
            cast(dict[str, object], tip_entry_raw).get("block_height"), "tip.block_height"
        )
        confirmation_depth = _depth_from_heights(tip_height, tx_block_height)

    return ResolvedTx(
        tx_cbor=tx_cbor,
        components=components,
        confirmation_depth=confirmation_depth,
        block_time=_require_non_negative_int(info_entry.get("tx_timestamp"), "tx_timestamp"),
        block_slot=_require_non_negative_int(info_entry.get("absolute_slot"), "absolute_slot"),
        provider="koios",
        provider_url=koios_url,
    )


async def _resolve_via_blockfrost(
    tx_hash: str, project_id: str, fetch_fn: FetchOutbound
) -> ResolvedTx:
    base = BLOCKFROST_MAINNET_HOST
    headers = {"project_id": project_id, "accept": "application/json"}

    cbor_res = await fetch_fn(
        f"{base}/txs/{tx_hash}/cbor",
        FetchOutboundOptions(method="GET", purpose="cardano", headers=headers),
    )
    if cbor_res.status == 404:
        raise _ProviderNegative(f"{base} returned 404 for the transaction")
    if cbor_res.status != 200:
        raise RuntimeError(f"tx cbor returned HTTP {cbor_res.status}")
    cbor_json = _parse_json(cbor_res.bytes)
    if not isinstance(cbor_json, dict):
        raise RuntimeError("tx cbor response is not an object")
    cbor_field = cast(dict[str, object], cbor_json).get("cbor")
    if not isinstance(cbor_field, str):
        raise RuntimeError("tx cbor response carries no cbor field")
    tx_cbor = _hex_to_bytes(cbor_field)
    components = _bind_fetched_tx(tx_hash=tx_hash, tx_cbor=tx_cbor, provider_url=base)

    tx_res = await fetch_fn(
        f"{base}/txs/{tx_hash}",
        FetchOutboundOptions(method="GET", purpose="cardano", headers=headers),
    )
    if tx_res.status != 200:
        raise RuntimeError(f"tx info returned HTTP {tx_res.status}")
    tx_json_raw = _parse_json(tx_res.bytes)
    if not isinstance(tx_json_raw, dict):
        raise RuntimeError("tx info response is not an object")
    tx_json = cast(dict[str, object], tx_json_raw)
    block_time = _require_non_negative_int(tx_json.get("block_time"), "block_time")
    block_slot = _require_non_negative_int(tx_json.get("slot"), "slot")
    # Confirmations are counted in BLOCKS, not slots: Cardano's active-slot
    # coefficient f=0.05 means only ~1 slot in 20 produces a block, so a
    # slot-difference count would inflate depth by ~20x.
    tx_block_height = _require_non_negative_int(tx_json.get("block_height"), "block_height")

    tip_res = await fetch_fn(
        f"{base}/blocks/latest",
        FetchOutboundOptions(method="GET", purpose="cardano", headers=headers),
    )
    if tip_res.status != 200:
        raise RuntimeError(f"blocks/latest returned HTTP {tip_res.status}")
    tip_json_raw = _parse_json(tip_res.bytes)
    if not isinstance(tip_json_raw, dict):
        raise RuntimeError("blocks/latest response is not an object")
    tip_height = _require_non_negative_int(
        cast(dict[str, object], tip_json_raw).get("height"), "tip_height"
    )

    return ResolvedTx(
        tx_cbor=tx_cbor,
        components=components,
        confirmation_depth=_depth_from_heights(tip_height, tx_block_height),
        block_time=block_time,
        block_slot=block_slot,
        provider="blockfrost",
        provider_url=base,
    )


# depth = tip - block + 1; a transaction in the tip block has depth exactly 1.
# A provider whose tip height is below the height of the block it itself
# reports for the transaction contradicts its own snapshot. An internally
# inconsistent snapshot proves only that the provider's view is unusable, so
# the provider is discarded through the per-provider failure path (the raise
# lands in the caller's unusable handling) and contributes no chain facts — a
# depth is never fabricated by flooring.
def _depth_from_heights(tip_height: int, block_height: int) -> int:
    depth = tip_height - block_height + 1
    if depth < 1:
        raise RuntimeError(
            f"inconsistent provider snapshot: tip height {tip_height} is below "
            f"the transaction's block height {block_height}"
        )
    return depth


def _parse_json(data: bytes) -> object:
    return json.loads(data.decode("utf-8"))


def _require_non_negative_int(value: object, field: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ValueError(f"gateway_field_invalid: {field} (got {type(value).__name__}={value!r})")
    return value


def _hex_to_bytes(hex_str: str) -> bytes:
    s = hex_str[2:] if hex_str.startswith(("0x", "0X")) else hex_str
    if not re.fullmatch(r"[0-9a-fA-F]*", s) or len(s) % 2 != 0:
        raise ValueError(f"invalid hex: {hex_str!r}")
    return bytes.fromhex(s)


__all__ = [
    "BLOCKFROST_MAINNET_HOST",
    "KOIOS_MAINNET_URL",
    "ResolveFailure",
    "ResolveOutcome",
    "ResolvedTx",
    "resolve_cardano_tx",
]
