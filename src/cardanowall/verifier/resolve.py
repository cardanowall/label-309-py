from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Final, Literal, cast

from .cbor_walker import slice_label_309_value
from .types import FetchOutbound, FetchOutboundOptions, VerifyTxInput

KOIOS_MAINNET_URL: Final[str] = "https://api.koios.rest/api/v1"
BLOCKFROST_MAINNET_HOST: Final[str] = "https://cardano-mainnet.blockfrost.io/api/v0"


@dataclass(frozen=True)
class ResolvedTx:
    tx_cbor: bytes
    num_confirmations: int
    block_time: int
    block_slot: int
    provider: Literal["koios", "blockfrost"]
    provider_url: str


class NotALabel309RecordError(Exception):
    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.code: str = "NOT_A_CARDANOWALL_RECORD"


async def resolve_cardano_tx(*, input: VerifyTxInput, fetch_fn: FetchOutbound) -> ResolvedTx:
    # `None` means "use the default Koios chain"; an EMPTY tuple means "no Koios
    # gateways" (caller routes straight to Blockfrost) — distinct from None,
    # matching the TS `?? [KOIOS_MAINNET_URL]` nullish-coalesce.
    koios_chain = (
        (KOIOS_MAINNET_URL,)
        if input.cardano_gateway_chain is None
        else input.cardano_gateway_chain
    )

    last_err: Exception | None = None
    for koios_url in koios_chain:
        try:
            return await _resolve_via_koios(input.tx_hash, koios_url, fetch_fn)
        except NotALabel309RecordError:
            raise
        except Exception as e:
            last_err = e

    if input.blockfrost_project_id is not None:
        try:
            return await _resolve_via_blockfrost(
                input.tx_hash, input.blockfrost_project_id, fetch_fn
            )
        except NotALabel309RecordError:
            raise
        except Exception as e:
            last_err = e

    raise RuntimeError(f"all_providers_failed: {last_err if last_err is not None else 'unknown'}")


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
        raise RuntimeError(f"koios_tx_cbor_{cbor_res.status}")
    cbor_json = _parse_json(cbor_res.bytes)
    if not isinstance(cbor_json, list) or len(cbor_json) == 0:
        raise NotALabel309RecordError("koios returned empty array for tx_cbor; tx may not exist")
    cbor_entry_raw = cbor_json[0]
    if not isinstance(cbor_entry_raw, dict):
        raise RuntimeError("koios_tx_cbor_malformed_entry")
    cbor_entry = cast(dict[str, object], cbor_entry_raw)
    cbor_field = cbor_entry.get("cbor")
    if not isinstance(cbor_field, str):
        raise RuntimeError("koios_tx_cbor_missing_cbor_field")
    tx_hash_field = cbor_entry.get("tx_hash")
    if isinstance(tx_hash_field, str) and tx_hash_field.lower() != tx_hash.lower():
        raise RuntimeError(f"koios_tx_cbor_hash_mismatch: requested {tx_hash} got {tx_hash_field}")
    tx_cbor = _hex_to_bytes(cbor_field)

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
        raise RuntimeError(f"koios_tx_info_{info_res.status}")
    info_json = _parse_json(info_res.bytes)
    if not isinstance(info_json, list) or len(info_json) == 0:
        raise NotALabel309RecordError("koios returned empty array for tx_info")
    info_entry_raw = info_json[0]
    if not isinstance(info_entry_raw, dict):
        raise RuntimeError("koios_tx_info_malformed_entry")
    info_entry = cast(dict[str, object], info_entry_raw)
    tx_hash_info = info_entry.get("tx_hash")
    if isinstance(tx_hash_info, str) and tx_hash_info.lower() != tx_hash.lower():
        raise RuntimeError(f"koios_tx_info_hash_mismatch: requested {tx_hash} got {tx_hash_info}")

    # Koios v1 `/tx_info` no longer returns `num_confirmations` — only
    # `block_height`. Confirmations are counted in BLOCKS (Cardano's
    # active-slot coefficient f=0.05 means a slot-difference count would inflate
    # by ~20x), so derive `max(0, tipHeight - txHeight + 1)` from the `/tip`
    # block_height. A deprecated direct read of `num_confirmations` stays as a
    # forward-compat fallback for older Koios deployments.
    num_confirmations_raw = info_entry.get("num_confirmations")
    if isinstance(num_confirmations_raw, int) and not isinstance(num_confirmations_raw, bool):
        num_confirmations = _require_non_negative_int(num_confirmations_raw, "num_confirmations")
    else:
        tx_block_height = _require_non_negative_int(info_entry.get("block_height"), "block_height")
        tip_res = await fetch_fn(
            f"{koios_url}/tip",
            FetchOutboundOptions(
                method="GET", purpose="cardano", headers={"accept": "application/json"}
            ),
        )
        if tip_res.status != 200:
            raise RuntimeError(f"koios_tip_{tip_res.status}")
        tip_json = _parse_json(tip_res.bytes)
        if not isinstance(tip_json, list) or len(tip_json) == 0:
            raise RuntimeError("koios_tip_empty")
        tip_entry_raw = tip_json[0]
        if not isinstance(tip_entry_raw, dict):
            raise RuntimeError("koios_tip_malformed_entry")
        tip_height = _require_non_negative_int(
            cast(dict[str, object], tip_entry_raw).get("block_height"), "tip.block_height"
        )
        num_confirmations = max(0, tip_height - tx_block_height + 1)

    return ResolvedTx(
        tx_cbor=tx_cbor,
        num_confirmations=num_confirmations,
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
    if cbor_res.status != 200:
        raise RuntimeError(f"blockfrost_tx_cbor_{cbor_res.status}")
    cbor_json = _parse_json(cbor_res.bytes)
    if not isinstance(cbor_json, dict):
        raise RuntimeError("blockfrost_tx_cbor_malformed")
    cbor_field = cast(dict[str, object], cbor_json).get("cbor")
    if not isinstance(cbor_field, str):
        raise RuntimeError("blockfrost_tx_cbor_missing_cbor_field")
    tx_cbor = _hex_to_bytes(cbor_field)

    tx_res = await fetch_fn(
        f"{base}/txs/{tx_hash}",
        FetchOutboundOptions(method="GET", purpose="cardano", headers=headers),
    )
    if tx_res.status != 200:
        raise RuntimeError(f"blockfrost_tx_{tx_res.status}")
    tx_json_raw = _parse_json(tx_res.bytes)
    if not isinstance(tx_json_raw, dict):
        raise RuntimeError("blockfrost_tx_malformed")
    tx_json = cast(dict[str, object], tx_json_raw)
    block_time = _require_non_negative_int(tx_json.get("block_time"), "block_time")
    tx_slot = _require_non_negative_int(tx_json.get("slot"), "slot")

    # Confirmations are counted in BLOCKS, not slots. Prefer Blockfrost's native
    # `confirmations` field when present; otherwise derive
    # `max(0, tipHeight - txHeight + 1)` from `block_height` (on `/txs/{hash}`)
    # and `height` (on `/blocks/latest`) — both are the block-number field.
    native_confirmations = tx_json.get("confirmations")
    if isinstance(native_confirmations, int) and not isinstance(native_confirmations, bool):
        num_confirmations = _require_non_negative_int(native_confirmations, "confirmations")
    else:
        tx_block_height = _require_non_negative_int(tx_json.get("block_height"), "block_height")
        tip_res = await fetch_fn(
            f"{base}/blocks/latest",
            FetchOutboundOptions(method="GET", purpose="cardano", headers=headers),
        )
        if tip_res.status != 200:
            raise RuntimeError(f"blockfrost_blocks_latest_{tip_res.status}")
        tip_json_raw = _parse_json(tip_res.bytes)
        if not isinstance(tip_json_raw, dict):
            raise RuntimeError("blockfrost_tip_malformed")
        tip_height = _require_non_negative_int(
            cast(dict[str, object], tip_json_raw).get("height"), "tip_height"
        )
        num_confirmations = max(0, tip_height - tx_block_height + 1)

    return ResolvedTx(
        tx_cbor=tx_cbor,
        num_confirmations=num_confirmations,
        block_time=block_time,
        block_slot=tx_slot,
        provider="blockfrost",
        provider_url=base,
    )


def extract_label_309_metadata(tx_cbor: bytes) -> bytes | None:
    # Byte-faithful label-309 extraction (delegates to the position-aware
    # `cbor_walker`, which never decode-then-re-encodes). The walker unwraps a
    # Conway tag-259 auxiliary_data, reassembles a chunked-bytes label-309 value
    # by byte-concatenation, and returns the producer's ORIGINAL record bytes —
    # so a non-canonical on-chain encoding surfaces as MALFORMED_CBOR at the
    # structural validator instead of being silently laundered.
    return slice_label_309_value(tx_cbor)


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
