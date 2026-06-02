"""Position-aware CBOR walker for byte-faithful label-309 metadata extraction.

The verifier MUST fetch raw transaction CBOR and extract the label-309 value
VERBATIM (not via decode-then-re-encode). A re-encode pass would silently
launder a non-conformant on-chain record into a conformant one because the
decoder normalises non-canonical input (sorts map keys, collapses
indefinite-length encodings, etc.); the structural validator's canonical-CBOR
check only catches the violation if it sees the producer's original bytes.

Pure stdlib walker (no `cbor2` dependency for the slicing path). Rejects
indefinite-length encodings, which canonical CBOR forbids; the structural
validator downstream performs the rest of the deterministic-encoding checks.
"""

from __future__ import annotations

from dataclasses import dataclass


class MalformedTxCborError(ValueError):
    """Raised on a structural CBOR violation while walking raw tx bytes.

    Carries the `MALFORMED_CBOR` code so the verifier surfaces it under the
    `MALFORMED_CBOR` validation issue (matching the TS twin's
    `RangeError("MALFORMED_CBOR: …")`).
    """

    def __init__(self, message: str) -> None:
        super().__init__(f"MALFORMED_CBOR: {message}")
        self.code: str = "MALFORMED_CBOR"


@dataclass(frozen=True)
class _CborHead:
    mt: int
    ai: int
    payload_start: int
    value_u64: int


def _read_head(data: bytes, pos: int) -> _CborHead:
    if pos >= len(data):
        raise MalformedTxCborError("truncated input (no head byte)")
    head = data[pos]
    mt = head >> 5
    ai = head & 0x1F
    p = pos + 1
    value_u64: int
    if ai < 24:
        value_u64 = ai
    elif ai == 24:
        if p + 1 > len(data):
            raise MalformedTxCborError("truncated 1-byte argument")
        value_u64 = data[p]
        p += 1
    elif ai == 25:
        if p + 2 > len(data):
            raise MalformedTxCborError("truncated 2-byte argument")
        value_u64 = (data[p] << 8) | data[p + 1]
        p += 2
    elif ai == 26:
        if p + 4 > len(data):
            raise MalformedTxCborError("truncated 4-byte argument")
        value_u64 = int.from_bytes(data[p : p + 4], "big")
        p += 4
    elif ai == 27:
        if p + 8 > len(data):
            raise MalformedTxCborError("truncated 8-byte argument")
        value_u64 = int.from_bytes(data[p : p + 8], "big")
        p += 8
    elif ai == 31:
        raise MalformedTxCborError(
            "indefinite-length encoding (ai=31) not allowed under canonical CBOR"
        )
    else:
        raise MalformedTxCborError(f"reserved additional info ai={ai}")
    return _CborHead(mt=mt, ai=ai, payload_start=p, value_u64=value_u64)


def _skip_cbor_item(data: bytes, pos: int) -> int:
    h = _read_head(data, pos)
    p = h.payload_start
    if h.mt in (0, 1):
        return p
    if h.mt in (2, 3):
        if p + h.value_u64 > len(data):
            kind = "byte" if h.mt == 2 else "text"
            raise MalformedTxCborError(f"truncated {kind} string payload")
        return p + h.value_u64
    if h.mt == 4:
        for _ in range(h.value_u64):
            p = _skip_cbor_item(data, p)
        return p
    if h.mt == 5:
        for _ in range(h.value_u64 * 2):
            p = _skip_cbor_item(data, p)
        return p
    if h.mt == 6:
        return _skip_cbor_item(data, p)
    if h.mt == 7:
        if h.ai < 24:
            return p
        if h.ai == 24:
            if p + 1 > len(data):
                raise MalformedTxCborError("truncated simple value")
            return p + 1
        if h.ai in (25, 26, 27):
            return p
        raise MalformedTxCborError(f"unsupported major-7 ai={h.ai}")
    raise MalformedTxCborError(f"unknown major type {h.mt}")


# CBOR tag 259 wraps post-Alonzo auxiliary_data (CIP-29).
_CARDANO_AUX_DATA_TAG = 259
_POE_LABEL = 309


@dataclass(frozen=True)
class TxComponents:
    """Byte-faithful components of a Cardano transaction.

    `tx_body` and `witness_set` are EXACT on-chain byte slices:
    `blake2b256(tx_body)` equals the transaction hash, and the witness set
    decodes to the vkey witnesses that authorised the transaction.

    `label309` is the reassembled label-309 value (chunked-bytes concatenated),
    `None` when auxiliary_data is null/undefined or label 309 is absent.
    `aux_metadata_labels` is the ascending-sorted list of every integer key in
    the auxiliary metadata map (`()` when aux is null).
    """

    label309: bytes | None
    tx_body: bytes
    witness_set: bytes
    aux_metadata_labels: tuple[int, ...]


def slice_tx_components(tx_cbor: bytes) -> TxComponents:
    """Walk the transaction CBOR once and return its byte-faithful components.

    Raises `MalformedTxCborError` on structural violations. The body and
    witness-set slices are the producer's ORIGINAL bytes; `label309` carries the
    same byte-faithful guarantee (no decode-then-re-encode, so non-canonical
    encodings reach the structural validator unchanged).
    """
    tx_head = _read_head(tx_cbor, 0)
    if tx_head.mt != 4:
        raise MalformedTxCborError(f"tx CBOR is not a CBOR array (major type {tx_head.mt})")
    if tx_head.value_u64 < 4:
        raise MalformedTxCborError(
            f"tx CBOR array has {tx_head.value_u64} elements; expected >= 4 "
            "(post-Conway: [body, witness_set, is_valid, auxiliary_data])"
        )

    body_start = tx_head.payload_start
    body_end = _skip_cbor_item(tx_cbor, body_start)
    witness_set_start = body_end
    witness_set_end = _skip_cbor_item(tx_cbor, witness_set_start)
    pos = _skip_cbor_item(tx_cbor, witness_set_end)  # skip is_valid

    tx_body = tx_cbor[body_start:body_end]
    witness_set = tx_cbor[witness_set_start:witness_set_end]

    if pos >= len(tx_cbor):
        raise MalformedTxCborError("truncated tx (auxiliary_data missing)")
    aux_first_byte = tx_cbor[pos]
    if aux_first_byte in (0xF6, 0xF7):
        return TxComponents(
            label309=None, tx_body=tx_body, witness_set=witness_set, aux_metadata_labels=()
        )

    aux_map_pos = pos
    aux_head = _read_head(tx_cbor, pos)
    if aux_head.mt == 6:
        if aux_head.value_u64 != _CARDANO_AUX_DATA_TAG:
            raise MalformedTxCborError(
                f"auxiliary_data carries unexpected CBOR tag {aux_head.value_u64}; "
                f"expected {_CARDANO_AUX_DATA_TAG} or bare map"
            )
        aux_map_pos = aux_head.payload_start

    map_head = _read_head(tx_cbor, aux_map_pos)
    if map_head.mt != 5:
        raise MalformedTxCborError(
            f"auxiliary_data is not a CBOR map (major type {map_head.mt})"
        )

    # Disambiguate the tagged (post-Alonzo, `{0 -> metadata, 1 -> ...}`) and
    # bare (pre-Alonzo, the map IS the metadata map) auxiliary_data shapes by
    # walking the map keys: if any int key in `{0,1,2,3}` is present, treat it
    # as the post-Alonzo shape and find key 0; else treat the whole map as
    # metadata directly. Modern Cardano txs (Conway+) are always tag-259
    # wrapped, but synthetic fixtures often emit the post-Alonzo shape bare.
    entry_pos = map_head.payload_start
    saw_aux_key = False
    found_metadata_at: int | None = None
    for _ in range(map_head.value_u64):
        key_head = _read_head(tx_cbor, entry_pos)
        if key_head.mt == 0 and key_head.value_u64 <= 3:
            saw_aux_key = True
            if key_head.value_u64 == 0:
                found_metadata_at = key_head.payload_start
        entry_pos = _skip_cbor_item(tx_cbor, entry_pos)  # skip key
        entry_pos = _skip_cbor_item(tx_cbor, entry_pos)  # skip value

    if saw_aux_key or aux_head.mt == 6:
        metadata_map_pos = found_metadata_at
    else:
        metadata_map_pos = aux_map_pos

    if metadata_map_pos is None:
        return TxComponents(
            label309=None, tx_body=tx_body, witness_set=witness_set, aux_metadata_labels=()
        )

    meta_head = _read_head(tx_cbor, metadata_map_pos)
    if meta_head.mt != 5:
        raise MalformedTxCborError(f"metadata is not a CBOR map (major type {meta_head.mt})")
    labels: list[int] = []
    label309: bytes | None = None
    pair_pos = meta_head.payload_start
    for _ in range(meta_head.value_u64):
        key_head = _read_head(tx_cbor, pair_pos)
        key_val = _decode_int_key(key_head)
        labels.append(key_val)
        value_start = _skip_cbor_item(tx_cbor, pair_pos)
        value_end = _skip_cbor_item(tx_cbor, value_start)
        if key_val == _POE_LABEL:
            label309 = _reassemble_label_309_value(tx_cbor, value_start, value_end)
        pair_pos = value_end
    labels.sort()
    return TxComponents(
        label309=label309,
        tx_body=tx_body,
        witness_set=witness_set,
        aux_metadata_labels=tuple(labels),
    )


def slice_label_309_value(tx_cbor: bytes) -> bytes | None:
    """Extract the byte slice corresponding to the value under metadata label 309.

    Returns `None` when auxiliary_data is null/undefined or when label 309 is
    absent. Raises `MalformedTxCborError` on structural violations. Returns the
    producer's ORIGINAL on-chain bytes — no decode-then-re-encode pass.
    """
    return slice_tx_components(tx_cbor).label309


def _reassemble_label_309_value(tx_cbor: bytes, value_start: int, value_end: int) -> bytes:
    """Reassemble the label-309 record body from its on-chain shape.

    Cardano caps individual metadata `bstr` / `tstr` values at 64 bytes, so a
    CIP-309 record's canonical CBOR is emitted as a `bytes-chunk-array`
    (`[ bstr .size (1..64), … ]`). The verifier byte-concatenates the chunks IN
    ORDER before validation. Small records (<= 64 bytes) MAY be a single `bstr`
    directly; a bare CBOR map value is accepted for backward-compat with older
    producers and small synthetic fixtures.
    """
    head = _read_head(tx_cbor, value_start)
    # Major type 4 = array -> chunked-bytes; concatenate inner bstr items.
    if head.mt == 4:
        out = bytearray()
        chunk_pos = head.payload_start
        for i in range(head.value_u64):
            chunk_head = _read_head(tx_cbor, chunk_pos)
            if chunk_head.mt != 2:
                raise MalformedTxCborError(
                    f"label-309 value is a CBOR array but element {i} has major type "
                    f"{chunk_head.mt}; expected byte string (chunked-bytes shape)"
                )
            chunk_value_start = chunk_head.payload_start
            chunk_value_end = chunk_value_start + chunk_head.value_u64
            out += tx_cbor[chunk_value_start:chunk_value_end]
            chunk_pos = chunk_value_end
        return bytes(out)
    # Major type 2 = single bstr value. The bstr CONTENTS are the canonical
    # CBOR record body — strip the bstr head so the validator sees the map.
    if head.mt == 2:
        return tx_cbor[head.payload_start : head.payload_start + head.value_u64]
    # Major type 5 = map directly (bare-canonical shape). Pass through unchanged.
    if head.mt == 5:
        return tx_cbor[value_start:value_end]
    raise MalformedTxCborError(
        f"label-309 value has major type {head.mt}; "
        "expected array (chunked), byte string, or map"
    )


def _decode_int_key(h: _CborHead) -> int:
    if h.mt == 0:
        return h.value_u64
    if h.mt == 1:
        return -1 - h.value_u64
    raise MalformedTxCborError(
        f"metadata map key has major type {h.mt}; expected unsigned integer"
    )


__all__ = [
    "MalformedTxCborError",
    "TxComponents",
    "slice_label_309_value",
    "slice_tx_components",
]
