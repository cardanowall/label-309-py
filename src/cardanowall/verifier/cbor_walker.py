"""Position-aware CBOR walker for byte-faithful transaction slicing.

The verifier MUST fetch raw transaction CBOR and consume its components
VERBATIM (never via decode-then-re-encode). A re-encode pass would silently
launder a non-conformant on-chain record into a conformant one because a
decoder normalises non-canonical input (sorts map keys, collapses
indefinite-length encodings, …); the structural validator's canonical-CBOR
check only catches a violation if it sees the producer's original bytes — and
the transaction-reference integrity binding (blake2b-256 over the body and
auxiliary-data bytes) is meaningful only over the bytes exactly as fetched.

Pure stdlib walker (no ``cbor2`` dependency on the slicing path). Rejects
indefinite-length encodings, which canonical CBOR forbids.
"""

from __future__ import annotations

from dataclasses import dataclass


class MalformedTxCborError(ValueError):
    """Raised on a structural CBOR violation while walking raw tx bytes.

    Carries the ``MALFORMED_CBOR`` code so the verifier surfaces it under the
    ``MALFORMED_CBOR`` issue."""

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


# CBOR tag 259 wraps the keyed-map auxiliary-data form (CIP-29 / Conway).
_CARDANO_AUX_DATA_TAG = 259
_POE_LABEL = 309
# Conway transaction-body key carrying the 32-byte auxiliary_data_hash.
_BODY_KEY_AUX_DATA_HASH = 7


@dataclass(frozen=True)
class TxComponents:
    """Byte-faithful components of a Cardano transaction.

    ``tx_body``, ``witness_set``, and ``auxiliary_data`` are EXACT on-chain
    byte slices: ``blake2b256(tx_body)`` equals the transaction id, and
    ``blake2b256(auxiliary_data)`` equals the body's ``auxiliary_data_hash``
    for a transaction that exists on chain. ``auxiliary_data`` is ``None``
    when the slot is CBOR null/undefined (or absent in a pre-Alonzo
    three-element transaction).
    """

    tx_body: bytes
    witness_set: bytes
    auxiliary_data: bytes | None


def slice_tx_components(tx_cbor: bytes) -> TxComponents:
    """Walk the transaction CBOR once and return its byte-faithful components.

    Accepts the four-element post-Alonzo shape
    ``[body, witness_set, is_valid, auxiliary_data]`` and the three-element
    pre-Alonzo shape ``[body, witness_set, auxiliary_data]``. Raises
    ``MalformedTxCborError`` on structural violations.
    """
    tx_head = _read_head(tx_cbor, 0)
    if tx_head.mt != 4:
        raise MalformedTxCborError(f"tx CBOR is not a CBOR array (major type {tx_head.mt})")
    if tx_head.value_u64 not in (3, 4):
        raise MalformedTxCborError(
            f"tx CBOR array has {tx_head.value_u64} elements; expected 3 "
            "([body, witness_set, auxiliary_data]) or 4 "
            "([body, witness_set, is_valid, auxiliary_data])"
        )

    body_start = tx_head.payload_start
    body_end = _skip_cbor_item(tx_cbor, body_start)
    witness_set_start = body_end
    witness_set_end = _skip_cbor_item(tx_cbor, witness_set_start)
    pos = witness_set_end
    if tx_head.value_u64 == 4:
        pos = _skip_cbor_item(tx_cbor, pos)  # skip is_valid

    tx_body = tx_cbor[body_start:body_end]
    witness_set = tx_cbor[witness_set_start:witness_set_end]

    if pos >= len(tx_cbor):
        raise MalformedTxCborError("truncated tx (auxiliary_data missing)")
    if tx_cbor[pos] in (0xF6, 0xF7):
        return TxComponents(tx_body=tx_body, witness_set=witness_set, auxiliary_data=None)
    aux_end = _skip_cbor_item(tx_cbor, pos)
    return TxComponents(
        tx_body=tx_body, witness_set=witness_set, auxiliary_data=tx_cbor[pos:aux_end]
    )


def auxiliary_data_hash_from_tx_body(tx_body: bytes) -> bytes | None:
    """Slice the 32-byte ``auxiliary_data_hash`` (body key 7) out of a
    byte-faithful transaction-body slice; ``None`` when the body carries no
    such key. Raises ``MalformedTxCborError`` on structural violations."""
    body_head = _read_head(tx_body, 0)
    if body_head.mt != 5:
        raise MalformedTxCborError(f"tx body is not a CBOR map (major type {body_head.mt})")
    pos = body_head.payload_start
    for _ in range(body_head.value_u64):
        key_head = _read_head(tx_body, pos)
        value_start = _skip_cbor_item(tx_body, pos)
        value_end = _skip_cbor_item(tx_body, value_start)
        if key_head.mt == 0 and key_head.value_u64 == _BODY_KEY_AUX_DATA_HASH:
            value_head = _read_head(tx_body, value_start)
            if value_head.mt != 2:
                raise MalformedTxCborError("auxiliary_data_hash is not a byte string")
            return tx_body[value_head.payload_start : value_end]
        pos = value_end
    return None


@dataclass(frozen=True)
class UnwrappedAuxiliaryData:
    """The label-309 value slice inside an auxiliary-data envelope.

    ``label_309`` is the raw CBOR bytes of the value under metadata label
    309 — the transport chunk array, byte-exact — or ``None`` when the
    well-formed auxiliary data simply carries no label-309 entry.
    ``metadata_labels`` is the ascending-sorted list of every metadata label
    in the envelope (empty when the envelope carries no metadata map).
    """

    label_309: bytes | None
    metadata_labels: tuple[int, ...]


def unwrap_auxiliary_data(aux_bytes: bytes) -> UnwrappedAuxiliaryData:
    """Unwrap auxiliary-data bytes down to the label-309 value slice.

    Accepts the three era envelope forms, dispatching purely on the top-level
    CBOR type and tag — NEVER on map-key inspection:

      - an untagged map is always the metadata map itself;
      - an untagged two-element array is ``[transaction_metadata,
        auxiliary_scripts]`` — the metadata map is element 0;
      - tag 259 is the keyed-map form — the metadata map sits under integer
        key 0 (a tag-259 map with no key 0 is well-formed auxiliary data that
        carries no metadata).

    Any other top-level shape, and any tag other than 259, raises
    ``MalformedTxCborError``. Key-sniffing heuristics are forbidden: a
    metadata map is keyed by integer labels, so treating a map that happens
    to contain a small-integer key as a keyed wrapper would silently
    mis-parse legitimate metadata.
    """
    head = _read_head(aux_bytes, 0)

    if head.mt == 6:
        if head.value_u64 != _CARDANO_AUX_DATA_TAG:
            raise MalformedTxCborError(
                f"auxiliary_data carries CBOR tag {head.value_u64}; only tag "
                f"{_CARDANO_AUX_DATA_TAG} is an auxiliary-data envelope"
            )
        inner_pos = head.payload_start
        inner_head = _read_head(aux_bytes, inner_pos)
        if inner_head.mt != 5:
            raise MalformedTxCborError(
                f"tag-259 auxiliary_data payload is not a CBOR map (major type {inner_head.mt})"
            )
        metadata_map_pos = _find_tag259_metadata_map(aux_bytes, inner_head)
        if metadata_map_pos is None:
            return UnwrappedAuxiliaryData(label_309=None, metadata_labels=())
        return _walk_metadata_map(aux_bytes, metadata_map_pos)

    if head.mt == 4:
        if head.value_u64 != 2:
            raise MalformedTxCborError(
                f"untagged auxiliary_data array has {head.value_u64} elements; the "
                "metadata-with-scripts form is exactly [transaction_metadata, auxiliary_scripts]"
            )
        first_head = _read_head(aux_bytes, head.payload_start)
        if first_head.mt != 5:
            raise MalformedTxCborError(
                "metadata-with-scripts auxiliary_data element 0 is not a CBOR map "
                f"(major type {first_head.mt})"
            )
        return _walk_metadata_map(aux_bytes, head.payload_start)

    if head.mt == 5:
        # An untagged map IS the metadata map itself — never key-sniffed.
        return _walk_metadata_map(aux_bytes, 0)

    raise MalformedTxCborError(
        f"auxiliary_data has top-level major type {head.mt}; expected map, "
        "two-element array, or tag 259"
    )


def _find_tag259_metadata_map(aux_bytes: bytes, map_head: _CborHead) -> int | None:
    pos = map_head.payload_start
    for _ in range(map_head.value_u64):
        key_head = _read_head(aux_bytes, pos)
        value_start = _skip_cbor_item(aux_bytes, pos)
        value_end = _skip_cbor_item(aux_bytes, value_start)
        if key_head.mt == 0 and key_head.value_u64 == 0:
            return value_start
        pos = value_end
    return None


def _walk_metadata_map(aux_bytes: bytes, map_pos: int) -> UnwrappedAuxiliaryData:
    meta_head = _read_head(aux_bytes, map_pos)
    if meta_head.mt != 5:
        raise MalformedTxCborError(f"metadata is not a CBOR map (major type {meta_head.mt})")
    labels: list[int] = []
    label_309: bytes | None = None
    pos = meta_head.payload_start
    for _ in range(meta_head.value_u64):
        key_head = _read_head(aux_bytes, pos)
        if key_head.mt != 0:
            raise MalformedTxCborError(
                f"metadata map key has major type {key_head.mt}; metadata labels are "
                "unsigned integers"
            )
        labels.append(key_head.value_u64)
        value_start = _skip_cbor_item(aux_bytes, pos)
        value_end = _skip_cbor_item(aux_bytes, value_start)
        if key_head.value_u64 == _POE_LABEL:
            label_309 = aux_bytes[value_start:value_end]
        pos = value_end
    labels.sort()
    return UnwrappedAuxiliaryData(label_309=label_309, metadata_labels=tuple(labels))


__all__ = [
    "MalformedTxCborError",
    "TxComponents",
    "UnwrappedAuxiliaryData",
    "auxiliary_data_hash_from_tx_body",
    "slice_tx_components",
    "unwrap_auxiliary_data",
]
