"""Metadata-label-309 carriage: the whole-body chunk-array transport.

The Cardano ledger caps every metadata byte string and text string at 64
bytes, so a serialised record body crosses the ledger as an opaque whole-body
chunk array: a definite-length CBOR array of definite-length byte strings of
at most 64 bytes each, whose in-order concatenation is the canonical
record-body bytes. This transport split is the ONLY chunking the format
performs — fields inside the reassembled body are ordinary CBOR values with
no per-field chunk wrappers and no 64-byte cap of their own.

This module owns both directions of that transport:

  - ``chunk_record_body``         — producer: canonical body bytes → the chunk
                                    array stored as the label-309 value.
  - ``reassemble_label_309_value``— consumer: raw label-309 value bytes → the
                                    record body, enforcing the carriage-error
                                    taxonomy (``MALFORMED_CBOR`` for every
                                    non-chunk-array shape, ``CHUNK_TOO_LARGE``
                                    for an oversized element, zero-length
                                    elements tolerated).

Reassembly happens BEFORE structural validation: ``validate`` receives the
concatenated body and never sees the transport wrapper.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final, cast

from cardanowall._crypto.cbor import CanonicalCborValue, encode_canonical_cbor
from cardanowall.poe_standard import severity_of

from .types import VerifierIssue

# The ledger's per-metadatum string cap: the maximum transport chunk size.
TRANSPORT_CHUNK_MAX_BYTES: Final[int] = 64


def chunk_record_body(body: bytes) -> list[bytes]:
    """Split a serialised record body into the whole-body transport chunk
    array — the value a producer stores under metadata label 309.

    Uses the minimal split: every chunk except the last is exactly 64 bytes.
    The chunk-array form is required regardless of body length, so a body of
    64 bytes or fewer still yields a one-element array.

    A canonical CBOR record body is never empty, so zero-length input is a
    caller bug and raises ``ValueError`` (the ``1* bstr`` transport grammar
    cannot represent an empty body).
    """
    if len(body) == 0:
        raise ValueError("record body must be non-empty; a CBOR value is at least one byte")
    return [
        bytes(body[offset : offset + TRANSPORT_CHUNK_MAX_BYTES])
        for offset in range(0, len(body), TRANSPORT_CHUNK_MAX_BYTES)
    ]


def encode_label_309_value(body: bytes) -> bytes:
    """Serialise the transport chunk array to the CBOR bytes of the label-309
    value (the byte form of ``chunk_record_body``'s output). Convenience for
    producers and test harnesses that embed the value at the byte level."""
    return encode_canonical_cbor(cast("CanonicalCborValue", chunk_record_body(body)))


@dataclass(frozen=True)
class Label309ReassemblyOk:
    ok: bool
    body: bytes


@dataclass(frozen=True)
class Label309ReassemblyFail:
    ok: bool
    issue: VerifierIssue


Label309ReassemblyResult = Label309ReassemblyOk | Label309ReassemblyFail


def reassemble_label_309_value(value_bytes: bytes) -> Label309ReassemblyResult:
    """Reassemble a label-309 value into the record body, enforcing the
    carriage-error taxonomy:

      - a definite-length array of definite-length byte strings each ≤ 64
        bytes is accepted; the body is the in-order concatenation;
      - zero-length elements are tolerated (chunk boundaries are
        semantics-free, including degenerate ones) — an array whose
        concatenation is empty reassembles to zero bytes, and the failure
        then surfaces from the canonical decode of the empty body, not from
        this layer;
      - an element longer than 64 bytes is ``CHUNK_TOO_LARGE``;
      - every other shape — a non-array value, a non-byte-string element, an
        indefinite-length array or element, a non-minimal length header — is
        ``MALFORMED_CBOR``.

    The input is the raw CBOR bytes of the label-309 value exactly as carried
    in the transaction's auxiliary data.
    """
    head = _read_strict_head(value_bytes, 0)
    if head is None:
        return _failure("MALFORMED_CBOR", "label-309 value failed to decode as canonical CBOR")
    if head.mt != 4:
        return _failure(
            "MALFORMED_CBOR",
            "label-309 value must be the whole-body chunk array (a CBOR array of "
            "byte strings), regardless of body length",
        )
    pos = head.payload_start
    chunks: list[bytes] = []
    for i in range(head.value):
        chunk_head = _read_strict_head(value_bytes, pos)
        if chunk_head is None:
            return _failure("MALFORMED_CBOR", f"chunk array element {i} failed to decode")
        if chunk_head.mt != 2:
            return _failure("MALFORMED_CBOR", f"chunk array element {i} is not a byte string")
        end = chunk_head.payload_start + chunk_head.value
        if end > len(value_bytes):
            return _failure("MALFORMED_CBOR", f"chunk array element {i} is truncated")
        if chunk_head.value > TRANSPORT_CHUNK_MAX_BYTES:
            return _failure(
                "CHUNK_TOO_LARGE",
                f"chunk array element {i} is {chunk_head.value} bytes; the ledger caps "
                f"metadata byte strings at {TRANSPORT_CHUNK_MAX_BYTES}",
            )
        chunks.append(value_bytes[chunk_head.payload_start : end])
        pos = end
    if pos != len(value_bytes):
        return _failure("MALFORMED_CBOR", "trailing bytes after the label-309 chunk array")
    return Label309ReassemblyOk(ok=True, body=b"".join(chunks))


def _failure(code: str, message: str) -> Label309ReassemblyFail:
    return Label309ReassemblyFail(
        ok=False,
        issue=VerifierIssue(
            code=code,
            path=(),
            message=message,
            severity=severity_of(code),  # type: ignore[arg-type]
        ),
    )


@dataclass(frozen=True)
class _StrictHead:
    mt: int
    value: int
    payload_start: int


# Canonical-CBOR head reader for the transport value: definite lengths only
# and shortest-form length arguments (a non-minimal head is MALFORMED_CBOR,
# matching the canonical decoder the record body itself is held to).
def _read_strict_head(data: bytes, pos: int) -> _StrictHead | None:
    if pos >= len(data):
        return None
    initial = data[pos]
    mt = initial >> 5
    ai = initial & 0x1F
    p = pos + 1
    if ai < 24:
        return _StrictHead(mt=mt, value=ai, payload_start=p)
    if ai == 24:
        if p + 1 > len(data):
            return None
        value = data[p]
        if value < 24:
            return None  # non-minimal
        return _StrictHead(mt=mt, value=value, payload_start=p + 1)
    if ai == 25:
        if p + 2 > len(data):
            return None
        value = int.from_bytes(data[p : p + 2], "big")
        if value <= 0xFF:
            return None  # non-minimal
        return _StrictHead(mt=mt, value=value, payload_start=p + 2)
    if ai == 26:
        if p + 4 > len(data):
            return None
        value = int.from_bytes(data[p : p + 4], "big")
        if value <= 0xFFFF:
            return None  # non-minimal
        return _StrictHead(mt=mt, value=value, payload_start=p + 4)
    if ai == 27:
        if p + 8 > len(data):
            return None
        value = int.from_bytes(data[p : p + 8], "big")
        if value <= 0xFFFF_FFFF:
            return None  # non-minimal
        return _StrictHead(mt=mt, value=value, payload_start=p + 8)
    # ai 28-30 reserved; ai 31 indefinite-length — both rejected.
    return None


__all__ = [
    "TRANSPORT_CHUNK_MAX_BYTES",
    "Label309ReassemblyFail",
    "Label309ReassemblyOk",
    "Label309ReassemblyResult",
    "chunk_record_body",
    "encode_label_309_value",
    "reassemble_label_309_value",
]
