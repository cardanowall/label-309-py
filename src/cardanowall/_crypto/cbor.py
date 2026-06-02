from __future__ import annotations

import cbor2
from cbor2 import CBORDecodeError

CanonicalCborValue = (
    None
    | bool
    | int
    | float
    | str
    | bytes
    | list["CanonicalCborValue"]
    | dict[str | int, "CanonicalCborValue"]
)


class CanonicalCborError(Exception):
    # Every canonical-CBOR decode violation collapses to this single public
    # CIP-309 taxonomy code: indefinite-length items, duplicate keys, unsorted
    # keys, non-minimal integers, invalid UTF-8. The specific cause survives in
    # the human-readable message, not as a separate code.
    MALFORMED_CBOR = "MALFORMED_CBOR"

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code: str = code


class _ScanAbort(Exception):
    pass


def encode_canonical_cbor(value: CanonicalCborValue) -> bytes:
    return cbor2.dumps(value, canonical=True)


def decode_canonical_cbor(data: bytes) -> object:
    _scan_for_noncanonical_maps(data)
    try:
        return cbor2.loads(data, allow_indefinite=False)
    except CBORDecodeError as e:
        raise _map_decode_error(e) from e


def decode_cbor_permissive(data: bytes) -> object:
    # Outer Cardano tx CBOR is not constrained to canonical form (indefinite-length,
    # unsorted maps); CIP-309 records themselves MUST go through decode_canonical_cbor.
    return cbor2.loads(data)


# PyPI cbor2 6.x is C-extension only and does not enforce RFC 8949 §4.2.1
# deterministic-decode rules for maps: it neither rejects duplicate keys nor
# rejects non-canonical (unsorted) key ordering. The reference TS twin
# (cbor2.js with `rejectDuplicateKeys`) rejects BOTH, so to keep the two
# implementations byte/code-identical we run a structural pre-scan here that
# enforces map-key uniqueness AND canonical bytewise-lexicographic ordering on
# the encoded key bytes (RFC 8949 §4.2.1). Both violations surface as the same
# MALFORMED_CBOR code — the CIP-309 taxonomy has no separate duplicate-key
# entry. Any structural problem the scan can't parse is left to cbor2 to reject.
def _scan_for_noncanonical_maps(data: bytes) -> None:
    try:
        _walk(data, 0)
    except _ScanAbort:
        return


def _walk(data: bytes, pos: int) -> int:
    n = len(data)
    if pos >= n:
        raise _ScanAbort
    ib = data[pos]
    pos += 1
    major = ib >> 5
    addl = ib & 0x1F
    if addl == 31:
        raise _ScanAbort
    if major == 7:
        # A CIP-309 record carries integers, byte/text strings, arrays, maps and
        # `null` — and nothing else. The major-type-7 surface admits only the
        # three primitives we allow: false (0xf4), true (0xf5), null (0xf6).
        # Everything else on this surface — undefined (0xf7), the simple-value
        # range, and ALL floats (float16/32/64) — is rejected. This is the
        # byte-identical parity twin of the TS decoder's rejectFloats /
        # rejectSimple / rejectUndefined / rejectNegativeZero options. Without
        # it, a float16/32/64 holding an integral value (e.g. 1.0) decodes to a
        # Python float that compares equal to int 1 and slips past a schema
        # check, so two byte strings that are NOT byte-identical would
        # canonicalise to the same record — breaking cross-impl parity.
        if addl not in (20, 21, 22):
            raise CanonicalCborError(
                CanonicalCborError.MALFORMED_CBOR,
                "major-type-7 value is not one of {false, true, null} "
                "(floats, simple values and undefined are not valid in a CIP-309 record)",
            )
        return pos

    arg, pos = _read_arg(data, pos, addl)
    if major in (0, 1):
        return pos
    if major in (2, 3):
        if pos + arg > n:
            raise _ScanAbort
        return pos + arg
    if major == 4:
        for _ in range(arg):
            pos = _walk(data, pos)
        return pos
    if major == 5:
        prev_key: bytes | None = None
        for _ in range(arg):
            key_start = pos
            pos = _walk(data, pos)
            key_bytes = data[key_start:pos]
            if prev_key is not None and key_bytes <= prev_key:
                # `<` would be a sort violation (non-canonical order); `==` is a
                # duplicate. RFC 8949 §4.2.1 requires strictly-increasing
                # bytewise-lexicographic encoded keys, so both fail under one code.
                raise CanonicalCborError(
                    CanonicalCborError.MALFORMED_CBOR,
                    "map keys are not in canonical order or contain duplicates",
                )
            prev_key = key_bytes
            pos = _walk(data, pos)
        return pos
    if major == 6:
        return _walk(data, pos)
    raise _ScanAbort


def _read_arg(data: bytes, pos: int, addl: int) -> tuple[int, int]:
    n = len(data)
    if addl < 24:
        return addl, pos
    if addl == 24:
        if pos + 1 > n:
            raise _ScanAbort
        return data[pos], pos + 1
    if addl == 25:
        if pos + 2 > n:
            raise _ScanAbort
        return int.from_bytes(data[pos : pos + 2], "big"), pos + 2
    if addl == 26:
        if pos + 4 > n:
            raise _ScanAbort
        return int.from_bytes(data[pos : pos + 4], "big"), pos + 4
    if addl == 27:
        if pos + 8 > n:
            raise _ScanAbort
        return int.from_bytes(data[pos : pos + 8], "big"), pos + 8
    raise _ScanAbort


def _map_decode_error(cause: CBORDecodeError) -> CanonicalCborError:
    # Every canonical-decode failure collapses to MALFORMED_CBOR — indefinite-
    # length (streaming) items, duplicate keys, non-canonical ordering, non-
    # minimal ints, invalid UTF-8. Duplicate / unsorted maps are caught by the
    # pre-scan above and never reach here. The specific cause survives in the
    # message; for indefinite-length we state it explicitly so the diagnostic is
    # not lost when the code is collapsed.
    message = str(cause).lower()
    is_indefinite = "indefinite" in message or "streaming" in message
    detail = (
        f"indefinite-length items are not permitted in canonical CBOR: {cause}"
        if is_indefinite
        else str(cause)
    )
    return CanonicalCborError(CanonicalCborError.MALFORMED_CBOR, f"cbor decode failed: {detail}")
