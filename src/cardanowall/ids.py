"""Stripe-style prefixed resource IDs + Crockford base32 codec.

Parity twin of ``@cardanowall/sdk-ts`` ``src/ids``. Wire form is
``<prefix>_<26-char-crockford-base32>`` over a 16-byte UUIDv7 payload.

Crockford alphabet ``0123456789abcdefghjkmnpqrstvwxyz`` — the letters i,
l, o, u are excluded for visual disambiguation. Decoding is
case-insensitive and accepts the I/L → 1, O → 0 aliases; U is always
invalid.
"""

from __future__ import annotations

import re

_ALPHABET = "0123456789abcdefghjkmnpqrstvwxyz"

# Decode table: char code -> 5-bit value, -1 = invalid. ASCII < 128 only.
_DECODE_TABLE: list[int] = [-1] * 128
for _i, _ch in enumerate(_ALPHABET):
    _DECODE_TABLE[ord(_ch)] = _i
    _DECODE_TABLE[ord(_ch.upper())] = _i
# Crockford disambiguation: I/L -> 1, O -> 0. U/u stay invalid (reserved).
_DECODE_TABLE[ord("I")] = 1
_DECODE_TABLE[ord("i")] = 1
_DECODE_TABLE[ord("L")] = 1
_DECODE_TABLE[ord("l")] = 1
_DECODE_TABLE[ord("O")] = 0
_DECODE_TABLE[ord("o")] = 0

CROCKFORD_ENCODED_LENGTH_FOR_UUID = 26

# The CIP-309 record id is the one prefixed id the standard itself defines.
# The generic codec below works for any ``<prefix>_<base32>`` id a gateway
# mints; service entity ids (account / invoice / api-key) live in the service,
# not in the public standard, so no constants are exported for them here.
POE_ID_PREFIX = "poe"

# Strict Crockford-32 lowercase alphabet (no I/L/O/U). Stricter than
# ``[0-9a-z]{26}`` so the most common typo classes are caught at the parser.
_CROCKFORD_LOWER = "[0-9a-hjkmnp-tv-z]{26}"

# Public pattern string. The ``^…$`` anchors keep it byte-identical to the
# TypeScript SDK's exported pattern (and usable as ``new RegExp(pattern)`` in
# JS, where ``.test()`` rejects a trailing newline). In Python, however, ``$``
# matches just before a final ``\n``, so ``re.compile(PATTERN).match(value)``
# would over-accept ``"poe_…\n"``. Consumers in Python MUST validate with
# ``re.fullmatch`` (or use ``is_prefixed_id``/``decode_prefixed_id`` below,
# which already do); ``re.match`` against this pattern is unsafe.
POE_ID_PATTERN = f"^{POE_ID_PREFIX}_{_CROCKFORD_LOWER}$"

# Compiled validator (internal detail; the public surface is the pattern
# string + the encode/decode/guard functions). Intentionally un-anchored and
# applied with ``fullmatch`` so a trailing newline is rejected the same way
# the JS ``^…$`` + ``.test()`` pair rejects it.
POE_ID_RE = re.compile(f"{POE_ID_PREFIX}_{_CROCKFORD_LOWER}")

_UUID_HEX_RE = re.compile(r"[0-9a-f]{32}")
_ISPREFIXED_BODY_RE = re.compile(r"[0-9a-hjkmnp-tv-z]{26}")


def encode_bytes_variable_length(data: bytes) -> str:
    """Encode raw bytes as a lowercase Crockford base32 string (no padding).

    Output length is ``ceil(len(data) * 8 / 5)`` with no ``=`` padding
    character. For 16-byte UUIDs this produces 26 chars.
    """
    bits = 0
    bit_count = 0
    out: list[str] = []
    for byte in data:
        bits = (bits << 8) | byte
        bit_count += 8
        while bit_count >= 5:
            bit_count -= 5
            out.append(_ALPHABET[(bits >> bit_count) & 0x1F])
    if bit_count > 0:
        out.append(_ALPHABET[(bits << (5 - bit_count)) & 0x1F])
    return "".join(out)


def encode_crockford_base32(data: bytes) -> str:
    """Encode exactly 16 raw bytes (a UUID payload) as a 26-char string."""
    if len(data) != 16:
        raise ValueError(f"crockford-base32: expected 16 bytes, got {len(data)}")
    return encode_bytes_variable_length(data)


def decode_crockford_base32(encoded: str) -> bytes:
    """Decode a 26-char Crockford base32 string back to 16 raw bytes.

    Case-insensitive; accepts the I/L → 1, O → 0 disambiguation mappings.
    Raises ``ValueError`` on wrong length, invalid characters, or non-zero
    pad bits.
    """
    if len(encoded) != CROCKFORD_ENCODED_LENGTH_FOR_UUID:
        raise ValueError(
            f"crockford-base32: expected {CROCKFORD_ENCODED_LENGTH_FOR_UUID}-char "
            f"input, got {len(encoded)}"
        )
    out = bytearray(16)
    bits = 0
    bit_count = 0
    out_idx = 0
    for i, ch in enumerate(encoded):
        code = ord(ch)
        value = _DECODE_TABLE[code] if code < 128 else -1
        if value < 0:
            raise ValueError(f"crockford-base32: invalid character {ch!r} at index {i}")
        bits = (bits << 5) | value
        bit_count += 5
        if bit_count >= 8:
            bit_count -= 8
            out[out_idx] = (bits >> bit_count) & 0xFF
            out_idx += 1
    # 26 symbols x 5 = 130 bits consumed, 16 bytes x 8 = 128 bits emitted, so
    # exactly 2 trailing zero pad bits should remain. Anything else means the
    # input wasn't produced by this encoder (or was tampered with).
    if bit_count != 2 or (bits & 0x3) != 0:
        raise ValueError("crockford-base32: non-zero pad bits at end of input")
    return bytes(out)


def _uuid_string_to_bytes(uuid: str) -> bytes:
    # Accept the canonical 8-4-4-4-12 hyphenated form (case-insensitive) only:
    # exactly 4 hyphens and 32 hex chars after de-hyphenation.
    hex_ = uuid.replace("-", "").lower()
    if not _UUID_HEX_RE.fullmatch(hex_) or uuid.count("-") != 4:
        raise ValueError(f"prefixed-id: not a canonical hyphenated UUID: {uuid!r}")
    return bytes.fromhex(hex_)


def _bytes_to_uuid_string(data: bytes) -> str:
    if len(data) != 16:
        raise ValueError(f"prefixed-id: expected 16 decoded bytes, got {len(data)}")
    h = data.hex()
    return f"{h[0:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:]}"


def encode_prefixed_id(prefix: str, uuid: str) -> str:
    """Encode a canonical hyphenated UUID into ``f"{prefix}_{crockford}"``."""
    encoded = encode_crockford_base32(_uuid_string_to_bytes(uuid))
    return f"{prefix}_{encoded}"


def decode_prefixed_id(prefix: str, encoded: str) -> str:
    """Decode a wire-format prefixed id back to the bare canonical UUID.

    Raises ``ValueError`` when the prefix does not match, the body is not
    26 base32 chars, or the encoded payload is malformed.
    """
    if not isinstance(encoded, str):
        raise ValueError(f"prefixed-id: expected string, got {type(encoded).__name__}")
    sep = encoded.find("_")
    if sep < 0:
        raise ValueError(f"prefixed-id: missing prefix separator in {encoded!r}")
    actual_prefix = encoded[:sep]
    if actual_prefix != prefix:
        raise ValueError(f"prefixed-id: expected prefix {prefix!r}, got {actual_prefix!r}")
    body = encoded[sep + 1 :]
    return _bytes_to_uuid_string(decode_crockford_base32(body))


def is_prefixed_id(prefix: str, candidate: object) -> bool:
    """Cheap strict-lowercase guard (no I/L/O/U aliases, no byte round-trip).

    Matches the prefix and the strict lowercase Crockford alphabet but does
    NOT validate the payload bytes round-trip. Use ``decode_prefixed_id``
    when full validation is required.
    """
    if not isinstance(candidate, str):
        return False
    head = f"{prefix}_"
    if not candidate.startswith(head):
        return False
    body = candidate[len(head) :]
    # ``fullmatch`` (not ``match``) so a trailing newline in the body is
    # rejected: Python's ``$`` would match just before a final ``\n`` and
    # over-accept ``"poe_…\n"`` relative to the TS ``^…$`` + ``.test()`` guard.
    return bool(_ISPREFIXED_BODY_RE.fullmatch(body))
