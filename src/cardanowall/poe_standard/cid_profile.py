"""IPFS CID structural validator for the Label 309 CID profile.

Pure stdlib, no external CID/multihash/multibase library, so the structural
validator stays inside the closed import catalogue.

Accept CIDv0 (``Qm`` prefix, base58btc, sha2-256 multihash) and CIDv1
(multibase prefix + version 0x01 + codec + multihash) per the closed profile:

- Multibase: ``b``, ``B``, ``f``, ``F``, ``z``
- Multicodec: 0x55 (raw), 0x70 (dag-pb), 0x71 (dag-cbor)
- Multihash: 0x12 (sha2-256, 32 B), 0xb220 (blake2b-256, 32 B)
"""

from __future__ import annotations

from typing import Final

RECOGNISED_CIDV1_CODECS: Final[frozenset[int]] = frozenset({0x55, 0x70, 0x71})
# Multihash table: code -> digest length (bytes).
RECOGNISED_MULTIHASH: Final[dict[int, int]] = {0x12: 32, 0xB220: 32}

_B58_ALPHA: Final[str] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B58_INDEX: Final[dict[str, int]] = {c: i for i, c in enumerate(_B58_ALPHA)}

_B32_ALPHA_LOWER: Final[str] = "abcdefghijklmnopqrstuvwxyz234567"
_B32_INDEX_LOWER: Final[dict[str, int]] = {c: i for i, c in enumerate(_B32_ALPHA_LOWER)}
_B32_ALPHA_UPPER: Final[str] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
_B32_INDEX_UPPER: Final[dict[str, int]] = {c: i for i, c in enumerate(_B32_ALPHA_UPPER)}


def _b58_decode(s: str) -> bytes | None:
    if not s:
        return b""
    n = 0
    for ch in s:
        v = _B58_INDEX.get(ch)
        if v is None:
            return None
        n = n * 58 + v
    body = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    leading = 0
    for ch in s:
        if ch == "1":
            leading += 1
        else:
            break
    return b"\x00" * leading + body


def _b32_decode(s: str, alpha_index: dict[str, int]) -> bytes | None:
    # Multibase strips padding per spec; tolerate either form.
    s = s.rstrip("=")
    bits = 0
    buffer = 0
    out = bytearray()
    for ch in s:
        v = alpha_index.get(ch)
        if v is None:
            return None
        buffer = (buffer << 5) | v
        bits += 5
        if bits >= 8:
            bits -= 8
            out.append((buffer >> bits) & 0xFF)
    return bytes(out)


_B16_ALPHA_LOWER: Final[str] = "0123456789abcdef"
_B16_INDEX_LOWER: Final[dict[str, int]] = {c: i for i, c in enumerate(_B16_ALPHA_LOWER)}
_B16_ALPHA_UPPER: Final[str] = "0123456789ABCDEF"
_B16_INDEX_UPPER: Final[dict[str, int]] = {c: i for i, c in enumerate(_B16_ALPHA_UPPER)}


def _b16_decode(s: str, alpha_index: dict[str, int]) -> bytes | None:
    if len(s) % 2 != 0:
        return None
    out = bytearray()
    for i in range(0, len(s), 2):
        hi = alpha_index.get(s[i])
        lo = alpha_index.get(s[i + 1])
        if hi is None or lo is None:
            return None
        out.append((hi << 4) | lo)
    return bytes(out)


def _read_varint(data: bytes, offset: int) -> tuple[int, int] | None:
    """Read one unsigned LEB128 varint; returns ``(value, next_offset)`` or
    ``None`` on truncation / overflow (the profile uses <= 16-bit codes)."""
    value = 0
    shift = 0
    i = offset
    while i < len(data):
        b = data[i]
        value |= (b & 0x7F) << shift
        i += 1
        if (b & 0x80) == 0:
            return (value, i)
        shift += 7
        if shift > 28:
            return None
    return None


def _is_valid_cidv0(s: str) -> bool:
    # CIDv0: a base58btc-encoded sha2-256 multihash. Decode the WHOLE string
    # and verify the multihash prefix (0x12 = sha2-256, 0x20 = 32-byte digest)
    # and total length (34 bytes); a `Qm` prefix alone is not sufficient.
    decoded = _b58_decode(s)
    if decoded is None or len(decoded) != 34:
        return False
    return decoded[0] == 0x12 and decoded[1] == 0x20


def _is_valid_cidv1(s: str) -> bool:
    if len(s) < 1:
        return False
    prefix = s[0]
    rest = s[1:]
    payload: bytes | None
    # Decode the body VERBATIM against the case the prefix advertises — never
    # case-fold. RFC 4648 base32/base16 each have a distinct lower- and
    # upper-case multibase prefix (``b``/``B``, ``f``/``F``); a body whose case
    # disagrees with its prefix is not a canonical CID and is rejected (the
    # mismatched character is absent from the advertised alphabet), not folded
    # into the advertised case. base58btc is case-significant and never folded.
    if prefix == "b":
        payload = _b32_decode(rest, _B32_INDEX_LOWER)
    elif prefix == "B":
        payload = _b32_decode(rest, _B32_INDEX_UPPER)
    elif prefix == "f":
        payload = _b16_decode(rest, _B16_INDEX_LOWER)
    elif prefix == "F":
        payload = _b16_decode(rest, _B16_INDEX_UPPER)
    elif prefix == "z":
        payload = _b58_decode(rest)
    else:
        return False
    if payload is None or len(payload) < 4:
        return False
    # CIDv1 layout: <version varint> <multicodec varint> <multihash>
    version_parse = _read_varint(payload, 0)
    if version_parse is None or version_parse[0] != 1:
        return False
    codec_parse = _read_varint(payload, version_parse[1])
    if codec_parse is None or codec_parse[0] not in RECOGNISED_CIDV1_CODECS:
        return False
    mh_parse = _read_varint(payload, codec_parse[1])
    if mh_parse is None:
        return False
    len_parse = _read_varint(payload, mh_parse[1])
    if len_parse is None:
        return False
    expected_digest_len = RECOGNISED_MULTIHASH.get(mh_parse[0])
    if expected_digest_len is None or len_parse[0] != expected_digest_len:
        return False
    return len_parse[1] + len_parse[0] == len(payload)


def is_valid_cid(s: str) -> bool:
    """Return True iff ``s`` is a structurally valid IPFS CID inside the
    Label 309 v1 CID profile."""
    if not s:
        return False
    if s.startswith("Qm"):
        return _is_valid_cidv0(s)
    return _is_valid_cidv1(s)


def validate_cid_profile(cid: str) -> tuple[bool, str | None]:
    """Profile-validate a CID string.

    Returns ``(ok, reason_or_none)``. On failure the reason is
    ``"ipfs_cid_unsupported"`` so callers can route to the structural
    validator's ``INVALID_URI`` code.
    """
    if is_valid_cid(cid):
        return True, None
    return False, "ipfs_cid_unsupported"


__all__ = [
    "RECOGNISED_CIDV1_CODECS",
    "RECOGNISED_MULTIHASH",
    "is_valid_cid",
    "validate_cid_profile",
]
