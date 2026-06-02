from __future__ import annotations

# IPFS CID structural validator for the CIP-309 CID profile.
#
# Pure stdlib, no external CID/multihash/multibase library, so the structural
# validator stays inside the closed `cbor2 + cryptography + PyNaCl + argon2 +
# pyrage + stdlib` import catalogue.
#
# CIDv0: `Qm` prefix, exactly 46 base58btc chars, decodes to 34 bytes
# `[0x12, 0x20, <32-byte sha2-256 digest>]`.
#
# CIDv1: multibase prefix character + base-decoded payload
# `[version=0x01, codec_varint, multihash_code_varint,
#   multihash_length_varint, digest]`.
#
# Recognised codecs: raw (0x55), dag-pb (0x70), dag-cbor (0x71).
# Recognised multihash codes: sha2-256 (0x12, length 32) and
# blake2b-256 (0xb220, length 32).

RECOGNISED_CIDV1_CODECS: set[int] = {0x55, 0x70, 0x71}
RECOGNISED_MULTIHASH: dict[int, int] = {0x12: 32, 0xB220: 32}

_B58_ALPHA = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B58_INDEX = {c: i for i, c in enumerate(_B58_ALPHA)}

_B32_ALPHA_LOWER = "abcdefghijklmnopqrstuvwxyz234567"
_B32_INDEX_LOWER = {c: i for i, c in enumerate(_B32_ALPHA_LOWER)}
_B32_ALPHA_UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
_B32_INDEX_UPPER = {c: i for i, c in enumerate(_B32_ALPHA_UPPER)}


def _b58_decode(s: str) -> bytes | None:
    if not s:
        return None
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


def _b32_decode_no_pad(s: str, alpha_index: dict[str, int]) -> bytes | None:
    if not s:
        return b""
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


def _b16_decode(s: str, *, upper: bool) -> bytes | None:
    if len(s) % 2 != 0:
        return None
    try:
        if upper:
            if any(c not in "0123456789ABCDEF" for c in s):
                return None
        else:
            if any(c not in "0123456789abcdef" for c in s):
                return None
        return bytes.fromhex(s)
    except ValueError:
        return None


def _read_varint(data: bytes, offset: int) -> tuple[int, int] | None:
    value = 0
    shift = 0
    consumed = 0
    while consumed < 9:
        if offset + consumed >= len(data):
            return None
        b = data[offset + consumed]
        value |= (b & 0x7F) << shift
        consumed += 1
        if (b & 0x80) == 0:
            return (value, consumed)
        shift += 7
    return None


def _is_valid_cidv0(s: str) -> bool:
    if len(s) != 46 or not s.startswith("Qm"):
        return False
    decoded = _b58_decode(s)
    if decoded is None or len(decoded) != 34:
        return False
    return decoded[0] == 0x12 and decoded[1] == 0x20


def _is_valid_cidv1(s: str) -> bool:
    if len(s) < 2:
        return False
    prefix = s[0]
    rest = s[1:]
    payload: bytes | None
    if prefix == "b":
        payload = _b32_decode_no_pad(rest, _B32_INDEX_LOWER)
    elif prefix == "B":
        payload = _b32_decode_no_pad(rest, _B32_INDEX_UPPER)
    elif prefix == "f":
        payload = _b16_decode(rest, upper=False)
    elif prefix == "F":
        payload = _b16_decode(rest, upper=True)
    elif prefix == "z":
        payload = _b58_decode(rest)
    else:
        return False
    if payload is None or len(payload) < 2:
        return False
    if payload[0] != 0x01:
        return False
    cv = _read_varint(payload, 1)
    if cv is None:
        return False
    codec, codec_len = cv
    if codec not in RECOGNISED_CIDV1_CODECS:
        return False
    mh_off = 1 + codec_len
    mc = _read_varint(payload, mh_off)
    if mc is None:
        return False
    mh_code, mh_code_len = mc
    if mh_code not in RECOGNISED_MULTIHASH:
        return False
    expected_digest_len = RECOGNISED_MULTIHASH[mh_code]
    ml = _read_varint(payload, mh_off + mh_code_len)
    if ml is None:
        return False
    mh_len, mh_len_len = ml
    if mh_len != expected_digest_len:
        return False
    digest_off = mh_off + mh_code_len + mh_len_len
    if len(payload) - digest_off != mh_len:
        return False
    return True


def is_valid_cid(s: str) -> bool:
    """Return True iff ``s`` is a structurally valid IPFS CID inside the
    CIP-309 v1 CID profile.
    """
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


__all__ = ["is_valid_cid", "validate_cid_profile"]
