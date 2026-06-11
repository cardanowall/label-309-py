"""Offline CID decoding for the content-address binding of fetched bytes.

Both fetch schemes are content-addressed, so fetched bytes CAN be verified
against the URI itself — independently of whichever gateway served them. The
binding check decides ATTRIBUTION, and attribution decides what a mismatch
means: attributable bytes failing a record commitment condemn the record
(``URI_INTEGRITY_MISMATCH``); unattributable bytes indict only the serving
provider (``URI_PROVIDER_INTEGRITY_MISMATCH``).

This implementation verifies the binding for the raw-codec CIDv1 case: the
multihash is computed directly over the content bytes, so a plain hash
recompute proves the gateway served exactly what the CID addresses. The other
forms need block-level verification this SDK does not implement — DAG CIDs
(dag-pb / dag-cbor, including every CIDv0) commit to encoded blocks rather
than the file bytes a path gateway returns, and ``ar://`` needs the Arweave
``data_root`` chunk tree or the ANS-104 deep-hash — so fetched bytes under
those forms stay UNVERIFIED and their mismatches are routed through the
provider code, never ``URI_INTEGRITY_MISMATCH``.

The accepted multibase / multicodec / multihash sets mirror the normative CID
profile (already enforced by the structural validator); anything outside it
simply yields ``unsupported`` here.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final, Literal

from cardanowall._crypto.hash import blake2b_256, sha256

_CODEC_RAW: Final[int] = 0x55
_CODEC_DAG_PB: Final[int] = 0x70
_MULTIHASH_SHA2_256: Final[int] = 0x12
_MULTIHASH_BLAKE2B_256: Final[int] = 0xB220

CidBindingOutcome = Literal["verified", "failed", "unsupported"]


@dataclass(frozen=True, kw_only=True)
class ParsedCid:
    version: int
    codec: int
    multihash_code: int
    digest: bytes


_B58_ALPHABET: Final[str] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B58_INDEX: Final[dict[str, int]] = {c: i for i, c in enumerate(_B58_ALPHABET)}
_B32_ALPHABET: Final[str] = "abcdefghijklmnopqrstuvwxyz234567"
_B32_INDEX: Final[dict[str, int]] = {c: i for i, c in enumerate(_B32_ALPHABET)}
_B16_RE: Final[str] = "0123456789abcdef"


def _base58_decode(s: str) -> bytes | None:
    if not s:
        return None
    value = 0
    for ch in s:
        idx = _B58_INDEX.get(ch)
        if idx is None:
            return None
        value = value * 58 + idx
    body = value.to_bytes((value.bit_length() + 7) // 8, "big") if value else b""
    # Leading '1' characters encode leading zero bytes.
    n_leading = len(s) - len(s.lstrip("1"))
    return b"\x00" * n_leading + body


def _base32_decode(s: str) -> bytes | None:
    # RFC 4648 base32 without padding (the multibase 'b' form, lowercase).
    bits = 0
    acc = 0
    out = bytearray()
    for ch in s:
        idx = _B32_INDEX.get(ch)
        if idx is None:
            return None
        acc = (acc << 5) | idx
        bits += 5
        if bits >= 8:
            bits -= 8
            out.append((acc >> bits) & 0xFF)
    # Trailing bits must be zero padding only.
    if acc & ((1 << bits) - 1):
        return None
    return bytes(out)


def _base16_decode(s: str) -> bytes | None:
    if len(s) % 2 != 0 or any(c not in _B16_RE for c in s):
        return None
    return bytes.fromhex(s)


def _read_varint(data: bytes, offset: int) -> tuple[int, int] | None:
    value = 0
    shift = 0
    pos = offset
    while True:
        if pos >= len(data) or shift > 28:
            return None
        byte = data[pos]
        value |= (byte & 0x7F) << shift
        pos += 1
        if not byte & 0x80:
            return value, pos
        shift += 7


def parse_cid(cid: str) -> ParsedCid | None:
    """Decode the authority component of an ``ipfs://`` URI into its CID
    fields. Returns ``None`` for anything outside the profile's multibase set
    or for undecodable input — callers treat that exactly like an unsupported
    binding."""
    if len(cid) == 0:
        return None

    # CIDv0: fixed base58btc "Qm…" shape, an implied dag-pb + sha2-256 multihash.
    if cid.startswith("Qm") and len(cid) == 46:
        decoded0 = _base58_decode(cid)
        if decoded0 is None or len(decoded0) != 34:
            return None
        if decoded0[0] != _MULTIHASH_SHA2_256 or decoded0[1] != 32:
            return None
        return ParsedCid(
            version=0,
            codec=_CODEC_DAG_PB,
            multihash_code=_MULTIHASH_SHA2_256,
            digest=decoded0[2:],
        )

    prefix, body = cid[0], cid[1:]
    decoded: bytes | None
    if prefix == "b":
        decoded = _base32_decode(body)
    elif prefix == "B":
        decoded = _base32_decode(body.lower())
    elif prefix == "f":
        decoded = _base16_decode(body)
    elif prefix == "F":
        decoded = _base16_decode(body.lower())
    elif prefix == "z":
        decoded = _base58_decode(body)
    else:
        return None
    if decoded is None:
        return None

    version = _read_varint(decoded, 0)
    if version is None or version[0] != 1:
        return None
    codec = _read_varint(decoded, version[1])
    if codec is None:
        return None
    mh_code = _read_varint(decoded, codec[1])
    if mh_code is None:
        return None
    mh_length = _read_varint(decoded, mh_code[1])
    if mh_length is None:
        return None
    digest = decoded[mh_length[1] :]
    if len(digest) != mh_length[0]:
        return None
    return ParsedCid(version=1, codec=codec[0], multihash_code=mh_code[0], digest=digest)


def verify_ipfs_cid_binding(*, cid: str, path: str, data: bytes) -> CidBindingOutcome:
    """The minimum binding check: for a raw-codec CIDv1 with no path
    component, recompute the multihash directly over the fetched bytes and
    compare it to the CID's digest. Everything else — CIDv0, DAG codecs, a
    path component (which navigates a DAG the raw recompute cannot
    reproduce), an out-of-profile multihash — is ``unsupported``: the bytes
    stay unattributed and a mismatch indicts the provider, never the
    record."""
    if path != "":
        return "unsupported"
    parsed = parse_cid(cid)
    if parsed is None or parsed.version != 1 or parsed.codec != _CODEC_RAW:
        return "unsupported"
    if parsed.multihash_code == _MULTIHASH_SHA2_256:
        computed = sha256(data)
    elif parsed.multihash_code == _MULTIHASH_BLAKE2B_256:
        computed = blake2b_256(data)
    else:
        return "unsupported"
    return "verified" if computed == parsed.digest else "failed"


__all__ = ["CidBindingOutcome", "ParsedCid", "parse_cid", "verify_ipfs_cid_binding"]
