"""Age-style recipient string codec (bech32, BIP-173, no length limit).

A sender addresses a sealed-PoE record to a recipient by their bech32 recipient
string; the HRP makes the string self-describing so a parser routes to the right
KEM purely from the prefix:

    * X25519 (32 bytes)                          -> "age1..."
    * X-Wing / ML-KEM-768 + X25519 (1216 bytes)  -> "age1pqc..."

The encoder is byte-identical to the TypeScript ``@cardanowall/sdk-ts`` codec
(re-exported from ``@cardanowall/crypto-core``) and to a standard bech32 encoder
used with the no-length-limit flag: age recipients exceed the 90-character
BIP-173 cap -- an X-Wing recipient is ~1960 characters -- so the limit must be
off. The two languages MUST emit the same string for the same public key; that
cross-language parity is the load-bearing property and is pinned by a shared
fixture.

The ``age1pqc`` HRP is chosen for the hybrid key because upstream age v1.3.0
claims the shorter ``age1pq`` HRP for the same X-Wing primitive; ``age1pqc``
avoids colliding with that wire identifier.
"""

from __future__ import annotations

from dataclasses import dataclass

_BECH32_ALPHABET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_POLYMOD_GENERATORS = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)
# BIP-173 bech32 (not bech32m). The checksum constant 1 distinguishes the two.
_ENCODING_CONST = 1

_X25519_HRP = "age"
_XWING_HRP = "age1pqc"
_X25519_PUBLIC_KEY_BYTES = 32
_XWING_PUBLIC_KEY_BYTES = 1216


def _polymod_step(pre: int) -> int:
    b = pre >> 25
    chk = (pre & 0x1FFFFFF) << 5
    for i, gen in enumerate(_POLYMOD_GENERATORS):
        if (b >> i) & 1:
            chk ^= gen
    return chk


def _bytes_to_words(data: bytes) -> list[int]:
    # 8-bit bytes -> 5-bit words, padding the final partial group with zero bits.
    words: list[int] = []
    carry = 0
    pos = 0
    for n in data:
        carry = (carry << 8) | n
        pos += 8
        while pos >= 5:
            pos -= 5
            words.append((carry >> pos) & 31)
        carry &= (1 << pos) - 1
    if pos > 0:
        words.append((carry << (5 - pos)) & 31)
    return words


def _checksum(prefix: str, words: list[int]) -> str:
    chk = 1
    for ch in prefix:
        c = ord(ch)
        if c < 33 or c > 126:
            raise ValueError(f"bech32: invalid prefix ({prefix})")
        chk = _polymod_step(chk) ^ (c >> 5)
    chk = _polymod_step(chk)
    for ch in prefix:
        chk = _polymod_step(chk) ^ (ord(ch) & 31)
    for v in words:
        chk = _polymod_step(chk) ^ v
    for _ in range(6):
        chk = _polymod_step(chk)
    chk ^= _ENCODING_CONST
    return "".join(_BECH32_ALPHABET[(chk >> (5 * (5 - i))) & 31] for i in range(6))


def bech32_encode_no_limit(prefix: str, data: bytes) -> str:
    """Encode raw bytes to a bech32 string with NO length limit.

    ``prefix`` is the human-readable part (HRP). Output is byte-identical to a
    standard ``bech32.encode(hrp, toWords(data), no_limit=True)``.
    """
    if not prefix:
        raise ValueError("bech32: empty prefix")
    words = _bytes_to_words(data)
    lowered = prefix.lower()
    payload = "".join(_BECH32_ALPHABET[w] for w in words)
    return f"{lowered}1{payload}{_checksum(lowered, words)}"


def encode_age_x25519_recipient(public_key: bytes) -> str:
    """Encode a 32-byte X25519 public key to its ``age1...`` recipient string."""
    if len(public_key) != _X25519_PUBLIC_KEY_BYTES:
        raise ValueError("encode_age_x25519_recipient: public_key must be exactly 32 bytes")
    return bech32_encode_no_limit(_X25519_HRP, public_key)


def encode_age_xwing_recipient(public_key: bytes) -> str:
    """Encode a 1216-byte X-Wing public key to its ``age1pqc...`` recipient string."""
    if len(public_key) != _XWING_PUBLIC_KEY_BYTES:
        raise ValueError("encode_age_xwing_recipient: public_key must be exactly 1216 bytes")
    return bech32_encode_no_limit(_XWING_HRP, public_key)


@dataclass(frozen=True)
class ParsedAgeRecipient:
    """A recipient string decoded to its raw KEM public key.

    ``kem`` is ``"x25519"`` or ``"mlkem768x25519"`` (the X-Wing hybrid).
    """

    kem: str
    public_key: bytes


def parse_age_recipient(recipient: str) -> ParsedAgeRecipient:
    """Decode an ``age``-style recipient string back to its raw KEM public key.

    The inverse of :func:`encode_age_x25519_recipient` /
    :func:`encode_age_xwing_recipient`, routing on the bech32 HRP. A sender takes
    a recipient string a peer shared and recovers the exact public key (and which
    KEM it belongs to) needed to seal a record to them. Surrounding whitespace is
    tolerated so pasted strings parse. Raises ``ValueError`` on an unknown HRP, a
    bad checksum, or a key length that does not match the HRP's KEM.
    """
    hrp, data = _bech32_decode_no_limit(recipient.strip())
    if hrp == _X25519_HRP:
        if len(data) != _X25519_PUBLIC_KEY_BYTES:
            raise ValueError("parse_age_recipient: age recipient must carry a 32-byte X25519 key")
        return ParsedAgeRecipient(kem="x25519", public_key=data)
    if hrp == _XWING_HRP:
        if len(data) != _XWING_PUBLIC_KEY_BYTES:
            raise ValueError(
                "parse_age_recipient: age1pqc recipient must carry a 1216-byte X-Wing key"
            )
        return ParsedAgeRecipient(kem="mlkem768x25519", public_key=data)
    raise ValueError(f'parse_age_recipient: unrecognized recipient prefix "{hrp}"')


def _checksum_valid(prefix: str, words: list[int]) -> bool:
    chk = 1
    for ch in prefix:
        chk = _polymod_step(chk) ^ (ord(ch) >> 5)
    chk = _polymod_step(chk)
    for ch in prefix:
        chk = _polymod_step(chk) ^ (ord(ch) & 0x1F)
    for v in words:
        chk = _polymod_step(chk) ^ v
    return chk == 1


def _words_to_bytes(words: list[int]) -> bytes:
    # 5-bit words -> 8-bit bytes (the inverse of _bytes_to_words). Rejects
    # non-canonical padding: any leftover must be < 5 bits and all zero.
    out = bytearray()
    carry = 0
    pos = 0
    for w in words:
        carry = (carry << 5) | w
        pos += 5
        while pos >= 8:
            pos -= 8
            out.append((carry >> pos) & 0xFF)
        carry &= (1 << pos) - 1
    if pos >= 5 or carry != 0:
        raise ValueError("bech32: non-canonical padding")
    return bytes(out)


def _bech32_decode_no_limit(text: str) -> tuple[str, bytes]:
    """Decode a bech32 string with NO length limit, verifying the checksum.

    The separator is the last ``1`` in the string, so HRPs that themselves
    contain a ``1`` (e.g. the ``age1pqc`` recipient prefix) round-trip correctly.
    """
    if len(text) == 0:
        raise ValueError("bech32: empty string")
    has_lower = text != text.upper()
    has_upper = text != text.lower()
    if has_lower and has_upper:
        raise ValueError("bech32: mixed-case string")
    s = text.lower()
    sep = s.rfind("1")
    if sep < 1:
        raise ValueError("bech32: missing human-readable prefix")
    if len(s) - sep - 1 < 6:
        raise ValueError("bech32: data too short for checksum")
    hrp = s[:sep]
    for ch in hrp:
        if ord(ch) < 33 or ord(ch) > 126:
            raise ValueError("bech32: invalid prefix character")
    words: list[int] = []
    for ch in s[sep + 1 :]:
        v = _BECH32_ALPHABET.find(ch)
        if v == -1:
            raise ValueError("bech32: invalid data character")
        words.append(v)
    if not _checksum_valid(hrp, words):
        raise ValueError("bech32: bad checksum")
    return hrp, _words_to_bytes(words[:-6])


__all__ = [
    "ParsedAgeRecipient",
    "bech32_encode_no_limit",
    "encode_age_x25519_recipient",
    "encode_age_xwing_recipient",
    "parse_age_recipient",
]
