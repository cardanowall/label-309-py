# Segmented STREAM content format `chacha20-poly1305-stream64k`.
#
# RFC 8439 ChaCha20-Poly1305 in the 64 KiB segmented STREAM layout of the age
# v1 specification: the plaintext is split into 65536-byte chunks (every
# non-final chunk exactly 65536 bytes; the final chunk 0..65536, zero-length
# only when the whole plaintext is empty), and each chunk is sealed under the
# single-use content payload_key with the 12-byte per-chunk nonce
# `uint88_be(counter) || final_flag` (counter starts at 0, +1 per chunk;
# final_flag is 0x01 on the final chunk, 0x00 otherwise) and an empty per-chunk
# AAD, producing one 16-byte tag per chunk.
#
# The counter nonces are safe because the payload_key is single-use: it is an
# HKDF leaf of a fresh CEK salted by the envelope-unique 24-byte enc.nonce, so
# no two streams ever share a (key, nonce) pair. The final-flag byte
# domain-separates the last chunk, which is what makes truncation detectable; a
# final flag on a non-last chunk, data following the final chunk, or a
# non-final chunk of the wrong size all fail decryption as chunk-layout
# violations.
#
# Each chunk's tag is verified before that chunk's plaintext is released, so an
# incremental consumer can decrypt with bounded memory — but the whole-file
# plaintext-hash recheck runs post-hoc, so released chunk bytes MUST be treated
# as tentative (no side effects) until that final check passes.

from __future__ import annotations

from typing import Final

from .aead import (
    AeadVerificationError,
    chacha20_poly1305_decrypt,
    chacha20_poly1305_encrypt,
)

# Pinned format constants: 65536 plaintext bytes per non-final chunk, a 16-byte
# Poly1305 tag per chunk. The 88-bit counter admits 2^88 chunks — far above any
# realisable payload — so the format imposes no cryptographic payload ceiling;
# any practical maximum is a deployment denial-of-service policy.
CHUNK_SIZE: Final[int] = 65536
TAG_SIZE: Final[int] = 16

_SEALED_CHUNK_SIZE: Final[int] = CHUNK_SIZE + TAG_SIZE
_PAYLOAD_KEY_LENGTH: Final[int] = 32
_NONCE_COUNTER_BYTES: Final[int] = 11
_MAX_COUNTER: Final[int] = (1 << 88) - 1
_FINAL_FLAG: Final[bytes] = b"\x01"
_NONFINAL_FLAG: Final[bytes] = b"\x00"
_EMPTY_AAD: Final[bytes] = b""


class StreamTamperedError(Exception):
    """The STREAM ciphertext failed authentication or violates the chunk layout.

    Raised on a per-chunk tag failure, truncation (a last chunk without the
    final flag), data following the final chunk, a non-final chunk of the
    wrong size, a zero-length final chunk in a non-empty stream, or a blob
    shorter than the 16-byte floor (the lone tag of an empty final chunk).
    All collapse to the single TAMPERED_CIPHERTEXT-class failure: an untrusted
    caller must not be able to distinguish them.
    """

    code: str = "TAMPERED_CIPHERTEXT"


def _chunk_nonce(counter: int, final: bool) -> bytes:
    return counter.to_bytes(_NONCE_COUNTER_BYTES, "big") + (
        _FINAL_FLAG if final else _NONFINAL_FLAG
    )


def _assert_payload_key(payload_key: bytes) -> None:
    if len(payload_key) != _PAYLOAD_KEY_LENGTH:
        raise ValueError(
            f"payload_key MUST be exactly {_PAYLOAD_KEY_LENGTH} bytes, got {len(payload_key)}"
        )


class StreamSealer:
    """Incremental chunk machine for sealing one STREAM under one payload_key.

    The caller feeds plaintext chunks in order; every non-final chunk MUST be
    exactly CHUNK_SIZE bytes, the final chunk 0..CHUNK_SIZE bytes with a
    zero-length final chunk permitted only as the sole chunk of an empty
    stream. Chunk-discipline violations are caller misuse and raise ValueError;
    they never produce a malformed stream.
    """

    def __init__(self, payload_key: bytes) -> None:
        _assert_payload_key(payload_key)
        self._key = payload_key
        self._counter = 0
        self._finished = False

    def seal_chunk(self, plaintext: bytes, *, final: bool) -> bytes:
        if self._finished:
            raise ValueError("seal_chunk called after the final chunk was sealed")
        if self._counter > _MAX_COUNTER:
            raise ValueError("STREAM chunk counter exhausted")
        if final:
            if len(plaintext) > CHUNK_SIZE:
                raise ValueError(
                    f"final chunk plaintext MUST be at most {CHUNK_SIZE} bytes, "
                    f"got {len(plaintext)}"
                )
            if len(plaintext) == 0 and self._counter != 0:
                raise ValueError(
                    "a zero-length final chunk is only valid when the whole plaintext is empty"
                )
        elif len(plaintext) != CHUNK_SIZE:
            raise ValueError(
                f"non-final chunk plaintext MUST be exactly {CHUNK_SIZE} bytes, "
                f"got {len(plaintext)}"
            )
        sealed = chacha20_poly1305_encrypt(
            self._key, _chunk_nonce(self._counter, final), _EMPTY_AAD, plaintext
        )
        self._counter += 1
        self._finished = final
        return sealed

    @property
    def finished(self) -> bool:
        return self._finished


class StreamOpener:
    """Incremental chunk machine for opening one STREAM under one payload_key.

    The caller supplies sealed chunks in order with their finality; each
    chunk's plaintext is returned only after its tag verifies. Released bytes
    are tentative until the caller's whole-plaintext hash check passes. Any
    authentication or layout violation raises StreamTamperedError.
    """

    def __init__(self, payload_key: bytes) -> None:
        _assert_payload_key(payload_key)
        self._key = payload_key
        self._counter = 0
        self._finished = False

    def open_chunk(self, sealed: bytes, *, final: bool) -> bytes:
        if self._finished:
            raise StreamTamperedError("data follows the final chunk")
        if self._counter > _MAX_COUNTER:
            raise StreamTamperedError("STREAM chunk counter exhausted")
        if final:
            if len(sealed) < TAG_SIZE or len(sealed) > _SEALED_CHUNK_SIZE:
                raise StreamTamperedError("final chunk size violates the STREAM layout")
        elif len(sealed) != _SEALED_CHUNK_SIZE:
            raise StreamTamperedError("non-final chunk size violates the STREAM layout")
        try:
            plaintext = chacha20_poly1305_decrypt(
                self._key, _chunk_nonce(self._counter, final), _EMPTY_AAD, sealed
            )
        except AeadVerificationError as e:
            raise StreamTamperedError("STREAM chunk failed authentication") from e
        if final and len(plaintext) == 0 and self._counter != 0:
            # An empty final chunk is the encoding of the empty plaintext and
            # nothing else; after at least one non-final chunk it is a layout
            # violation even when its tag verifies.
            raise StreamTamperedError("zero-length final chunk in a non-empty stream")
        self._counter += 1
        self._finished = final
        return plaintext

    @property
    def finished(self) -> bool:
        return self._finished


def stream_seal(payload_key: bytes, plaintext: bytes) -> bytes:
    """Seal a whole buffer into the STREAM chunk sequence.

    An empty plaintext seals to exactly one zero-length final chunk (a lone
    16-byte tag); a plaintext of exactly CHUNK_SIZE bytes seals to a single
    final chunk of CHUNK_SIZE bytes.
    """
    sealer = StreamSealer(payload_key)
    out = bytearray()
    pos = 0
    total = len(plaintext)
    while total - pos > CHUNK_SIZE:
        out += sealer.seal_chunk(plaintext[pos : pos + CHUNK_SIZE], final=False)
        pos += CHUNK_SIZE
    out += sealer.seal_chunk(plaintext[pos:], final=True)
    return bytes(out)


def stream_open(payload_key: bytes, ciphertext: bytes) -> bytes:
    """Open a whole STREAM buffer, verifying every chunk tag and the layout.

    Chunk boundaries are implied by the layout: every chunk except the last is
    a full sealed chunk (CHUNK_SIZE + TAG_SIZE bytes), and whatever remains is
    the final chunk. A trailing remainder too short to be a chunk, a sealed
    final chunk whose tag was computed under the non-final flag (truncation),
    appended bytes (which either corrupt the final chunk or leave an
    impossible remainder), and a tag failure anywhere all raise
    StreamTamperedError.
    """
    opener = StreamOpener(payload_key)
    n = len(ciphertext)
    if n < TAG_SIZE:
        raise StreamTamperedError("ciphertext is shorter than the 16-byte STREAM floor")
    out = bytearray()
    pos = 0
    while True:
        remaining = n - pos
        final = remaining <= _SEALED_CHUNK_SIZE
        take = remaining if final else _SEALED_CHUNK_SIZE
        out += opener.open_chunk(ciphertext[pos : pos + take], final=final)
        pos += take
        if final:
            return bytes(out)
