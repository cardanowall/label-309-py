"""Behaviour tests for the chacha20-poly1305-stream64k segmented STREAM core.

Self-generated (no pinned fixture bytes): they seal and open inside the test,
locking in the chunk layout (65536-byte plaintext chunks, 16-byte tags, the
uint88_be(counter) || final_flag nonce, empty per-chunk AAD), the empty- and
boundary-plaintext encodings, the incremental chunk machine, and the rejection
of every layout violation. The byte-pinned cross-SDK vectors live in the
stream-layout fixture replayed by the sealed-PoE KAT suite.
"""

from __future__ import annotations

import pytest

from cardanowall._crypto.aead import chacha20_poly1305_encrypt
from cardanowall._crypto.stream import (
    CHUNK_SIZE,
    TAG_SIZE,
    StreamOpener,
    StreamSealer,
    StreamTamperedError,
    stream_open,
    stream_seal,
)

_KEY = bytes((0x42 + i) & 0xFF for i in range(32))


def _pattern(n: int) -> bytes:
    return bytes(i & 0xFF for i in range(n))


def test_constants_are_pinned() -> None:
    assert CHUNK_SIZE == 65536
    assert TAG_SIZE == 16


@pytest.mark.parametrize(
    "length",
    [0, 1, 15, 16, 17, 1000, CHUNK_SIZE - 1, CHUNK_SIZE, CHUNK_SIZE + 1, 3 * CHUNK_SIZE + 5],
)
def test_roundtrip_and_chunk_arithmetic(length: int) -> None:
    plaintext = _pattern(length)
    ciphertext = stream_seal(_KEY, plaintext)
    # Every chunk adds exactly one 16-byte tag; chunk count is ceil(n/65536)
    # with the empty plaintext occupying exactly one zero-length final chunk
    # and an exact multiple of CHUNK_SIZE ending in a FULL final chunk (never
    # an extra empty one).
    if length == 0:
        chunks = 1
    else:
        chunks = (length + CHUNK_SIZE - 1) // CHUNK_SIZE
    assert len(ciphertext) == length + chunks * TAG_SIZE
    assert stream_open(_KEY, ciphertext) == plaintext


def test_empty_plaintext_is_one_final_chunk() -> None:
    ciphertext = stream_seal(_KEY, b"")
    assert len(ciphertext) == TAG_SIZE
    assert stream_open(_KEY, ciphertext) == b""


def test_chunk_nonce_layout_is_counter_then_final_flag() -> None:
    # Direct construction pin: the first chunk of a single-chunk stream is
    # sealed with nonce uint88_be(0) || 0x01 and empty AAD — reproduce it with
    # the raw AEAD and compare bytes.
    plaintext = b"nonce layout"
    expected = chacha20_poly1305_encrypt(_KEY, b"\x00" * 11 + b"\x01", b"", plaintext)
    assert stream_seal(_KEY, plaintext) == expected

    # Two-chunk stream: chunk 0 non-final (flag 0x00), chunk 1 final with
    # counter 1 (uint88_be(1) || 0x01).
    two_chunks = _pattern(CHUNK_SIZE + 3)
    expected2 = chacha20_poly1305_encrypt(
        _KEY, b"\x00" * 12, b"", two_chunks[:CHUNK_SIZE]
    ) + chacha20_poly1305_encrypt(_KEY, b"\x00" * 10 + b"\x01\x01", b"", two_chunks[CHUNK_SIZE:])
    assert stream_seal(_KEY, two_chunks) == expected2


def test_incremental_machines_match_whole_buffer_helpers() -> None:
    plaintext = _pattern(2 * CHUNK_SIZE + 100)
    sealer = StreamSealer(_KEY)
    sealed = (
        sealer.seal_chunk(plaintext[:CHUNK_SIZE], final=False)
        + sealer.seal_chunk(plaintext[CHUNK_SIZE : 2 * CHUNK_SIZE], final=False)
        + sealer.seal_chunk(plaintext[2 * CHUNK_SIZE :], final=True)
    )
    assert sealer.finished
    assert sealed == stream_seal(_KEY, plaintext)

    opener = StreamOpener(_KEY)
    full = CHUNK_SIZE + TAG_SIZE
    out = (
        opener.open_chunk(sealed[:full], final=False)
        + opener.open_chunk(sealed[full : 2 * full], final=False)
        + opener.open_chunk(sealed[2 * full :], final=True)
    )
    assert opener.finished
    assert out == plaintext


def test_open_rejects_flipped_tag() -> None:
    ciphertext = bytearray(stream_seal(_KEY, b"x"))
    ciphertext[-1] ^= 0x01
    with pytest.raises(StreamTamperedError):
        stream_open(_KEY, bytes(ciphertext))


def test_open_rejects_truncation_missing_final_chunk() -> None:
    # Drop the final chunk: the remaining full chunk is forced into the final
    # position, where its non-final-flag tag cannot verify.
    ciphertext = stream_seal(_KEY, _pattern(CHUNK_SIZE + 1))
    with pytest.raises(StreamTamperedError):
        stream_open(_KEY, ciphertext[: CHUNK_SIZE + TAG_SIZE])


def test_open_rejects_trailing_data_after_final_chunk() -> None:
    ciphertext = stream_seal(_KEY, b"x")
    with pytest.raises(StreamTamperedError):
        stream_open(_KEY, ciphertext + b"\xde\xad")
    # Trailing data that pushes the total over a full chunk turns the final
    # chunk into a misaligned non-final one — also caught.
    with pytest.raises(StreamTamperedError):
        stream_open(_KEY, ciphertext + bytes(CHUNK_SIZE * 2))


def test_open_rejects_short_non_final_chunk() -> None:
    # Removing bytes from inside the first (non-final) chunk shifts every
    # implied boundary; authentication fails.
    ciphertext = stream_seal(_KEY, _pattern(CHUNK_SIZE + 1))
    mutated = ciphertext[:100] + ciphertext[116:]
    with pytest.raises(StreamTamperedError):
        stream_open(_KEY, mutated)
    # The incremental machine rejects an explicitly short non-final chunk
    # before any AEAD work.
    opener = StreamOpener(_KEY)
    with pytest.raises(StreamTamperedError):
        opener.open_chunk(ciphertext[: CHUNK_SIZE + TAG_SIZE - 1], final=False)


def test_open_rejects_below_the_16_byte_floor() -> None:
    with pytest.raises(StreamTamperedError):
        stream_open(_KEY, b"")
    with pytest.raises(StreamTamperedError):
        stream_open(_KEY, b"\x00" * (TAG_SIZE - 1))


def test_open_rejects_empty_final_chunk_in_non_empty_stream() -> None:
    # A maliciously assembled stream: one full non-final chunk followed by a
    # genuinely sealed zero-length final chunk. Every tag verifies, but the
    # layout rule (a zero-length final chunk encodes only the empty plaintext)
    # rejects it.
    chunk0 = chacha20_poly1305_encrypt(_KEY, b"\x00" * 12, b"", _pattern(CHUNK_SIZE))
    empty_final = chacha20_poly1305_encrypt(_KEY, b"\x00" * 10 + b"\x01\x01", b"", b"")
    with pytest.raises(StreamTamperedError):
        stream_open(_KEY, chunk0 + empty_final)


def test_opener_rejects_chunk_after_final() -> None:
    plaintext = b"done"
    sealed = stream_seal(_KEY, plaintext)
    opener = StreamOpener(_KEY)
    assert opener.open_chunk(sealed, final=True) == plaintext
    with pytest.raises(StreamTamperedError):
        opener.open_chunk(sealed, final=True)


def test_sealer_enforces_chunk_discipline() -> None:
    sealer = StreamSealer(_KEY)
    # Non-final chunks must be exactly CHUNK_SIZE.
    with pytest.raises(ValueError):
        sealer.seal_chunk(b"short", final=False)
    # A zero-length final chunk is only the empty stream's encoding.
    sealer.seal_chunk(_pattern(CHUNK_SIZE), final=False)
    with pytest.raises(ValueError):
        sealer.seal_chunk(b"", final=True)
    sealer.seal_chunk(b"tail", final=True)
    with pytest.raises(ValueError):
        sealer.seal_chunk(b"more", final=True)


def test_key_length_is_validated() -> None:
    with pytest.raises(ValueError):
        stream_seal(b"\x00" * 31, b"x")
    with pytest.raises(ValueError):
        stream_open(b"\x00" * 33, b"\x00" * 16)
