from __future__ import annotations

import pytest

from cardanowall.poe_standard.chunked import (
    bytes_chunk_array_concat,
    chunk_bytes,
    chunk_text,
    reconstruct_chunked_uri,
)

# --- chunk_bytes -----------------------------------------------------------


def test_chunk_bytes_short_is_single_chunk() -> None:
    assert chunk_bytes(b"\x00" * 64) == [b"\x00" * 64]


def test_chunk_bytes_long_is_split() -> None:
    payload = b"\x01" * 100
    chunks = chunk_bytes(payload)
    assert len(chunks) == 2
    assert chunks[0] == b"\x01" * 64
    assert chunks[1] == b"\x01" * 36


def test_chunk_bytes_empty_returns_one_empty() -> None:
    assert chunk_bytes(b"") == [b""]


def test_bytes_chunk_array_concat_roundtrip() -> None:
    payload = b"abcdef" * 30
    chunks = chunk_bytes(payload)
    assert bytes_chunk_array_concat(chunks) == payload


# --- chunk_text ------------------------------------------------------------


def test_chunk_text_short_string() -> None:
    assert chunk_text("hello", max_bytes=64) == ["hello"]


def test_chunk_text_splits_on_codepoint_boundary() -> None:
    # 4-byte UTF-8 codepoint U+1F600 (grinning face emoji).
    smile = "\U0001f600"  # 4 bytes
    # Use a budget such that one smile fits but two don't span boundary.
    chunks = chunk_text(smile * 20, max_bytes=8)
    for c in chunks:
        assert len(c.encode("utf-8")) <= 8
    assert "".join(chunks) == smile * 20


def test_chunk_text_codepoint_larger_than_budget_raises() -> None:
    smile = "\U0001f600"
    with pytest.raises(ValueError):
        chunk_text(smile, max_bytes=3)


def test_chunk_text_empty() -> None:
    assert chunk_text("") == [""]


# --- reconstruct_chunked_uri ----------------------------------------------


def test_reconstruct_chunked_uri_clean() -> None:
    ok, uri, err = reconstruct_chunked_uri(["ar://", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"])
    assert ok and uri is not None and err is None


def test_reconstruct_chunked_uri_empty_array_is_invalid() -> None:
    ok, _uri, err = reconstruct_chunked_uri([])
    assert not ok and err == "INVALID_URI"


def test_reconstruct_chunked_uri_codepoint_aligned_split_passes() -> None:
    # A conformant producer MUST split at codepoint boundaries;
    # `chunk_text` is that producer-side splitter. After
    # canonical CBOR decode, every chunk arrives as a Python `str` (cbor2
    # rejects malformed UTF-8 tstr at decode and surfaces it as
    # MALFORMED_CBOR upstream). Reconstruction byte-concatenates the chunks
    # and decodes strictly, so it MUST succeed for any codepoint-aligned
    # chunking and round-trip the original string.
    smile = "\U0001f600"
    chunks = chunk_text(("a" + smile) * 5, max_bytes=8)
    ok, uri, err = reconstruct_chunked_uri(chunks)
    assert ok and err is None
    assert uri == ("a" + smile) * 5
