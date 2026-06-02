from __future__ import annotations

# Chunked-bytes / chunked-text helpers. Cardano metadata `bstr` / `tstr`
# cap is 64 bytes, so any logical byte-string or URI longer than 64 bytes
# is carried as an array of ≤ 64-byte chunks. The chunk arrays are
# non-empty (`1*`) and each chunk satisfies `.size (1..64)` — empty inputs
# are deliberately disallowed at this layer.

CHUNK_MAX_BYTES = 64


def chunk_bytes(value: bytes) -> list[bytes]:
    """Split a logical byte string into ≤ 64-byte CBOR-bytes segments.

    Always returns a non-empty list (the chunked-bytes form has no scalar
    variant). For an empty input, returns ``[b""]`` so the caller's schema
    invariant (array of ≥ 1 element) holds; a zero-length chunk fails the
    structural-validator's ``CHUNK_TOO_LARGE`` gate (each chunk MUST be 1..64
    bytes), which is correct: an empty logical value should never be serialised
    as a chunked bytes array.
    """
    if len(value) == 0:
        return [b""]
    return [value[i : i + CHUNK_MAX_BYTES] for i in range(0, len(value), CHUNK_MAX_BYTES)]


def chunk_text(value: str, max_bytes: int = CHUNK_MAX_BYTES) -> list[str]:
    """Split a logical text string into ≤ ``max_bytes``-byte UTF-8 chunks.

    Implements the CIP-309 ``uri-chunk-array`` producer-side splitter:
    each output chunk's UTF-8 encoding is ≤ ``max_bytes``, AND no multi-byte
    UTF-8 codepoint is split across chunk boundaries. The split is greedy:
    each chunk holds as many whole codepoints as fit in the byte budget. The
    inverse is ``"".join(chunks)``.
    """
    if max_bytes < 1:
        raise ValueError("max_bytes must be >= 1")
    if value == "":
        return [""]
    out: list[str] = []
    current_chars: list[str] = []
    current_byte_count = 0
    for ch in value:
        ch_bytes = len(ch.encode("utf-8"))
        if ch_bytes > max_bytes:
            # A single codepoint larger than the chunk budget cannot satisfy
            # the no-split rule under ANY split — surface immediately.
            raise ValueError(
                f"codepoint U+{ord(ch):04X} encodes to {ch_bytes} bytes, "
                f"exceeds max_bytes={max_bytes}",
            )
        if current_byte_count + ch_bytes > max_bytes:
            out.append("".join(current_chars))
            current_chars = [ch]
            current_byte_count = ch_bytes
        else:
            current_chars.append(ch)
            current_byte_count += ch_bytes
    if current_chars:
        out.append("".join(current_chars))
    return out


def bytes_chunk_array_concat(chunks: list[bytes]) -> bytes:
    """Concatenate a chunked-bytes-array back into the underlying byte
    string. Inverse of ``chunk_bytes``."""
    return b"".join(chunks)


def reconstruct_chunked_uri(
    chunks: list[str],
) -> tuple[bool, str | None, str | None]:
    """Reconstruct a chunked-tstr-array into a single URI string.

    Returns ``(ok, uri_or_none, error_code_or_none)`` where the error code is
    ``"INVALID_URI"`` when reconstruction fails.

    The chunks arrive as Python ``str`` values produced by the canonical-CBOR
    decoder, which already rejects any non-UTF-8 ``tstr`` (surfacing it
    upstream as ``MALFORMED_CBOR``). The only structural task left here is to
    byte-concatenate the chunks and decode the result strictly; a conformant
    producer never splits a multi-byte codepoint across chunks, so this decode
    succeeds for every well-formed record. The ``INVALID_URI`` branch is the
    residual guard for a byte sequence that does not reconstruct to valid
    UTF-8.
    """
    if not chunks:
        return False, None, "INVALID_URI"
    concat_bytes = b"".join(c.encode("utf-8") for c in chunks)
    try:
        return True, concat_bytes.decode("utf-8"), None
    except UnicodeDecodeError:
        return False, None, "INVALID_URI"


__all__ = [
    "CHUNK_MAX_BYTES",
    "bytes_chunk_array_concat",
    "chunk_bytes",
    "chunk_text",
    "reconstruct_chunked_uri",
]
