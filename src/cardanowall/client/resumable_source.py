"""Byte-source abstraction for the resumable upload driver.

A :class:`ResumableSource` exposes a fixed ``size`` plus two async readers — a
positional ``slice(start, end)`` (for sending one chunk) and a whole-source
``stream()`` (for the one-time whole-file hash on a fresh create). Three inputs
adapt to it: an in-memory ``bytes``/``bytearray``, a filesystem path
(``str`` / :class:`os.PathLike`), and an already-open binary file object
(anything with ``read``/``seek``). A source that is already a
:class:`ResumableSource` passes through.

Parity twin: ``resumable-source.ts`` in ``@cardanowall/sdk-ts`` (which adapts
``Blob`` / ``Uint8Array`` / a path string). The slice/stream methods are async
because the upload driver is async over :class:`httpx.AsyncClient`; a path or
file-like source therefore performs its I/O off the event-loop thread.
"""

from __future__ import annotations

import asyncio
import os
from collections.abc import AsyncIterator
from pathlib import Path
from typing import BinaryIO, Protocol, Union, cast, runtime_checkable

# Whole-source streaming granularity for the one-time hash on a fresh create —
# read the source 1 MiB at a time so a multi-GB file is never materialised.
_STREAM_CHUNK_BYTES = 1024 * 1024


@runtime_checkable
class ResumableSource(Protocol):
    """A sized, randomly-sliceable, streamable byte source."""

    @property
    def size(self) -> int:
        """Total number of bytes in the source."""
        ...

    async def slice(self, start: int, end: int) -> bytes:
        """Return ``[start, end)`` as a fresh ``bytes`` (``end`` exclusive)."""
        ...

    def stream(self) -> AsyncIterator[bytes]:
        """Yield the whole source in order as byte chunks."""
        ...


# A path (str / os.PathLike), in-memory bytes, an open binary file, or an
# already-built ResumableSource.
ResumableSourceInput = Union[
    ResumableSource, bytes, bytearray, memoryview, str, "os.PathLike[str]", BinaryIO
]


class _BytesSource:
    """In-memory ``bytes`` source: zero-copy slices via ``memoryview``."""

    def __init__(self, data: bytes) -> None:
        self._data = data
        self._view = memoryview(data)

    @property
    def size(self) -> int:
        return len(self._data)

    async def slice(self, start: int, end: int) -> bytes:
        return bytes(self._view[start:end])

    async def stream(self) -> AsyncIterator[bytes]:
        for pos in range(0, len(self._data), _STREAM_CHUNK_BYTES):
            yield bytes(self._view[pos : pos + _STREAM_CHUNK_BYTES])


class _PathSource:
    """Filesystem-path source: positional reads, re-opened per slice.

    Each ``slice`` opens the file, seeks, and loops until the requested range is
    filled (handling OS short reads); ``stream`` reads sequentially in 1 MiB
    chunks. All blocking I/O is dispatched to a worker thread so the async upload
    driver is never blocked.
    """

    def __init__(self, path: Path) -> None:
        self._path = path
        self._size = path.stat().st_size

    @property
    def size(self) -> int:
        return self._size

    async def slice(self, start: int, end: int) -> bytes:
        length = end - start
        if length <= 0:
            return b""
        return await asyncio.to_thread(self._read_range, start, length)

    def _read_range(self, start: int, length: int) -> bytes:
        out = bytearray()
        with self._path.open("rb") as fh:
            fh.seek(start)
            while len(out) < length:
                chunk = fh.read(length - len(out))
                if not chunk:
                    break
                out += chunk
        return bytes(out)

    async def stream(self) -> AsyncIterator[bytes]:
        fh = await asyncio.to_thread(self._path.open, "rb")
        try:
            while True:
                chunk = await asyncio.to_thread(fh.read, _STREAM_CHUNK_BYTES)
                if not chunk:
                    return
                yield chunk
        finally:
            await asyncio.to_thread(fh.close)


class _FileObjectSource:
    """Open binary file-object source (anything with ``read``/``seek``).

    The size is measured once via ``seek(0, SEEK_END)``. Slices seek + read on a
    lock-guarded worker thread, since a shared handle's position is not safe
    under the driver's parallel chunk reads.
    """

    def __init__(self, fileobj: BinaryIO) -> None:
        if not (hasattr(fileobj, "read") and hasattr(fileobj, "seek")):
            raise TypeError("file-like source MUST support read() and seek()")
        self._fileobj = fileobj
        current = fileobj.tell()
        fileobj.seek(0, os.SEEK_END)
        self._size = fileobj.tell()
        fileobj.seek(current, os.SEEK_SET)
        self._lock = asyncio.Lock()

    @property
    def size(self) -> int:
        return self._size

    async def slice(self, start: int, end: int) -> bytes:
        length = end - start
        if length <= 0:
            return b""
        async with self._lock:
            return await asyncio.to_thread(self._read_range, start, length)

    def _read_range(self, start: int, length: int) -> bytes:
        out = bytearray()
        self._fileobj.seek(start)
        while len(out) < length:
            chunk = self._fileobj.read(length - len(out))
            if not chunk:
                break
            out += chunk
        return bytes(out)

    async def stream(self) -> AsyncIterator[bytes]:
        pos = 0
        while pos < self._size:
            end = min(pos + _STREAM_CHUNK_BYTES, self._size)
            yield await self.slice(pos, end)
            pos = end


def to_resumable_source(source: ResumableSourceInput) -> ResumableSource:
    """Adapt any accepted input into a :class:`ResumableSource`.

    Order of detection: an already-built ``ResumableSource`` (duck-typed on
    ``size`` + ``slice`` + ``stream``, excluding raw byte containers) passes
    through; ``bytes``/``bytearray``/``memoryview`` become an in-memory source;
    a ``str`` / :class:`os.PathLike` becomes a path source; anything else with
    ``read`` + ``seek`` becomes a file-object source.
    """
    if isinstance(source, (bytes, bytearray, memoryview)):
        return _BytesSource(bytes(source))
    if isinstance(source, (str, os.PathLike)):
        return _PathSource(Path(source))
    # An already-built ResumableSource (has size/slice/stream but is not a raw
    # byte container, handled above).
    if (
        hasattr(source, "size")
        and callable(getattr(source, "slice", None))
        and callable(getattr(source, "stream", None))
    ):
        return source  # type: ignore[return-value]
    if hasattr(source, "read") and hasattr(source, "seek"):
        # The ResumableSource protocol was already matched above, so at this point
        # the source is an open binary file object.
        return _FileObjectSource(cast("BinaryIO", source))
    raise TypeError(
        "source MUST be bytes, a filesystem path, an open binary file, or a ResumableSource"
    )


__all__ = ["ResumableSource", "ResumableSourceInput", "to_resumable_source"]
