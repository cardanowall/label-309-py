"""Server-sent-events driver behind :meth:`PoeNamespace.wait`.

``GET /poe/events/{poe_id}`` is the gateway's push channel for a record's
publish lifecycle: the first frame is a ``state`` event carrying a full status
snapshot, followed by live ``poe_status_changed`` / ``cardano_submission_failed``
events carrying the same snapshot shape, with ``ping`` keepalives in between.
Each frame's SSE ``id`` is a durable sequence number; a reconnecting client
sends it back as ``last-event-id`` and the stream replays only newer events,
so no status change is lost across a drop.

The reader owns the bytes (EventSource-style helpers cannot attach the
``authorization`` header): it decodes the stream incrementally, enforces the
same safety limits as the gateway's parser (64 KiB per line, 256 KiB per
event), and reconnects with jittered 1/2/5/15/30 s backoff on network errors,
protocol violations, or a clean end before the target — resuming by id. A
concurrent-stream 429 waits out ``retry-after`` (or the next backoff step,
whichever is longer); any other definitive HTTP rejection raises the typed
error immediately.

Raw engine statuses are normalised before evaluation: ``submitted`` reads as
``confirming`` and ``permanent_failure`` as ``failed``; unknown statuses pass
through for forward compatibility.
"""

from __future__ import annotations

import asyncio
import json
import random
import urllib.parse
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Literal, NoReturn

import httpx

from .parse_http_error import parse_http_error
from .poe_failed_error import PoeFailedError
from .poe_wait_timeout_error import PoeWaitTimeoutError
from .types import PoeStatusSnapshot

# Parser safety limits, mirroring the gateway's SSE framing bounds. A single
# line (or an accumulated event) beyond these is a protocol violation: the
# connection is dropped and re-established rather than buffered unbounded.
_MAX_LINE_BYTES = 65_536
_MAX_EVENT_BYTES = 262_144

# Reconnect backoff ladder (seconds); the last step repeats. Each delay gets
# +/-20% jitter so a fleet of waiters does not thundering-herd a recovering
# gateway. The ladder resets after any connection that delivered a frame.
_BACKOFF_SECONDS = (1.0, 2.0, 5.0, 15.0, 30.0)
_JITTER_FRACTION = 0.2

# The stream stays open across long confirmation gaps bridged only by 30 s
# pings, so the read side must not time out on its own — the caller's overall
# deadline (asyncio.timeout) governs instead.
_STREAM_TIMEOUT = httpx.Timeout(connect=10.0, read=None, write=10.0, pool=10.0)

# Async sleep hook for the backoff waits; module-level so tests can stub it.
_sleep: Callable[[float], Awaitable[None]] = asyncio.sleep

PoeWaitTarget = Literal["submitted", "confirmed"]


@dataclass(frozen=True)
class _ResolvedConfig:
    api_key: str | None
    base_url: str
    http_client: httpx.AsyncClient


class _SseProtocolError(Exception):
    """A frame violated the SSE framing limits; the connection is recycled."""


@dataclass
class _SseEvent:
    name: str
    data: str
    id: str | None


@dataclass
class _SseParser:
    """Incremental SSE frame parser over raw response bytes.

    Feed byte chunks; complete events come back as they dispatch (on the blank
    line). Field handling follows the SSE grammar: ``event:`` / ``data:``
    (multi-line data joined with newlines) / ``id:``; ``:``-prefixed comment
    lines are ignored. Lines split on LF or CRLF. Both limits above are
    enforced while accumulating, so a hostile or corrupted stream cannot grow
    the buffers unbounded.
    """

    _buffer: bytearray = field(default_factory=bytearray)
    _event_name: str = ""
    _data_lines: list[str] = field(default_factory=list)
    _event_id: str | None = None
    _event_bytes: int = 0

    def feed(self, chunk: bytes) -> list[_SseEvent]:
        events: list[_SseEvent] = []
        self._buffer.extend(chunk)
        while True:
            newline = self._buffer.find(b"\n")
            if newline == -1:
                if len(self._buffer) > _MAX_LINE_BYTES:
                    raise _SseProtocolError("SSE line exceeds the 64 KiB limit")
                break
            if newline > _MAX_LINE_BYTES:
                raise _SseProtocolError("SSE line exceeds the 64 KiB limit")
            raw = bytes(self._buffer[:newline])
            del self._buffer[: newline + 1]
            if raw.endswith(b"\r"):
                raw = raw[:-1]
            event = self._handle_line(raw)
            if event is not None:
                events.append(event)
        return events

    def _handle_line(self, raw: bytes) -> _SseEvent | None:
        if not raw:
            return self._dispatch()
        self._event_bytes += len(raw)
        if self._event_bytes > _MAX_EVENT_BYTES:
            raise _SseProtocolError("SSE event exceeds the 256 KiB limit")
        line = raw.decode("utf-8", errors="replace")
        if line.startswith(":"):
            return None
        name, _, value = line.partition(":")
        if value.startswith(" "):
            value = value[1:]
        if name == "event":
            self._event_name = value
        elif name == "data":
            self._data_lines.append(value)
        elif name == "id" and "\x00" not in value:
            self._event_id = value
        return None

    def _dispatch(self) -> _SseEvent | None:
        # A blank line with nothing accumulated (e.g. between keepalives) is
        # not an event.
        if not self._event_name and not self._data_lines and self._event_id is None:
            return None
        event = _SseEvent(
            name=self._event_name or "message",
            data="\n".join(self._data_lines),
            id=self._event_id,
        )
        self._event_name = ""
        self._data_lines = []
        self._event_id = None
        self._event_bytes = 0
        return event


def _normalize_status(status: str) -> str:
    """Collapse raw engine statuses onto the wire lifecycle: ``submitted`` is
    the engine's post-submit state (already confirming from the client's view)
    and ``permanent_failure`` is the engine spelling of ``failed``. Unknown
    values pass through for forward compatibility."""
    if status == "submitted":
        return "confirming"
    if status == "permanent_failure":
        return "failed"
    return status


def _read_str(payload: dict[str, object], key: str) -> str | None:
    value = payload.get(key)
    return value if isinstance(value, str) else None


def _read_int(payload: dict[str, object], key: str) -> int | None:
    value = payload.get(key)
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value


def _parse_snapshot(data: str) -> PoeStatusSnapshot | None:
    """Parse an event's JSON payload into a normalised snapshot; tolerant of
    absent optional fields. ``None`` for payloads without a string ``status``
    (e.g. the ``ping`` keepalive's ``{}``)."""
    if not data:
        return None
    try:
        payload = json.loads(data)
    except json.JSONDecodeError:
        return None
    if not isinstance(payload, dict):
        return None
    status = payload.get("status")
    if not isinstance(status, str):
        return None
    return {
        "id": _read_str(payload, "id") or "",
        "status": _normalize_status(status),
        "tx_hash": _read_str(payload, "tx_hash"),
        "block_height": _read_int(payload, "block_height"),
        "block_time": _read_str(payload, "block_time"),
        "num_confirmations": _read_int(payload, "num_confirmations") or 0,
        "request_id": _read_str(payload, "request_id"),
    }


def _target_reached(status: str, target: PoeWaitTarget) -> bool:
    if target == "submitted":
        # `confirming` means the transaction left the gateway for the chain,
        # so it satisfies the weaker "submitted" target; `confirmed` trivially
        # satisfies both.
        return status in ("confirming", "confirmed")
    return status == "confirmed"


def _retry_after_seconds(response: httpx.Response) -> float | None:
    header = response.headers.get("retry-after")
    if header is None:
        return None
    try:
        return float(header)
    except ValueError:
        return None


def _raise_typed(response: httpx.Response) -> NoReturn:
    """Raise the typed error for a definitive (non-retryable) HTTP rejection.

    The response body must already be read (``aread``) by the caller."""
    try:
        body = response.json()
    except (json.JSONDecodeError, ValueError):
        body = None
    retry_after = _retry_after_seconds(response)
    raise parse_http_error(
        http_status=response.status_code,
        body=body,
        request_id=response.headers.get("x-request-id"),
        retry_after_seconds=int(retry_after) if retry_after is not None else None,
    )


class _WaitState:
    """Progress shared with the timeout wrapper, so a deadline can surface the
    last snapshot seen before it fired."""

    last_snapshot: PoeStatusSnapshot | None = None


async def wait_for_poe(
    config: _ResolvedConfig,
    poe_id: str,
    *,
    target: PoeWaitTarget,
    timeout: float | None = None,
) -> PoeStatusSnapshot:
    """Stream ``GET /poe/events/{poe_id}`` until ``target`` (or a terminal
    state) is reached; the transport/retry contract is documented on the
    module. Raises :class:`PoeFailedError` on the terminal ``failed`` status
    and :class:`PoeWaitTimeoutError` when ``timeout`` elapses first."""
    state = _WaitState()
    if timeout is None:
        return await _wait_loop(config, poe_id, target, state)
    try:
        async with asyncio.timeout(timeout):
            return await _wait_loop(config, poe_id, target, state)
    except TimeoutError as err:
        raise PoeWaitTimeoutError(state.last_snapshot) from err


async def _wait_loop(
    config: _ResolvedConfig,
    poe_id: str,
    target: PoeWaitTarget,
    state: _WaitState,
) -> PoeStatusSnapshot:
    url = f"{config.base_url}/poe/events/{urllib.parse.quote(poe_id, safe='')}"
    last_event_id: str | None = None
    ladder_idx = 0
    while True:
        headers = {"accept": "text/event-stream"}
        if config.api_key is not None:
            headers["authorization"] = f"Bearer {config.api_key}"
        if last_event_id is not None:
            headers["last-event-id"] = last_event_id
        retry_after: float | None = None
        delivered = False
        try:
            async with config.http_client.stream(
                "GET", url, headers=headers, timeout=_STREAM_TIMEOUT
            ) as response:
                if response.status_code == 429:
                    # Concurrent-stream cap: back off (honouring retry-after)
                    # and try again rather than failing the wait.
                    retry_after = _retry_after_seconds(response)
                elif response.status_code >= 500:
                    pass  # transient server-side failure: backoff retry below
                elif not response.is_success:
                    await response.aread()
                    _raise_typed(response)
                else:
                    parser = _SseParser()
                    async for chunk in response.aiter_bytes():
                        for event in parser.feed(chunk):
                            delivered = True
                            if event.id is not None:
                                last_event_id = event.id
                            if event.name == "ping":
                                continue
                            snapshot = _parse_snapshot(event.data)
                            if snapshot is None:
                                continue
                            state.last_snapshot = snapshot
                            if snapshot["status"] == "failed":
                                raise PoeFailedError(snapshot)
                            if _target_reached(snapshot["status"], target):
                                return snapshot
                    # Clean stream end without the target: reconnect below,
                    # resuming from the last seen frame id.
        except _SseProtocolError:
            pass  # framing violation: drop the connection and resume by id
        except httpx.HTTPError:
            pass  # network failure: reconnect with backoff

        if delivered:
            ladder_idx = 0
        delay = _BACKOFF_SECONDS[min(ladder_idx, len(_BACKOFF_SECONDS) - 1)]
        ladder_idx += 1
        # Jitter is de-synchronisation, not security material.
        delay *= 1.0 + random.uniform(-_JITTER_FRACTION, _JITTER_FRACTION)  # noqa: S311
        if retry_after is not None:
            delay = max(delay, retry_after)
        await _sleep(delay)


__all__ = ["PoeWaitTarget", "wait_for_poe"]
