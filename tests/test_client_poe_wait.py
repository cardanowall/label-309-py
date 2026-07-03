"""Behaviour tests for ``PoeNamespace.wait`` — the SSE status wait.

A streaming :class:`httpx.MockTransport` serves scripted SSE frames, covering
the full matrix: target resolution (including the initial ``state`` frame),
raw-status normalisation (``submitted`` → ``confirming``,
``permanent_failure`` → ``failed``), the terminal-failure and timeout error
paths, keepalive ``ping`` frames, the reconnect-with-``last-event-id`` resume,
the oversized-line framing guard, the 429 concurrent-stream backoff, and task
cancellation.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator, Awaitable, Callable
from typing import Any

import httpx
import pytest

from cardanowall.client import poe_events
from cardanowall.client.label309_client import Label309Client
from cardanowall.client.not_found_error import NotFoundError
from cardanowall.client.poe_failed_error import PoeFailedError
from cardanowall.client.poe_wait_timeout_error import PoeWaitTimeoutError

API_KEY = "opaque-bearer-fixture-token"
BASE = "http://test.example/api/v1"
POE_ID = "poe_06bqrjg0csvqfanaqexvqexvqc"


class _FrameStream(httpx.AsyncByteStream):
    """Serve scripted byte frames as a streaming response body."""

    def __init__(self, frames: list[bytes], *, hang_after: bool = False) -> None:
        self._frames = frames
        self._hang_after = hang_after

    async def __aiter__(self) -> AsyncIterator[bytes]:
        for frame in self._frames:
            yield frame
        if self._hang_after:
            # An idle-but-open stream (a gateway between status changes);
            # only cancellation or the caller's deadline ends it.
            await asyncio.Event().wait()

    async def aclose(self) -> None:
        return None


def _snap(status: str, **overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "id": POE_ID,
        "status": status,
        "tx_hash": None,
        "block_height": None,
        "block_time": None,
        "num_confirmations": 0,
        "request_id": "req-fixture",
    }
    payload.update(overrides)
    return payload


def _frame(event: str, data: dict[str, object], event_id: int | None = None) -> bytes:
    lines: list[str] = []
    if event_id is not None:
        lines.append(f"id: {event_id}")
    lines.append(f"event: {event}")
    lines.append(f"data: {json.dumps(data)}")
    return ("\n".join(lines) + "\n\n").encode()


def _ping() -> bytes:
    return b"event: ping\ndata: {}\n\n"


def _sse_response(frames: list[bytes], *, hang_after: bool = False) -> httpx.Response:
    return httpx.Response(
        200,
        stream=_FrameStream(frames, hang_after=hang_after),
        headers={"content-type": "text/event-stream"},
    )


def _sequential_client(
    responses: list[httpx.Response],
) -> tuple[Label309Client, list[httpx.Request]]:
    """A client whose transport serves ``responses`` in order, recording every
    request for header/path assertions."""
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return responses[len(requests) - 1]

    transport = httpx.MockTransport(handler)
    client = Label309Client(
        api_key=API_KEY,
        base_url=BASE,
        http_client=httpx.AsyncClient(transport=transport),
    )
    return client, requests


def _instant_sleep(record: list[float]) -> Callable[[float], Awaitable[None]]:
    async def sleeper(seconds: float) -> None:
        record.append(seconds)

    return sleeper


# ---------------------------------------------------------------------------
# Target resolution + normalisation
# ---------------------------------------------------------------------------


def test_wait_confirmed_happy_path_streams_to_confirmed() -> None:
    async def run() -> None:
        client, requests = _sequential_client(
            [
                _sse_response(
                    [
                        _frame("state", _snap("submitting"), event_id=1),
                        _ping(),
                        _frame(
                            "poe_status_changed",
                            _snap("confirming", tx_hash="ab" * 32),
                            event_id=2,
                        ),
                        _frame(
                            "poe_status_changed",
                            _snap(
                                "confirmed",
                                tx_hash="ab" * 32,
                                block_height=1200,
                                block_time="2026-07-03T12:00:00Z",
                                num_confirmations=3,
                            ),
                            event_id=3,
                        ),
                    ]
                )
            ]
        )
        async with client:
            out = await client.poe.wait(POE_ID, target="confirmed")
        assert out["status"] == "confirmed"
        assert out["tx_hash"] == "ab" * 32
        assert out["block_height"] == 1200
        assert out["num_confirmations"] == 3
        # One connection was enough; it carried the SSE accept + bearer auth
        # and hit the record's events resource.
        assert len(requests) == 1
        assert requests[0].url.path == "/api/v1/poe/events/" + POE_ID
        assert requests[0].headers["accept"] == "text/event-stream"
        assert requests[0].headers["authorization"] == f"Bearer {API_KEY}"
        assert "last-event-id" not in requests[0].headers

    asyncio.run(run())


def test_wait_returns_instantly_when_state_already_confirmed() -> None:
    async def run() -> None:
        client, _requests = _sequential_client(
            [_sse_response([_frame("state", _snap("confirmed", num_confirmations=12))])]
        )
        async with client:
            out = await client.poe.wait(POE_ID)
        assert out["status"] == "confirmed"
        assert out["num_confirmations"] == 12

    asyncio.run(run())


def test_wait_target_submitted_resolves_on_confirming() -> None:
    async def run() -> None:
        client, _requests = _sequential_client(
            [
                _sse_response(
                    [
                        _frame("state", _snap("submitting")),
                        _frame("poe_status_changed", _snap("confirming")),
                    ]
                )
            ]
        )
        async with client:
            out = await client.poe.wait(POE_ID, target="submitted")
        assert out["status"] == "confirming"

    asyncio.run(run())


def test_wait_raw_submitted_normalizes_and_satisfies_target_submitted() -> None:
    async def run() -> None:
        client, _requests = _sequential_client(
            [_sse_response([_frame("state", _snap("submitted"))])]
        )
        async with client:
            out = await client.poe.wait(POE_ID, target="submitted")
        # The raw engine status is normalised in the returned snapshot.
        assert out["status"] == "confirming"

    asyncio.run(run())


# ---------------------------------------------------------------------------
# Terminal failure
# ---------------------------------------------------------------------------


def test_wait_failed_raises_with_snapshot() -> None:
    async def run() -> None:
        client, _requests = _sequential_client(
            [
                _sse_response(
                    [
                        _frame("state", _snap("submitting")),
                        _frame("poe_status_changed", _snap("failed")),
                    ]
                )
            ]
        )
        async with client:
            with pytest.raises(PoeFailedError) as excinfo:
                await client.poe.wait(POE_ID)
        assert excinfo.value.snapshot["status"] == "failed"
        assert excinfo.value.snapshot["id"] == POE_ID

    asyncio.run(run())


def test_wait_submission_failed_event_normalizes_permanent_failure() -> None:
    async def run() -> None:
        client, _requests = _sequential_client(
            [
                _sse_response(
                    [
                        _frame("state", _snap("submitting")),
                        _frame("cardano_submission_failed", _snap("permanent_failure")),
                    ]
                )
            ]
        )
        async with client:
            with pytest.raises(PoeFailedError) as excinfo:
                await client.poe.wait(POE_ID)
        assert excinfo.value.snapshot["status"] == "failed"

    asyncio.run(run())


# ---------------------------------------------------------------------------
# Reconnect / framing limits / backoff
# ---------------------------------------------------------------------------


def test_wait_reconnect_resumes_with_last_event_id(monkeypatch: pytest.MonkeyPatch) -> None:
    delays: list[float] = []
    monkeypatch.setattr(poe_events, "_sleep", _instant_sleep(delays))

    async def run() -> None:
        client, requests = _sequential_client(
            [
                # First connection: the state frame arrives (id 5), then the
                # stream ends without the target.
                _sse_response([_frame("state", _snap("submitting"), event_id=5)]),
                _sse_response([_frame("state", _snap("confirmed"), event_id=6)]),
            ]
        )
        async with client:
            out = await client.poe.wait(POE_ID)
        assert out["status"] == "confirmed"
        assert len(requests) == 2
        assert "last-event-id" not in requests[0].headers
        assert requests[1].headers["last-event-id"] == "5"

    asyncio.run(run())
    # One backoff wait between the two connections, on the first ladder step
    # (1 s ± 20% jitter) since the first connection delivered a frame.
    assert len(delays) == 1
    assert 0.8 <= delays[0] <= 1.2


def test_wait_does_not_resume_from_uncommitted_frame_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An ``id:`` from a frame the stream cut off before the terminating blank
    line must not become the resume point: the frame was never dispatched, and
    resuming past it would skip its replay. The reconnect must carry NO
    ``last-event-id``, and the cut-off ``confirmed`` payload must not have
    resolved the wait."""
    delays: list[float] = []
    monkeypatch.setattr(poe_events, "_sleep", _instant_sleep(delays))

    truncated = (
        f"id: 42\nevent: poe_status_changed\ndata: {json.dumps(_snap('confirmed'))}\n"
    ).encode()  # no terminating blank line

    async def run() -> None:
        client, requests = _sequential_client(
            [
                _sse_response([truncated]),
                _sse_response([_frame("state", _snap("confirmed"), event_id=43)]),
            ]
        )
        async with client:
            out = await client.poe.wait(POE_ID)
        assert out["status"] == "confirmed"
        assert len(requests) == 2
        assert "last-event-id" not in requests[1].headers

    asyncio.run(run())


def test_wait_oversized_line_drops_connection_and_reconnects(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    delays: list[float] = []
    monkeypatch.setattr(poe_events, "_sleep", _instant_sleep(delays))

    async def run() -> None:
        oversized = b"data: " + b"a" * 70_000 + b"\n\n"
        client, requests = _sequential_client(
            [
                _sse_response([_frame("state", _snap("submitting"), event_id=1), oversized]),
                _sse_response([_frame("state", _snap("confirmed"), event_id=2)]),
            ]
        )
        async with client:
            out = await client.poe.wait(POE_ID)
        assert out["status"] == "confirmed"
        # The oversized line was not buffered or delivered — the connection
        # was recycled and the wait resumed from the last complete frame.
        assert len(requests) == 2
        assert requests[1].headers["last-event-id"] == "1"

    asyncio.run(run())
    assert len(delays) == 1


def test_wait_429_waits_out_retry_after_then_retries(monkeypatch: pytest.MonkeyPatch) -> None:
    delays: list[float] = []
    monkeypatch.setattr(poe_events, "_sleep", _instant_sleep(delays))

    async def run() -> None:
        client, requests = _sequential_client(
            [
                httpx.Response(
                    429,
                    headers={"retry-after": "7"},
                    json={"code": "rate-limited", "title": "concurrent stream cap"},
                ),
                _sse_response([_frame("state", _snap("confirmed"))]),
            ]
        )
        async with client:
            out = await client.poe.wait(POE_ID)
        assert out["status"] == "confirmed"
        assert len(requests) == 2

    asyncio.run(run())
    # The wait honoured the server's retry-after (7 s > the 1 s ladder step).
    assert delays == [7.0]


def test_wait_definitive_http_error_raises_typed() -> None:
    async def run() -> None:
        client, requests = _sequential_client(
            [
                httpx.Response(
                    404,
                    json={
                        "type": "https://cardanowall.com/problems/not-found",
                        "title": "not found",
                        "status": 404,
                        "code": "not-found",
                        "detail": "no such record",
                    },
                )
            ]
        )
        async with client:
            with pytest.raises(NotFoundError):
                await client.poe.wait(POE_ID)
        # A definitive rejection is not retried.
        assert len(requests) == 1

    asyncio.run(run())


# ---------------------------------------------------------------------------
# Deadline + cancellation
# ---------------------------------------------------------------------------


def test_wait_timeout_raises_with_last_snapshot() -> None:
    async def run() -> None:
        client, _requests = _sequential_client(
            [_sse_response([_frame("state", _snap("submitting"))], hang_after=True)]
        )
        async with client:
            with pytest.raises(PoeWaitTimeoutError) as excinfo:
                await client.poe.wait(POE_ID, timeout=0.05)
        last = excinfo.value.last_snapshot
        assert last is not None
        assert last["status"] == "submitting"

    asyncio.run(run())


def test_wait_cancellation_propagates() -> None:
    async def run() -> None:
        client, _requests = _sequential_client(
            [_sse_response([_frame("state", _snap("submitting"))], hang_after=True)]
        )
        async with client:
            task: asyncio.Task[Any] = asyncio.create_task(client.poe.wait(POE_ID))
            await asyncio.sleep(0.02)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task

    asyncio.run(run())
