"""Behaviour tests for the resumable upload driver against a stub gateway.

A stateful :class:`httpx.MockTransport` handler models the session lifecycle
(create → ``missing[]`` → chunk PUT → complete), plus resume, the create-time
dedup short-circuit, the 409 incomplete-resend, and abandon (DELETE). No new
crypto vectors — these assert the transport state machine: which routes are hit,
the per-chunk ``Digest`` header, the missing-set drive, and the cancel→abandon
behaviour.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
from typing import Any

import httpx
import pytest

from cardanowall.client.label309_client import Label309Client
from cardanowall.client.partial_upload_error import PartialUploadError
from cardanowall.client.resumable_upload import (
    RESUMABLE_THRESHOLD_BYTES,
    ResumableUploadError,
    UploadCancelledError,
)
from cardanowall.client.types import UploadProgress

API_KEY = "opaque-bearer-fixture-token"
BASE = "http://test.example/api/v1"


def _client(handler: Any) -> Label309Client:
    transport = httpx.MockTransport(handler)
    return Label309Client(
        api_key=API_KEY,
        base_url=BASE,
        http_client=httpx.AsyncClient(transport=transport),
    )


class StubGateway:
    """A minimal content-addressed upload-session gateway over MockTransport.

    Tracks one session's received chunk indices, validates each chunk's
    ``Digest`` header, and serves create / status / chunk / complete / abandon.
    Records the routes it served for assertions.
    """

    def __init__(
        self,
        *,
        chunk_bytes: int = 16,
        dedup_at_create: bool = False,
        complete_mode: str = "ok",  # 'ok' | 'accepted' | 'incomplete-once'
    ) -> None:
        self.chunk_bytes = chunk_bytes
        self.dedup_at_create = dedup_at_create
        self.complete_mode = complete_mode
        self.session_id = "11111111-1111-1111-1111-111111111111"
        self.attempt_id = "22222222-2222-2222-2222-222222222222"
        self.total_bytes = 0
        self.chunk_count = 0
        self.declared_sha256 = ""
        self.received: set[int] = set()
        self.calls: list[tuple[str, str]] = []
        self.digests: dict[int, str] = {}
        self._complete_attempts = 0
        # When set, drop these indices server-side AFTER the first complete to
        # exercise the 409 incomplete-resend path.
        self.drop_on_first_complete: set[int] = set()
        self.abandoned = False
        self.put_count = 0

    def __call__(self, request: httpx.Request) -> httpx.Response:
        method = request.method
        path = request.url.path
        self.calls.append((method, path))
        sessions = "/api/v1/poe/uploads/sessions"

        if method == "POST" and path == sessions:
            return self._create(request)
        if method == "GET" and path == f"{sessions}/{self.session_id}":
            return self._status()
        if method == "PUT" and path.startswith(f"{sessions}/{self.session_id}/chunks/"):
            return self._put_chunk(request, int(path.rsplit("/", 1)[1]))
        if method == "POST" and path == f"{sessions}/{self.session_id}/complete":
            return self._complete()
        if method == "DELETE" and path == f"{sessions}/{self.session_id}":
            self.abandoned = True
            return httpx.Response(204)
        if method == "GET" and path.startswith("/api/v1/poe/uploads/attempts/"):
            return self._attempt()
        return httpx.Response(404, json={"code": "not-found", "title": "route"})

    def _create(self, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        self.declared_sha256 = body["sha256"]
        self.total_bytes = body["total_bytes"]
        if self.dedup_at_create:
            return httpx.Response(
                200,
                json={
                    "deduplicated": True,
                    "uri": "ar://deduped",
                    "sha256": self.declared_sha256,
                    "bytes": self.total_bytes,
                    "charged_usd_micros": 0,
                },
            )
        self.chunk_count = max(1, -(-self.total_bytes // self.chunk_bytes))
        return httpx.Response(
            201,
            json={
                "session_id": self.session_id,
                "chunk_bytes": self.chunk_bytes,
                "chunk_count": self.chunk_count,
                "received": [],
                "expires_at": "2026-06-16T00:00:00Z",
                "max_chunk_bytes": self.chunk_bytes,
            },
        )

    def _status(self) -> httpx.Response:
        missing = [i for i in range(self.chunk_count) if i not in self.received]
        return httpx.Response(
            200,
            json={
                "session_id": self.session_id,
                "state": "assembling" if missing else "pending",
                "sha256": self.declared_sha256,
                "total_bytes": self.total_bytes,
                "chunk_bytes": self.chunk_bytes,
                "chunk_count": self.chunk_count,
                "received": sorted(self.received),
                "missing": missing,
                "attempt_id": None,
                "uri": None,
            },
        )

    def _put_chunk(self, request: httpx.Request, index: int) -> httpx.Response:
        self.put_count += 1
        digest_header = request.headers.get("digest", "")
        expected = "sha-256=" + base64.b64encode(hashlib.sha256(request.content).digest()).decode()
        if digest_header != expected:
            return httpx.Response(400, json={"code": "chunk-digest-mismatch", "title": "digest"})
        self.digests[index] = digest_header
        self.received.add(index)
        remaining = self.chunk_count - len(self.received)
        return httpx.Response(
            200,
            json={
                "index": index,
                "received": sorted(self.received),
                "remaining": remaining,
                "complete": remaining == 0,
            },
        )

    def _complete(self) -> httpx.Response:
        self._complete_attempts += 1
        if self._complete_attempts == 1 and self.drop_on_first_complete:
            # Simulate dropped writes: forget some chunks and report 409.
            self.received -= self.drop_on_first_complete
            self.drop_on_first_complete = set()
            return httpx.Response(
                409,
                json={"code": "incomplete-upload", "title": "incomplete"},
            )
        if len(self.received) < self.chunk_count:
            return httpx.Response(409, json={"code": "incomplete-upload", "title": "incomplete"})
        if self.complete_mode == "accepted":
            return httpx.Response(200, json={"accepted": True, "attempt_id": self.attempt_id})
        return httpx.Response(
            200,
            json={
                "ok": True,
                "uri": "ar://assembled",
                "sha256": self.declared_sha256,
                "bytes": self.total_bytes,
                "charged_usd_micros": 12345,
            },
        )

    def _attempt(self) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "attempt_id": self.attempt_id,
                "state": "committed",
                "sha256": self.declared_sha256,
                "bytes": self.total_bytes,
                "backend": "arweave",
                "uri": "ar://assembled",
                "charged_usd_micros": 12345,
            },
        )


# ---------------------------------------------------------------------------
# Single-shot path (file <= threshold).
# ---------------------------------------------------------------------------


def test_small_file_uses_single_shot_uploads() -> None:
    async def run() -> None:
        captured: dict[str, Any] = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured["path"] = request.url.path
            return httpx.Response(
                200,
                json={
                    "uploads": [
                        {"idx": 0, "ok": True, "uri": "ar://small", "sha256": "ab", "bytes": 5}
                    ]
                },
            )

        async with _client(handler) as client:
            result = await client.poe.upload_resumable(source=b"hello")
            assert result["mode"] == "single-shot"
            assert result["uri"] == "ar://small"
            assert result["deduplicated"] is False
        # The single-shot path posts the multipart /poe/uploads route, not a session.
        assert captured["path"] == "/api/v1/poe/uploads"

    asyncio.run(run())


def test_small_file_per_file_failure_raises_partial_upload_error() -> None:
    async def run() -> None:
        def handler(_request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json={
                    "uploads": [
                        {
                            "idx": 0,
                            "ok": False,
                            "error": {"code": "provider-rejected", "detail": "nope"},
                        }
                    ]
                },
            )

        async with _client(handler) as client:
            with pytest.raises(PartialUploadError):
                await client.poe.upload_resumable(source=b"hello")

    asyncio.run(run())


# ---------------------------------------------------------------------------
# Chunked session path: create -> missing[] -> PUT each -> complete.
# ---------------------------------------------------------------------------


def test_large_file_chunked_session_full_flow() -> None:
    async def run() -> None:
        gw = StubGateway(chunk_bytes=16)
        # 40 bytes over a 16-byte grid → 3 chunks (16, 16, 8).
        data = bytes((i * 3) & 0xFF for i in range(40))
        progress: list[UploadProgress] = []
        created_ids: list[str] = []

        async with _client(gw) as client:
            result = await client.poe.upload_resumable(
                source=data,
                threshold=8,  # force the chunked path
                on_progress=progress.append,
                on_session_created=created_ids.append,
            )
        assert result["mode"] == "chunked"
        assert result["uri"] == "ar://assembled"
        # All three chunks were PUT, each with a valid Digest header.
        assert gw.received == {0, 1, 2}
        assert len(gw.digests) == 3
        # on_session_created fired with the session id before any chunk PUT.
        assert created_ids == [gw.session_id]
        # Progress fired once per chunk.
        assert len(progress) == 3
        assert progress[-1]["chunks_total"] == 3
        # The lifecycle hit create, three chunk PUTs, and complete.
        methods = [m for (m, _p) in gw.calls]
        assert methods.count("PUT") == 3
        assert ("POST", "/api/v1/poe/uploads/sessions") in gw.calls
        assert ("POST", f"/api/v1/poe/uploads/sessions/{gw.session_id}/complete") in gw.calls

    asyncio.run(run())


def test_chunk_digest_header_is_per_chunk_sha256_base64() -> None:
    async def run() -> None:
        gw = StubGateway(chunk_bytes=16)
        data = bytes(range(16)) + bytes(range(16, 24))  # 24 bytes → 2 chunks (16 + 8)
        async with _client(gw) as client:
            await client.poe.upload_resumable(source=data, threshold=8)
        # Chunk 0 is bytes[0:16], chunk 1 is bytes[16:24]; verify the stored
        # Digest headers match the per-chunk SHA-256.
        c0 = "sha-256=" + base64.b64encode(hashlib.sha256(data[0:16]).digest()).decode()
        c1 = "sha-256=" + base64.b64encode(hashlib.sha256(data[16:24]).digest()).decode()
        assert gw.digests[0] == c0
        assert gw.digests[1] == c1

    asyncio.run(run())


def test_complete_accepted_polls_attempt_to_committed() -> None:
    async def run() -> None:
        gw = StubGateway(chunk_bytes=16, complete_mode="accepted")
        data = b"x" * 20  # 2 chunks
        async with _client(gw) as client:
            result = await client.poe.upload_resumable(source=data, threshold=8)
        assert result["uri"] == "ar://assembled"
        # The attempt endpoint was polled.
        assert any(p.startswith("/api/v1/poe/uploads/attempts/") for (_m, p) in gw.calls)

    asyncio.run(run())


# ---------------------------------------------------------------------------
# Create-time dedup short-circuit.
# ---------------------------------------------------------------------------


def test_create_time_dedup_short_circuits_without_chunks() -> None:
    async def run() -> None:
        gw = StubGateway(dedup_at_create=True)
        data = b"y" * 40
        async with _client(gw) as client:
            result = await client.poe.upload_resumable(source=data, threshold=8)
        assert result["deduplicated"] is True
        assert result["uri"] == "ar://deduped"
        # No chunk was PUT.
        assert gw.put_count == 0
        assert all(m != "PUT" for (m, _p) in gw.calls)

    asyncio.run(run())


# ---------------------------------------------------------------------------
# Resume: pass session_id; only missing chunks are re-sent, no rehash.
# ---------------------------------------------------------------------------


def test_resume_sends_only_missing_chunks() -> None:
    async def run() -> None:
        gw = StubGateway(chunk_bytes=16)
        # Pre-seed server state as if chunks 0 and 1 already landed; only chunk 2
        # is missing. The driver adopts the server status (no rehash).
        gw.total_bytes = 40
        gw.chunk_count = 3
        gw.declared_sha256 = "deadbeef"
        gw.received = {0, 1}
        data = bytes((i * 3) & 0xFF for i in range(40))
        async with _client(gw) as client:
            result = await client.poe.upload_resumable(
                source=data, threshold=8, session_id=gw.session_id
            )
        assert result["uri"] == "ar://assembled"
        # Only chunk 2 was PUT on resume.
        assert gw.put_count == 1
        assert 2 in gw.digests
        # Resume starts with a GET status, never a create.
        assert ("GET", f"/api/v1/poe/uploads/sessions/{gw.session_id}") in gw.calls
        assert ("POST", "/api/v1/poe/uploads/sessions") not in gw.calls

    asyncio.run(run())


# ---------------------------------------------------------------------------
# 409 incomplete-upload at /complete → resend the gap → retry.
# ---------------------------------------------------------------------------


def test_incomplete_upload_resends_dropped_chunks() -> None:
    async def run() -> None:
        gw = StubGateway(chunk_bytes=16)
        gw.drop_on_first_complete = {1}  # server forgets chunk 1 after the first complete
        data = bytes((i * 5) & 0xFF for i in range(40))  # 3 chunks
        async with _client(gw) as client:
            result = await client.poe.upload_resumable(source=data, threshold=8)
        assert result["uri"] == "ar://assembled"
        # Chunk 1 was PUT twice (initial + resend); 4 PUTs total.
        assert gw.put_count == 4
        # Two complete attempts (the first 409'd).
        completes = [p for (m, p) in gw.calls if m == "POST" and p.endswith("/complete")]
        assert len(completes) == 2

    asyncio.run(run())


def test_progress_is_monotonic_across_a_409_resend() -> None:
    async def run() -> None:
        # The first /complete 409s (server dropped chunk 1), so the driver resends
        # the gap and retries. Progress must NEVER regress: a single accumulating
        # byte count spans the initial upload AND the resend. The resent chunk
        # adds to the running total rather than restarting it at one chunk.
        gw = StubGateway(chunk_bytes=16)
        gw.drop_on_first_complete = {1}
        data = bytes((i * 5) & 0xFF for i in range(40))  # 3 chunks (16, 16, 8)
        progress: list[UploadProgress] = []
        async with _client(gw) as client:
            result = await client.poe.upload_resumable(
                source=data,
                threshold=8,
                parallelism=1,  # deterministic order for the byte-count assertion
                on_progress=progress.append,
            )
        assert result["uri"] == "ar://assembled"
        sent = [p["bytes_sent"] for p in progress]
        # 4 chunk PUTs total → 4 progress callbacks (3 initial + 1 resend of chunk 1).
        assert len(sent) == 4
        # Strictly non-decreasing: the resend continued forward, never dropping
        # back to a single-chunk count.
        assert sent == sorted(sent), sent
        # Initial pass reaches the full 40 bytes; the resend keeps climbing past it.
        assert sent[2] == 40
        assert sent[-1] == 40 + 16  # the resent 16-byte chunk 1 adds on top
        assert all(p["total_bytes"] == 40 and p["chunks_total"] == 3 for p in progress)

    asyncio.run(run())


# ---------------------------------------------------------------------------
# Abandon (DELETE) — explicit + idempotent 404/410.
# ---------------------------------------------------------------------------


def test_abandon_upload_session_issues_delete() -> None:
    async def run() -> None:
        captured: dict[str, Any] = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured["method"] = request.method
            captured["path"] = request.url.path
            return httpx.Response(204)

        async with _client(handler) as client:
            await client.poe.abandon_upload_session("33333333-3333-3333-3333-333333333333")
        assert captured["method"] == "DELETE"
        assert captured["path"].endswith("/sessions/33333333-3333-3333-3333-333333333333")

    asyncio.run(run())


@pytest.mark.parametrize("status", [404, 410])
def test_abandon_is_idempotent_on_already_gone(status: int) -> None:
    async def run() -> None:
        def handler(_request: httpx.Request) -> httpx.Response:
            return httpx.Response(status, json={"code": "not-found", "title": "gone"})

        async with _client(handler) as client:
            # No exception: an already-reclaimed session is success.
            await client.poe.abandon_upload_session("44444444-4444-4444-4444-444444444444")

    asyncio.run(run())


# ---------------------------------------------------------------------------
# Cancel → abandon the session, raise UploadCancelledError.
# ---------------------------------------------------------------------------


def test_cooperative_cancel_abandons_session_and_raises() -> None:
    async def run() -> None:
        gw = StubGateway(chunk_bytes=16)
        data = b"z" * 40

        # Cancel only AFTER the session exists (so an abandon DELETE is issued):
        # return False until the session-created callback fires.
        state = {"session_created": False}

        def cancel() -> bool:
            return state["session_created"]

        async with _client(gw) as client:
            with pytest.raises(UploadCancelledError):
                await client.poe.upload_resumable(
                    source=data,
                    threshold=8,
                    cancel=cancel,
                    on_session_created=lambda _sid: state.__setitem__("session_created", True),
                )
        # The session was abandoned (DELETE issued) on cancel.
        assert gw.abandoned is True

    asyncio.run(run())


def test_cancel_before_session_raises_without_delete() -> None:
    async def run() -> None:
        gw = StubGateway(chunk_bytes=16)
        async with _client(gw) as client:
            with pytest.raises(UploadCancelledError):
                await client.poe.upload_resumable(
                    source=b"z" * 40, threshold=8, cancel=lambda: True
                )
        # Cancelled before any session existed → nothing to abandon.
        assert gw.abandoned is False
        assert gw.put_count == 0

    asyncio.run(run())


def test_task_cancellation_surfaces_session_id_when_abandon_fails() -> None:
    async def run() -> None:
        # A real task cancellation (asyncio.CancelledError) lands while a chunk PUT
        # is in flight (the session already exists), and the abandon DELETE itself
        # fails (500). The leak must NOT be swallowed: the driver surfaces an
        # UploadCancelledError carrying the session id so the caller can retry the
        # abandon or resume. Cancellation semantics are still honoured (code ==
        # "CANCELLED", chained from the CancelledError).
        session_id = "11111111-1111-1111-1111-111111111111"
        put_in_flight = asyncio.Event()

        async def handler(request: httpx.Request) -> httpx.Response:
            method = request.method
            path = request.url.path
            sessions = "/api/v1/poe/uploads/sessions"
            if method == "POST" and path == sessions:
                return httpx.Response(
                    201,
                    json={
                        "session_id": session_id,
                        "chunk_bytes": 16,
                        "chunk_count": 3,
                        "received": [],
                        "expires_at": "2026-06-16T00:00:00Z",
                        "max_chunk_bytes": 16,
                    },
                )
            if method == "PUT" and path.startswith(f"{sessions}/{session_id}/chunks/"):
                # Signal that a chunk PUT is in flight, then hang forever so the
                # task cancellation lands inside this real await — no monkeypatch.
                put_in_flight.set()
                await asyncio.Event().wait()  # never set: the test cancels instead
                raise AssertionError("unreachable")
            if method == "DELETE" and path == f"{sessions}/{session_id}":
                # Abandon fails non-idempotently — the session leaked.
                return httpx.Response(500, json={"code": "internal-error", "title": "boom"})
            raise AssertionError(f"unexpected request {method} {path}")

        transport = httpx.MockTransport(handler)
        client = Label309Client(
            api_key=API_KEY, base_url=BASE, http_client=httpx.AsyncClient(transport=transport)
        )
        async with client:
            task = asyncio.ensure_future(client.poe.upload_resumable(source=b"z" * 40, threshold=8))
            await asyncio.wait_for(put_in_flight.wait(), timeout=2.0)
            task.cancel()
            with pytest.raises(UploadCancelledError) as exc:
                await task

        # The abandon failed, so the leak is surfaced WITH the session id.
        assert exc.value.code == "CANCELLED"
        assert exc.value.session_id == session_id
        # The underlying CancelledError is chained, preserving cancellation context.
        assert isinstance(exc.value.__cause__, asyncio.CancelledError)

    asyncio.run(run())


# ---------------------------------------------------------------------------
# Source adapters: bytes, path, file-like all upload identically.
# ---------------------------------------------------------------------------


def test_path_source_uploads_same_as_bytes(tmp_path: Any) -> None:
    async def run() -> None:
        data = bytes((i * 7) & 0xFF for i in range(40))
        file_path = tmp_path / "blob.bin"
        file_path.write_bytes(data)

        gw = StubGateway(chunk_bytes=16)
        async with _client(gw) as client:
            result = await client.poe.upload_resumable(source=str(file_path), threshold=8)
        assert result["uri"] == "ar://assembled"
        # The declared whole-file digest the gateway received matches the file.
        assert gw.declared_sha256 == hashlib.sha256(data).hexdigest()
        assert gw.received == {0, 1, 2}

    asyncio.run(run())


def test_threshold_constant_is_48_mib() -> None:
    assert RESUMABLE_THRESHOLD_BYTES == 50_331_648


def test_attempt_released_surfaces_attempt_failed() -> None:
    async def run() -> None:
        gw = StubGateway(chunk_bytes=16, complete_mode="accepted")

        # Override the attempt endpoint to report a release.
        original = gw._attempt

        def released() -> httpx.Response:
            return httpx.Response(
                200,
                json={
                    "attempt_id": gw.attempt_id,
                    "state": "released",
                    "sha256": gw.declared_sha256,
                    "bytes": gw.total_bytes,
                    "backend": "arweave",
                    "reason": "provider_rejected",
                },
            )

        gw._attempt = released  # type: ignore[method-assign]
        _ = original
        data = b"q" * 20
        async with _client(gw) as client:
            with pytest.raises(ResumableUploadError) as exc:
                await client.poe.upload_resumable(source=data, threshold=8)
        assert exc.value.code == "ATTEMPT_FAILED"

    asyncio.run(run())
