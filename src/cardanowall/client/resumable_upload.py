"""Threshold-gated resumable upload driver.

A file at or below ``threshold`` is sent with the single-shot multipart
``uploads()`` call, unchanged. A larger file is uploaded as a content-addressed
session: the helper hashes the whole file once (streaming, so a multi-GB file is
never buffered), creates a session, PUTs each fixed-size chunk (several in
parallel, retrying a failed chunk), then completes — polling the shared attempt
endpoint if completion is accepted asynchronously. Both paths converge on one
``ar://`` URI.

The chunk size is the server's call: the create response returns the
authoritative ``chunk_bytes`` and a ``max_chunk_bytes`` ceiling, and the helper
recomputes its grid from those rather than from what it requested. So a
deployment behind a stricter proxy cap is honoured without an SDK release.

Cancellation is twofold: a cooperative ``cancel`` callable (checked at every
phase) AND ``asyncio.CancelledError`` (a cancelled task). Either, once a session
exists, triggers a best-effort ``abandon`` (DELETE the session) before the error
propagates, so the gateway can reclaim the half-uploaded session promptly. An
``on_session_created`` callback fires the instant a session is created so a
caller can persist the ``session_id`` for crash-resume before any chunk PUT.

Parity twin: ``resumable-upload.ts`` in ``@cardanowall/sdk-ts``.
"""

from __future__ import annotations

import asyncio
import base64
import json
import urllib.parse
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass
from typing import Any, cast

import httpx

from cardanowall._crypto.hash import sha256

from .http_error import Label309HttpError
from .parse_http_error import parse_http_error
from .resumable_source import ResumableSource, ResumableSourceInput, to_resumable_source
from .types import (
    StorageTarget,
    UploadAttemptStatus,
    UploadProgress,
    UploadResumableResult,
    UploadSessionChunkResponse,
    UploadSessionCompleteResponse,
    UploadSessionCreateResponse,
    UploadSessionDeduplicatedResponse,
    UploadSessionStatus,
)

# ~48 MiB. Sits comfortably under a 100 MB CDN body cap AND under stricter
# nginx/proxy defaults below it, so a single chunk PUT clears the smallest common
# single-request ceiling. Both the switch-to-chunked threshold and the requested
# chunk size default here; the server's ``max_chunk_bytes`` always wins.
RESUMABLE_THRESHOLD_BYTES = 50_331_648
RESUMABLE_CHUNK_BYTES = 50_331_648
_DEFAULT_PARALLELISM = 4
_DEFAULT_MAX_CHUNK_RETRIES = 4
_DEFAULT_CONTENT_TYPE = "application/octet-stream"
_DEFAULT_TARGET: StorageTarget = "arweave"
_ATTEMPT_POLL_INTERVAL_SECONDS = 1.0
_ATTEMPT_POLL_MAX_ATTEMPTS = 600
_COMPLETE_RETRIES = 2

_SESSIONS_PATH = "/poe/uploads/sessions"


def _seg(value: str) -> str:
    """Percent-encode an opaque id for safe interpolation as a single URL path segment.

    Session and attempt ids are opaque to the SDK; ``safe=""`` encodes every
    reserved character (including ``/``) so a value can never break out of its
    path segment, matching the TypeScript twin's ``encodeURIComponent``.
    """
    return urllib.parse.quote(value, safe="")


# Progress / session-created callbacks. Synchronous; the driver does not await
# them so a slow callback cannot stall an upload.
OnProgress = Callable[[UploadProgress], None]
OnSessionCreated = Callable[[str], None]
Cancel = Callable[[], bool]
# Internal per-chunk progress reporter: (chunk_index, chunk_byte_length). The
# accumulator lives in the caller so a single byte count spans the initial upload
# and any 409 resend.
ReportChunk = Callable[[int, int], None]


class ResumableUploadError(Exception):
    """A resumable upload failed.

    ``code`` discriminates the failure: ``SHA256_MISMATCH``, ``SESSION_FAILED``,
    ``ATTEMPT_FAILED``, ``ATTEMPT_POLL_TIMEOUT``, ``CHUNK_UPLOAD_FAILED``, or
    ``CANCELLED`` (cooperative ``cancel`` returned True). A ``CANCELLED`` /
    abandon-failure error carries ``session_id`` when a session existed, so the
    caller can retry the abandon.
    """

    def __init__(self, code: str, message: str, *, session_id: str | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.session_id = session_id


class UploadCancelledError(ResumableUploadError):
    """The upload was cancelled (cooperative ``cancel`` or ``asyncio.CancelledError``)."""

    def __init__(self, message: str, *, session_id: str | None = None) -> None:
        super().__init__("CANCELLED", message, session_id=session_id)


@dataclass(frozen=True)
class _ResolvedConfig:
    api_key: str | None
    base_url: str
    http_client: httpx.AsyncClient


# Single-shot uploads() of one blob, returning the resolved entry. Injected as a
# callback so the driver does not depend on the PoeNamespace class shape.
SingleShotUpload = Callable[..., Awaitable[dict[str, Any]]]


def _json_headers(config: _ResolvedConfig, idempotency_key: str | None = None) -> dict[str, str]:
    headers = {"content-type": "application/json", "accept": "application/json"}
    if config.api_key is not None:
        headers["authorization"] = f"Bearer {config.api_key}"
    if idempotency_key is not None:
        headers["idempotency-key"] = idempotency_key
    return headers


def _octet_headers(config: _ResolvedConfig, length: int, digest_b64: str) -> dict[str, str]:
    headers = {
        "content-type": "application/octet-stream",
        "accept": "application/json",
        "content-length": str(length),
        "digest": f"sha-256={digest_b64}",
    }
    if config.api_key is not None:
        headers["authorization"] = f"Bearer {config.api_key}"
    return headers


def _raise_for_status(response: httpx.Response) -> None:
    if response.is_success:
        return
    try:
        body = response.json()
    except (json.JSONDecodeError, ValueError):
        body = None
    request_id = response.headers.get("x-request-id")
    retry_after = response.headers.get("retry-after")
    retry_after_seconds: int | None
    try:
        retry_after_seconds = int(retry_after) if retry_after is not None else None
    except ValueError:
        retry_after_seconds = None
    raise parse_http_error(
        http_status=response.status_code,
        body=body,
        request_id=request_id,
        retry_after_seconds=retry_after_seconds,
    )


def _chunk_range(index: int, chunk_bytes: int, total_bytes: int) -> tuple[int, int]:
    start = index * chunk_bytes
    return start, min(start + chunk_bytes, total_bytes)


def _missing_indices(received: Sequence[int], chunk_count: int) -> list[int]:
    have = set(received)
    return [i for i in range(chunk_count) if i not in have]


def _server_missing(status: UploadSessionStatus) -> list[int]:
    """The authoritative chunk indices to send for a resumed session.

    The server's ``missing`` set is the source of truth; ``received`` is only a
    progress signal. A gateway that omits ``missing`` (older deployments) falls
    back to the gap derived from ``received`` + ``chunk_count``.
    """
    missing = status.get("missing")
    if isinstance(missing, list):
        return list(missing)
    return _missing_indices(status.get("received", []), status.get("chunk_count", 0))


def _check_cancel(cancel: Cancel | None, session_id: str | None) -> None:
    if cancel is not None and cancel():
        raise UploadCancelledError("upload cancelled", session_id=session_id)


async def _interruptible_sleep(
    seconds: float, cancel: Cancel | None, session_id: str | None
) -> None:
    """Sleep in short slices so a cooperative cancel interrupts a backoff/poll wait."""
    _check_cancel(cancel, session_id)
    remaining = seconds
    step = 0.1
    while remaining > 0:
        await asyncio.sleep(min(step, remaining))
        remaining -= step
        _check_cancel(cancel, session_id)


async def create_session(
    config: _ResolvedConfig,
    body: dict[str, Any],
) -> UploadSessionCreateResponse | UploadSessionDeduplicatedResponse:
    response = await config.http_client.post(
        f"{config.base_url}{_SESSIONS_PATH}",
        content=json.dumps(body, separators=(",", ":")),
        headers=_json_headers(config),
    )
    # A 402 funding error is surfaced through the typed-error path like any other
    # non-2xx; the dedup short-circuit arrives as a 200 and is read below.
    _raise_for_status(response)
    return cast("UploadSessionCreateResponse | UploadSessionDeduplicatedResponse", response.json())


async def get_session_status(config: _ResolvedConfig, session_id: str) -> UploadSessionStatus:
    response = await config.http_client.get(
        f"{config.base_url}{_SESSIONS_PATH}/{_seg(session_id)}",
        headers=_json_headers(config),
    )
    _raise_for_status(response)
    return cast("UploadSessionStatus", response.json())


async def put_chunk(
    config: _ResolvedConfig,
    session_id: str,
    index: int,
    data: bytes,
) -> UploadSessionChunkResponse:
    # The per-chunk Digest header is RFC 4648 base64 over the chunk's SHA-256. A
    # matching-digest re-PUT is an idempotent 200 server-side, so a retried chunk
    # is always safe.
    digest = base64.b64encode(sha256(data)).decode("ascii")
    response = await config.http_client.put(
        f"{config.base_url}{_SESSIONS_PATH}/{_seg(session_id)}/chunks/{index}",
        content=data,
        headers=_octet_headers(config, len(data), digest),
    )
    _raise_for_status(response)
    return cast("UploadSessionChunkResponse", response.json())


async def complete_session(
    config: _ResolvedConfig,
    session_id: str,
    idempotency_key: str,
) -> UploadSessionCompleteResponse:
    response = await config.http_client.post(
        f"{config.base_url}{_SESSIONS_PATH}/{_seg(session_id)}/complete",
        headers=_json_headers(config, idempotency_key),
    )
    _raise_for_status(response)
    return cast("UploadSessionCompleteResponse", response.json())


async def poll_attempt(
    config: _ResolvedConfig,
    attempt_id: str,
    cancel: Cancel | None,
    session_id: str | None,
) -> UploadAttemptStatus:
    for _ in range(_ATTEMPT_POLL_MAX_ATTEMPTS):
        _check_cancel(cancel, session_id)
        response = await config.http_client.get(
            f"{config.base_url}/poe/uploads/attempts/{_seg(attempt_id)}",
            headers=_json_headers(config),
        )
        _raise_for_status(response)
        status = cast("UploadAttemptStatus", response.json())
        # ``reserved`` is the only in-flight state; ``committed`` and ``released``
        # are terminal and returned to the caller to resolve.
        if status["state"] != "reserved":
            return status
        await _interruptible_sleep(_ATTEMPT_POLL_INTERVAL_SECONDS, cancel, session_id)
    raise ResumableUploadError(
        "ATTEMPT_POLL_TIMEOUT",
        f"upload attempt {attempt_id} did not reach a terminal state in time",
        session_id=session_id,
    )


async def abandon_session(config: _ResolvedConfig, session_id: str) -> None:
    """Discard an in-progress upload session: ``DELETE /poe/uploads/sessions/{sid}``.

    Idempotent — a 404/410 (already gone) is treated as success, so a
    double-abandon is safe. Any other non-2xx raises a typed error.
    """
    response = await config.http_client.delete(
        f"{config.base_url}{_SESSIONS_PATH}/{_seg(session_id)}",
        headers=_json_headers(config),
    )
    if response.status_code in (404, 410):
        return
    _raise_for_status(response)


async def _abandon_quietly(config: _ResolvedConfig, session_id: str | None) -> bool:
    """Best-effort abandon used on the cancel/error path. Returns True on success."""
    if session_id is None:
        return True
    try:
        await abandon_session(config, session_id)
        return True
    except (Label309HttpError, httpx.HTTPError):
        return False


def _is_terminal_chunk_error(err: BaseException) -> bool:
    """Whether a chunk-PUT error is the caller's fault (terminal) vs a transient hiccup.

    A definitive client-side 4xx — a conflicting digest, a size mismatch, an
    unauthorised/forbidden caller, an expired or missing session — is terminal:
    resending the same bytes cannot fix it. 408 (request timeout) and 429 (rate
    limited) are transient; any non-HTTP error (a network failure) is transient
    too, since the request never reached a definitive verdict.
    """
    if not isinstance(err, Label309HttpError):
        return False
    status = err.http_status
    return 400 <= status < 500 and status not in (408, 429)


def _is_incomplete_upload(err: BaseException) -> bool:
    # The typed HTTP error carries the RFC 7807 ``code``; an incomplete upload at
    # /complete is a 409 with code ``incomplete-upload``.
    return isinstance(err, Label309HttpError) and err.code == "incomplete-upload"


async def _put_chunk_with_retry(
    config: _ResolvedConfig,
    session_id: str,
    index: int,
    data: bytes,
    max_retries: int,
    cancel: Cancel | None,
) -> None:
    last_error: BaseException | None = None
    for attempt in range(max_retries + 1):
        _check_cancel(cancel, session_id)
        try:
            await put_chunk(config, session_id, index, data)
            return
        except UploadCancelledError:
            raise
        except (Label309HttpError, httpx.HTTPError) as err:
            _check_cancel(cancel, session_id)
            # A deterministic client-side 4xx cannot be fixed by resending the
            # same bytes: fail fast and surface the real problem rather than
            # masking it as CHUNK_UPLOAD_FAILED. Only transient failures are
            # worth a retry.
            if _is_terminal_chunk_error(err):
                raise
            last_error = err
            if attempt < max_retries:
                # Exponential backoff (250ms, 500ms, 1s, ...) capped at 8s.
                await _interruptible_sleep(min(0.25 * (2**attempt), 8.0), cancel, session_id)
    raise ResumableUploadError(
        "CHUNK_UPLOAD_FAILED",
        f"chunk {index} failed after {max_retries + 1} attempt(s): {last_error}",
        session_id=session_id,
    )


async def _upload_chunks(
    config: _ResolvedConfig,
    session_id: str,
    source: ResumableSource,
    chunk_bytes: int,
    total_bytes: int,
    missing: Sequence[int],
    parallelism: int,
    max_retries: int,
    cancel: Cancel | None,
    report_chunk: ReportChunk | None,
) -> None:
    """Upload ``missing`` chunk indices with bounded parallelism, retrying each.

    ``report_chunk`` is invoked once per chunk, AFTER the gateway durably accepts
    it, with the chunk's index and byte length. Chunks complete out of order under
    parallelism, and this helper may be called more than once for a single session
    (the initial upload plus a 409 resend), so it does NOT own the cumulative byte
    count — the caller accumulates the reported lengths into one monotonically
    growing total that spans every call.
    """
    cursor = 0
    lock = asyncio.Lock()
    lanes = max(1, min(parallelism, len(missing) or 1))

    async def worker() -> None:
        nonlocal cursor
        while True:
            _check_cancel(cancel, session_id)
            async with lock:
                if cursor >= len(missing):
                    return
                index = missing[cursor]
                cursor += 1
            start, end = _chunk_range(index, chunk_bytes, total_bytes)
            data = await source.slice(start, end)
            await _put_chunk_with_retry(config, session_id, index, data, max_retries, cancel)
            # Progress after each successful chunk PUT, reporting only this chunk's
            # contribution; the caller accumulates.
            if report_chunk is not None:
                report_chunk(index, len(data))

    await asyncio.gather(*(worker() for _ in range(lanes)))


async def upload_resumable(
    config: _ResolvedConfig,
    single_shot: SingleShotUpload,
    *,
    source: ResumableSourceInput,
    target: StorageTarget | None = None,
    threshold: int | None = None,
    chunk_bytes: int | None = None,
    parallelism: int | None = None,
    max_chunk_retries: int | None = None,
    idempotency_key: str | None = None,
    content_type: str | None = None,
    session_id: str | None = None,
    cancel: Cancel | None = None,
    on_progress: OnProgress | None = None,
    on_session_created: OnSessionCreated | None = None,
) -> UploadResumableResult:
    """Drive a single-file upload, choosing single-shot vs the chunked session flow by size."""
    resolved_source = to_resumable_source(source)
    resolved_target = target if target is not None else _DEFAULT_TARGET
    resolved_threshold = threshold if threshold is not None else RESUMABLE_THRESHOLD_BYTES
    total_bytes = resolved_source.size

    _check_cancel(cancel, None)

    # Small file (or no resume requested): the single-shot path. The whole file
    # is small enough to read once into memory for the multipart body.
    if total_bytes <= resolved_threshold and session_id is None:
        data = await resolved_source.slice(0, total_bytes)
        kwargs: dict[str, Any] = {"target": resolved_target, "data": data}
        if idempotency_key is not None:
            kwargs["idempotency_key"] = idempotency_key
        result = await single_shot(**kwargs)
        if on_progress is not None:
            on_progress(
                {
                    "bytes_sent": total_bytes,
                    "total_bytes": total_bytes,
                    "chunk_index": 0,
                    "chunks_total": 1,
                }
            )
        return {
            "uri": result["uri"],
            "sha256": result["sha256"],
            "bytes": result["bytes"],
            "deduplicated": False,
            "mode": "single-shot",
        }

    return await _run_session(
        config,
        resolved_source,
        resolved_target,
        total_bytes,
        chunk_bytes=chunk_bytes,
        parallelism=parallelism,
        max_chunk_retries=max_chunk_retries,
        idempotency_key=idempotency_key,
        content_type=content_type,
        resume_session_id=session_id,
        source_input=source,
        cancel=cancel,
        on_progress=on_progress,
        on_session_created=on_session_created,
    )


async def _run_session(
    config: _ResolvedConfig,
    source: ResumableSource,
    target: StorageTarget,
    total_bytes: int,
    *,
    chunk_bytes: int | None,
    parallelism: int | None,
    max_chunk_retries: int | None,
    idempotency_key: str | None,
    content_type: str | None,
    resume_session_id: str | None,
    source_input: ResumableSourceInput,
    cancel: Cancel | None,
    on_progress: OnProgress | None,
    on_session_created: OnSessionCreated | None,
) -> UploadResumableResult:
    active_session_id: str | None = None
    try:
        if resume_session_id is not None:
            # Resume: a session is content-addressed, so its declared digest,
            # total, and chunk grid all live server-side. Adopt the server status
            # as authoritative and NEVER re-hash the local source.
            status = await get_session_status(config, resume_session_id)
            state = status.get("state")
            uri = status.get("uri")
            if state == "completed" and uri is not None:
                return {
                    "uri": uri,
                    "sha256": status.get("sha256", ""),
                    "bytes": status.get("total_bytes", 0),
                    "deduplicated": False,
                    "mode": "chunked",
                }
            if state in ("failed", "expired"):
                raise ResumableUploadError(
                    "SESSION_FAILED",
                    f"cannot resume session {resume_session_id} in state '{state}'",
                    session_id=resume_session_id,
                )
            active_session_id = status["session_id"]
            declared_sha256 = status.get("sha256", "")
            session_chunk_bytes = status["chunk_bytes"]
            # The server's declared total is authoritative for the chunk grid,
            # not the live local source size: a source that grew between attempts
            # must not redraw the grid, or the final chunk would over-read past
            # the originally declared length and contradict the digest.
            grid_total_bytes = status["total_bytes"]
            chunk_count = status["chunk_count"]
            missing = _server_missing(status)
        else:
            # Fresh create: the only path that reads the whole source to compute
            # the declared digest, streamed so a multi-GB file is never buffered.
            declared_sha256 = await _hash_whole_file(source, cancel)
            requested_chunk_bytes = (
                chunk_bytes if chunk_bytes is not None else RESUMABLE_CHUNK_BYTES
            )
            _check_cancel(cancel, None)
            created = await create_session(
                config,
                {
                    "target": target,
                    "sha256": declared_sha256,
                    "total_bytes": total_bytes,
                    "chunk_bytes": requested_chunk_bytes,
                    "content_type": content_type
                    if content_type is not None
                    else _DEFAULT_CONTENT_TYPE,
                },
            )
            # Create-time dedup: the bytes already exist; nothing is uploaded.
            if created.get("deduplicated") is True:
                dedup = cast("UploadSessionDeduplicatedResponse", created)
                return {
                    "uri": dedup["uri"],
                    "sha256": dedup["sha256"],
                    "bytes": dedup["bytes"],
                    "deduplicated": True,
                    "mode": "chunked",
                }
            fresh = cast("UploadSessionCreateResponse", created)
            active_session_id = fresh["session_id"]
            # Surface the session id the instant it exists, before any chunk PUT,
            # so a caller can persist it for crash-resume.
            if on_session_created is not None:
                on_session_created(active_session_id)
            # Honour the server's authoritative chunk size (it may clamp).
            session_chunk_bytes = fresh["chunk_bytes"]
            grid_total_bytes = total_bytes
            chunk_count = fresh["chunk_count"]
            # A fresh create has no ``missing`` field and an empty ``received``,
            # so every index is outstanding.
            missing = _missing_indices(fresh.get("received", []), chunk_count)

        # Cumulative progress for this invocation. Chunks complete out of order
        # under parallelism, so ``bytes_sent`` accumulates the reported chunk
        # lengths; the index reported is the chunk that just landed. The reporter
        # is shared across the initial upload and any 409 resend in
        # ``_finish_session``, so a single monotonically-growing byte count spans
        # both — a resend must never regress progress back to one chunk.
        bytes_sent = 0

        def report_chunk(index: int, byte_length: int) -> None:
            nonlocal bytes_sent
            bytes_sent += byte_length
            if on_progress is not None:
                on_progress(
                    {
                        "bytes_sent": bytes_sent,
                        "total_bytes": grid_total_bytes,
                        "chunk_index": index,
                        "chunks_total": chunk_count,
                    }
                )

        if missing:
            await _upload_chunks(
                config,
                active_session_id,
                source,
                session_chunk_bytes,
                grid_total_bytes,
                missing,
                parallelism if parallelism is not None else _DEFAULT_PARALLELISM,
                max_chunk_retries if max_chunk_retries is not None else _DEFAULT_MAX_CHUNK_RETRIES,
                cancel,
                report_chunk,
            )

        return await _finish_session(
            config,
            active_session_id,
            declared_sha256,
            source_input=source_input,
            parallelism=parallelism,
            max_chunk_retries=max_chunk_retries,
            idempotency_key=idempotency_key,
            cancel=cancel,
            report_chunk=report_chunk,
        )
    except UploadCancelledError as err:
        # Cooperative cancel: abandon the session (if one exists) so the gateway
        # can reclaim it, then re-raise carrying the session id.
        abandoned = await _abandon_quietly(config, active_session_id)
        raise UploadCancelledError(
            "upload cancelled"
            if abandoned
            else f"upload cancelled; abandon of session {active_session_id} failed",
            session_id=None if abandoned else active_session_id,
        ) from err
    except asyncio.CancelledError as err:
        # A cancelled task: abandon once a session exists, then propagate the
        # cancellation (never swallow it). A real abandon failure must NOT be
        # swallowed — if the DELETE fails, the session leaked, so surface that to
        # the caller carrying the session id (mirroring the cooperative-cancel and
        # abort paths) instead of letting it vanish. Cancellation semantics are
        # preserved: a clean abandon re-raises the CancelledError untouched, and
        # the abandon-failure path raises ``UploadCancelledError`` (still a
        # cancellation, ``code == "CANCELLED"``) chained from the CancelledError.
        abandoned = await _abandon_quietly(config, active_session_id)
        if not abandoned:
            raise UploadCancelledError(
                f"upload cancelled; abandon of session {active_session_id} failed",
                session_id=active_session_id,
            ) from err
        raise


# Drive /complete to a terminal result. On a 409 incomplete-upload, the server's
# status is re-fetched and the still-missing chunks are resent against the
# server-authoritative grid, so the completion path never trusts a stale local size.
async def _finish_session(
    config: _ResolvedConfig,
    session_id: str,
    declared_sha256: str,
    *,
    source_input: ResumableSourceInput,
    parallelism: int | None,
    max_chunk_retries: int | None,
    idempotency_key: str | None,
    cancel: Cancel | None,
    report_chunk: ReportChunk | None,
) -> UploadResumableResult:
    # The completion key is the caller's promise of sameness; default it to the
    # session's declared digest so a re-invocation replays the recorded terminal
    # result rather than racing a second completion.
    key = idempotency_key if idempotency_key is not None else f"resumable-{declared_sha256}"

    for attempt in range(_COMPLETE_RETRIES + 1):
        _check_cancel(cancel, session_id)
        try:
            completion = await complete_session(config, session_id, key)
            if "ok" in completion:
                ok = cast("dict[str, Any]", completion)
                return {
                    "uri": ok["uri"],
                    "sha256": ok["sha256"],
                    "bytes": ok["bytes"],
                    # 0 for a dedup-on-commit (bytes already stored, nothing
                    # charged); compare numerically.
                    "deduplicated": ok.get("charged_usd_micros") == 0,
                    "mode": "chunked",
                }
            accepted = cast("dict[str, Any]", completion)
            return await _resolve_accepted(config, accepted["attempt_id"], cancel, session_id)
        except UploadCancelledError:
            raise
        except (Label309HttpError, httpx.HTTPError) as err:
            if attempt < _COMPLETE_RETRIES and _is_incomplete_upload(err):
                status = await get_session_status(config, session_id)
                still_missing = _server_missing(status)
                if not still_missing:
                    continue  # racing assembly; retry complete
                await _upload_chunks(
                    config,
                    session_id,
                    to_resumable_source(source_input),
                    status["chunk_bytes"],
                    # Re-bound the resend grid against the server's declared total
                    # too, so a source that grew during the upload cannot
                    # over-read the final chunk.
                    status["total_bytes"],
                    still_missing,
                    parallelism if parallelism is not None else _DEFAULT_PARALLELISM,
                    max_chunk_retries
                    if max_chunk_retries is not None
                    else _DEFAULT_MAX_CHUNK_RETRIES,
                    cancel,
                    # The SAME accumulating reporter as the initial upload, so a
                    # 409 resend continues the byte count forward rather than
                    # restarting it at one chunk.
                    report_chunk,
                )
                continue
            raise
    # Loop exhaustion means the gateway kept reporting an incomplete upload
    # despite resending the missing chunks.
    raise ResumableUploadError(
        "SESSION_FAILED",
        f"session {session_id} could not be completed after resending missing chunks",
        session_id=session_id,
    )


async def _resolve_accepted(
    config: _ResolvedConfig,
    attempt_id: str,
    cancel: Cancel | None,
    session_id: str | None,
) -> UploadResumableResult:
    status = await poll_attempt(config, attempt_id, cancel, session_id)
    # ``released`` is the terminal failure; surface the server's reason.
    if status["state"] == "released":
        raise ResumableUploadError(
            "ATTEMPT_FAILED",
            f"upload attempt {attempt_id} was released: {status.get('reason', 'unknown')}",
            session_id=session_id,
        )
    # ``committed`` is the terminal success and MUST carry a uri; a committed
    # attempt without one is a server contract violation, not a silent success.
    committed = cast("dict[str, Any]", status)
    if not committed.get("uri"):
        raise ResumableUploadError(
            "ATTEMPT_FAILED",
            f"upload attempt {attempt_id} committed without a uri",
            session_id=session_id,
        )
    return {
        "uri": committed["uri"],
        "sha256": committed["sha256"],
        "bytes": committed["bytes"],
        # A committed attempt that charged nothing deduped against bytes already
        # stored for this account on this backend.
        "deduplicated": committed.get("charged_usd_micros") == 0,
        "mode": "chunked",
    }


async def _hash_whole_file(source: ResumableSource, cancel: Cancel | None) -> str:
    """Whole-file SHA-256 (lowercase hex), streamed so a large file is never buffered."""
    import hashlib

    digest = hashlib.sha256()
    async for chunk in source.stream():
        _check_cancel(cancel, None)
        digest.update(chunk)
    return digest.hexdigest()


__all__ = [
    "RESUMABLE_CHUNK_BYTES",
    "RESUMABLE_THRESHOLD_BYTES",
    "Cancel",
    "OnProgress",
    "OnSessionCreated",
    "ResumableUploadError",
    "UploadCancelledError",
    "abandon_session",
    "upload_resumable",
]
