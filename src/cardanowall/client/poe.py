"""Wraps the mutating ``/poe/*`` REST surface (suffixes appended to the
configured versioned ``base_url``):

- POST ``/poe/quote`` — lock a USD price for an upcoming publish
- POST ``/poe/uploads`` — multipart binary upload to a backend
- POST ``/poe/publish`` — single finalised record (JSON)
- POST ``/poe/publish-batch`` — 1..50 finalised records (JSON)

Plus high-level helpers that compose the above into common flows:

- :py:meth:`PoeNamespace.publish_content` — hash-only
- :py:meth:`PoeNamespace.publish_prehashed` — caller already holds digest
- :py:meth:`PoeNamespace.publish_merkle` — internal quote + uploads +
  publish, Merkle root
- the two-phase sealed flow — :func:`cardanowall.client.sealed.seal_prepare`
  (pure, offline) feeding :py:meth:`PoeNamespace.quote_prepared_seal` /
  :py:meth:`PoeNamespace.submit_sealed`, with
  :py:meth:`PoeNamespace.publish_sealed` as the one-shot wrapper

Reads live under :class:`cardanowall.client.records.RecordsNamespace`;
verification runs locally via :mod:`cardanowall.verifier`.

All methods are coroutines (async). Use ``asyncio.run(...)`` for sync use.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any, Literal, cast

import httpx

from .parse_http_error import parse_http_error
from .partial_upload_error import PartialUploadError
from .poe_events import (
    _ResolvedConfig as _PoeEventsResolvedConfig,
)
from .poe_events import (
    wait_for_poe as _wait_for_poe_impl,
)
from .publish import (
    PublishMerkleResponse,
    Signer,
    SupportedHashAlg,
    SupportedKem,
    _ResolvedPublishConfig,
)
from .publish import (
    publish_content as _publish_content_impl,
)
from .publish import (
    publish_merkle as _publish_merkle_impl,
)
from .publish import (
    publish_prehashed as _publish_prehashed_impl,
)
from .resumable_source import ResumableSourceInput
from .resumable_upload import (
    Cancel,
    OnProgress,
    OnSessionCreated,
)
from .resumable_upload import (
    _ResolvedConfig as _ResumableResolvedConfig,
)
from .resumable_upload import (
    abandon_session as _abandon_session_impl,
)
from .resumable_upload import (
    upload_resumable as _upload_resumable_impl,
)
from .sealed import (
    PreparedSeal,
    SealedSubmission,
    UploadReceipt,
)
from .sealed import (
    publish_sealed as _publish_sealed_impl,
)
from .sealed import (
    quote_prepared_seal as _quote_prepared_seal_impl,
)
from .sealed import (
    submit_sealed as _submit_sealed_impl,
)
from .types import (
    PoeStatusSnapshot,
    PublishBatchResponse,
    PublishResponse,
    QuoteResponse,
    RecordSignature,
    StorageTarget,
    UploadResumableResult,
    UploadsResponse,
)


@dataclass(frozen=True)
class _ResolvedConfig:
    api_key: str | None
    base_url: str
    http_client: httpx.AsyncClient


def _build_json_headers(api_key: str | None, idempotency_key: str | None = None) -> dict[str, str]:
    headers = {"content-type": "application/json", "accept": "application/json"}
    if api_key is not None:
        headers["authorization"] = f"Bearer {api_key}"
    if idempotency_key is not None:
        headers["idempotency-key"] = idempotency_key
    return headers


def _build_multipart_headers(
    api_key: str | None, idempotency_key: str | None = None
) -> dict[str, str]:
    headers = {"accept": "application/json"}
    if api_key is not None:
        headers["authorization"] = f"Bearer {api_key}"
    if idempotency_key is not None:
        headers["idempotency-key"] = idempotency_key
    return headers


def _parse_retry_after(header: str | None) -> int | None:
    if header is None:
        return None
    try:
        parsed = int(header)
    except ValueError:
        return None
    return parsed


def _raise_for_status(response: httpx.Response) -> None:
    if response.is_success:
        return
    try:
        body = response.json()
    except (json.JSONDecodeError, ValueError):
        body = None
    request_id = response.headers.get("x-request-id")
    retry_after_seconds = _parse_retry_after(response.headers.get("retry-after"))
    raise parse_http_error(
        http_status=response.status_code,
        body=body,
        request_id=request_id,
        retry_after_seconds=retry_after_seconds,
    )


def _to_hex(record: bytes | str) -> str:
    if isinstance(record, str):
        return record
    return bytes(record).hex()


class PoeNamespace:
    """Low-level mutating PoE surface plus high-level publish helpers.

    Async-canonical: every method is a coroutine. Wrap in ``asyncio.run(...)``
    for synchronous use.
    """

    def __init__(self, config: _ResolvedConfig) -> None:
        self._config = config

    async def quote(
        self,
        *,
        record_bytes: int,
        recipient_count: int,
        file_bytes_total: int,
    ) -> QuoteResponse:
        """Request an opaque price lock for an upcoming /publish call. The
        gateway prices the described publish from the supplied byte counts,
        records the lock, and returns a sealed price token: ``quote_id``, the
        total ``amount`` in ``currency``, and an ``expires_at``. The gateway's
        pricing internals are deliberately NOT part of the response.

        ``amount`` is a decimal string; promote it to ``int`` at the
        application boundary if you need exact arithmetic.

        Pass the returned ``quote_id`` to ``publish()`` or the high-level
        ``publish_content`` / ``publish_prehashed`` helpers. The internally
        quoting helpers (``publish_merkle``, ``submit_sealed``,
        ``publish_sealed``) take no quote id — they price their exact shape
        themselves.
        """
        body = {
            "record_bytes": record_bytes,
            "recipient_count": recipient_count,
            "file_bytes_total": file_bytes_total,
        }
        response = await self._config.http_client.post(
            f"{self._config.base_url}/poe/quote",
            content=json.dumps(body, separators=(",", ":")),
            headers=_build_json_headers(self._config.api_key),
        )
        _raise_for_status(response)
        return cast(QuoteResponse, response.json())

    async def uploads(
        self,
        *,
        target: StorageTarget,
        data: Sequence[bytes],
        idempotency_key: str | None = None,
    ) -> UploadsResponse:
        """Upload 1..32 binary files to a storage backend. Returns one entry
        per file — successful entries carry the ``ar://`` URI + content
        hash, failed entries carry an error code / detail so the caller can
        retry just the failed indices.

        Billing: free. The storage cost is part of the publish quote (POST
        /poe/quote → POST /poe/publish) and is debited once at publish time
        against the locked price snapshot.

        On HTTP-level failure (auth, rate limit, malformed request) this
        raises a typed :class:`Label309HttpError` subclass. Per-file
        failures inside a 200 response are NOT raised by ``uploads()``
        itself — the response body is returned verbatim. The higher-level
        helpers (``publish_sealed``, ``publish_merkle``) treat any failed
        file as a :class:`PartialUploadError`.
        """
        files: list[tuple[str, tuple[str, bytes, str]]] = []
        for idx, payload in enumerate(data):
            files.append(
                (
                    f"file_{idx}",
                    (f"file_{idx}.bin", payload, "application/octet-stream"),
                )
            )
        response = await self._config.http_client.post(
            f"{self._config.base_url}/poe/uploads",
            data={"target": target},
            files=files,
            headers=_build_multipart_headers(self._config.api_key, idempotency_key),
        )
        _raise_for_status(response)
        return cast(UploadsResponse, response.json())

    async def upload_resumable(
        self,
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
        """Upload one file, choosing the single-shot or chunked-session path by size.

        A file at or below ``threshold`` (~48 MiB by default) is sent with the
        single-shot ``uploads()`` path; a larger one is uploaded as a
        content-addressed resumable session (create → PUT chunks in parallel →
        complete), converging on one ``ar://`` URI. ``source`` may be ``bytes``,
        a filesystem path, an open binary file, or a ``ResumableSource``.

        Resume an interrupted upload by passing the ``session_id`` from a prior
        attempt: the helper adopts the server's status and re-sends only the
        missing chunks, WITHOUT re-hashing the local source.

        Cancellation: a cooperative ``cancel`` callable is checked at every phase,
        and a cancelled task (``asyncio.CancelledError``) is honoured too; either,
        once a session exists, abandons it before the error propagates.
        ``on_session_created(session_id)`` fires the instant the session is
        created (before any chunk PUT) so a caller can persist it for crash-resume;
        ``on_progress(UploadProgress)`` fires after each chunk PUT.

        On a per-file storage failure inside the single-shot path the response is
        surfaced as a :class:`PartialUploadError` (mirroring the high-level
        publish helpers); HTTP-level failures raise a typed
        :class:`Label309HttpError` subclass.
        """
        resumable_config = _ResumableResolvedConfig(
            api_key=self._config.api_key,
            base_url=self._config.base_url,
            http_client=self._config.http_client,
        )
        return await _upload_resumable_impl(
            resumable_config,
            self._single_shot_upload,
            source=source,
            target=target,
            threshold=threshold,
            chunk_bytes=chunk_bytes,
            parallelism=parallelism,
            max_chunk_retries=max_chunk_retries,
            idempotency_key=idempotency_key,
            content_type=content_type,
            session_id=session_id,
            cancel=cancel,
            on_progress=on_progress,
            on_session_created=on_session_created,
        )

    async def _single_shot_upload(
        self,
        *,
        target: StorageTarget,
        data: bytes,
        idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        """Single-shot ``uploads()`` of one blob, returning ``{uri, sha256, bytes}``.

        Injected into the resumable driver. A per-file failure is raised as a
        :class:`PartialUploadError` so the small-file path reports a storage
        failure the same way the high-level publish helpers do.
        """
        result = await self.uploads(target=target, data=[data], idempotency_key=idempotency_key)
        first = result["uploads"][0]
        if first["ok"] is False:
            raise PartialUploadError(result)
        return {
            "uri": first["uri"],
            "sha256": first["sha256"],
            "bytes": first["bytes"],
        }

    async def abandon_upload_session(self, session_id: str) -> None:
        """Discard an in-progress resumable upload session.

        ``DELETE /poe/uploads/sessions/{session_id}``. Idempotent — a session the
        gateway has already reclaimed (404/410) is treated as success — so a
        caller can safely abandon a session it is unsure still exists (e.g. after
        a crash, before re-trying).
        """
        resumable_config = _ResumableResolvedConfig(
            api_key=self._config.api_key,
            base_url=self._config.base_url,
            http_client=self._config.http_client,
        )
        await _abandon_session_impl(resumable_config, session_id)

    async def wait(
        self,
        poe_id: str,
        *,
        target: Literal["submitted", "confirmed"] = "confirmed",
        timeout: float | None = None,
    ) -> PoeStatusSnapshot:
        """Wait for a published record to reach a lifecycle target by
        streaming ``GET /poe/events/{poe_id}`` (server-sent events).

        ``poe_id`` is the ``poe_<crockford>`` id returned by ``publish()``.
        ``target="submitted"`` resolves once the transaction left the gateway
        for the chain (status ``confirming``, or ``confirmed`` directly);
        ``target="confirmed"`` resolves only on ``confirmed``. Either way the
        final normalised :class:`~cardanowall.client.types.PoeStatusSnapshot`
        is returned.

        The stream reconnects transparently on network drops (resuming from
        the last seen frame id, so no status change is lost) and waits out the
        gateway's concurrent-stream cap (429). A terminal publish failure
        raises :class:`~cardanowall.client.poe_failed_error.PoeFailedError`
        carrying the failure snapshot; a ``timeout`` (seconds) that elapses
        first raises
        :class:`~cardanowall.client.poe_wait_timeout_error.PoeWaitTimeoutError`
        carrying the last snapshot seen. With ``timeout=None`` the wait is
        unbounded — cancel the task to stop it.
        """
        events_config = _PoeEventsResolvedConfig(
            api_key=self._config.api_key,
            base_url=self._config.base_url,
            http_client=self._config.http_client,
        )
        return await _wait_for_poe_impl(
            events_config,
            poe_id,
            target=target,
            timeout=timeout,
        )

    async def publish(
        self,
        *,
        record: bytes | str,
        quote_id: str,
        signatures: Sequence[RecordSignature] | None = None,
        idempotency_key: str | None = None,
    ) -> PublishResponse:
        """Submit a single finalised canonical-CBOR record to Cardano.

        ``record`` is either raw bytes or a lowercase hex string; the SDK
        hex-encodes ``bytes`` for the wire.

        ``quote_id`` is the UUID returned by a prior ``quote()`` call. The
        server consumes it atomically with the poe_record insert; expired or
        already-consumed quotes raise ``QuoteExpiredError`` /
        ``QuoteAlreadyConsumedError``.

        Returns 202 (``dedup_hit=False``) on freshly enqueued records, or
        200 (``dedup_hit=True``) when the same record bytes were previously
        submitted by this account.
        """
        body: dict[str, Any] = {"record": _to_hex(record), "quote_id": quote_id}
        if signatures is not None:
            body["signatures"] = list(signatures)
        response = await self._config.http_client.post(
            f"{self._config.base_url}/poe/publish",
            content=json.dumps(body, separators=(",", ":")),
            headers=_build_json_headers(self._config.api_key, idempotency_key),
        )
        _raise_for_status(response)
        parsed: dict[str, Any] = response.json()
        parsed["dedup_hit"] = response.status_code == 200
        return cast(PublishResponse, parsed)

    async def publish_batch(
        self,
        *,
        records: Sequence[dict[str, Any]],
        idempotency_key: str | None = None,
    ) -> PublishBatchResponse:
        """Submit 1..50 finalised records as independent Cardano transactions.

        Each entry of ``records`` is a dict with shape
        ``{"record": bytes | str, "quote_id": str,
        "signatures": Optional[Sequence[RecordSignature]]}``.
        Each entry carries its own ``quote_id`` — call ``quote()`` per
        record ahead of time. Per-record errors land in ``results[]``
        without rolling back the batch.
        """
        wire_records: list[dict[str, Any]] = []
        for r in records:
            entry: dict[str, Any] = {
                "record": _to_hex(r["record"]),
                "quote_id": r["quote_id"],
            }
            if r.get("signatures") is not None:
                entry["signatures"] = list(r["signatures"])
            wire_records.append(entry)
        body = {"records": wire_records}
        response = await self._config.http_client.post(
            f"{self._config.base_url}/poe/publish-batch",
            content=json.dumps(body, separators=(",", ":")),
            headers=_build_json_headers(self._config.api_key, idempotency_key),
        )
        _raise_for_status(response)
        return cast(PublishBatchResponse, response.json())

    async def publish_content(
        self,
        *,
        content: bytes | str,
        quote_id: str,
        signer: Signer | None = None,
        hash_alg: SupportedHashAlg = "sha2-256",
        idempotency_key: str | None = None,
    ) -> PublishResponse:
        """High-level hash-only publish: hash the supplied content, build a
        single-item Label 309 record, optionally sign with the caller-supplied
        signer, and submit. No Arweave, no /uploads — anchors the digest only.
        """
        config = _ResolvedPublishConfig(
            api_key=self._config.api_key,
            base_url=self._config.base_url,
            http_client=self._config.http_client,
        )
        return await _publish_content_impl(
            config,
            content=content,
            quote_id=quote_id,
            signer=signer,
            hash_alg=hash_alg,
            idempotency_key=idempotency_key,
        )

    async def publish_prehashed(
        self,
        *,
        hashes: dict[SupportedHashAlg, str],
        quote_id: str,
        signer: Signer | None = None,
        idempotency_key: str | None = None,
    ) -> PublishResponse:
        """Hash-already-computed PoE — anchor a precomputed content digest
        (hex-encoded) with optional path-1 signature. No Arweave, no
        /uploads, no client-side hashing.
        """
        config = _ResolvedPublishConfig(
            api_key=self._config.api_key,
            base_url=self._config.base_url,
            http_client=self._config.http_client,
        )
        return await _publish_prehashed_impl(
            config,
            hashes=hashes,
            quote_id=quote_id,
            signer=signer,
            idempotency_key=idempotency_key,
        )

    async def quote_prepared_seal(
        self,
        *,
        prepared: PreparedSeal,
        signer: Signer | None = None,
        supersedes: str | None = None,
    ) -> QuoteResponse:
        """Price a prepared seal without uploading anything — the preview UIs
        show before the user commits to storage.

        ``prepared`` comes from :func:`cardanowall.client.sealed.seal_prepare`.
        ``signer`` and ``supersedes`` affect the price only through their
        presence (a signed or superseding record is larger); the signer is
        not invoked. The returned quote may later be passed to
        :py:meth:`submit_sealed` via its ``quote`` argument — a still-fresh
        preview is consumed as the price lock, a stale one is silently
        replaced by a fresh internal quote.
        """
        config = _ResolvedPublishConfig(
            api_key=self._config.api_key,
            base_url=self._config.base_url,
            http_client=self._config.http_client,
        )
        return await _quote_prepared_seal_impl(
            config,
            prepared=prepared,
            signer=signer,
            supersedes=supersedes,
        )

    async def submit_sealed(
        self,
        *,
        prepared: PreparedSeal,
        signer: Signer | None = None,
        max_usd_micros: int | None = None,
        quote: QuoteResponse | None = None,
        supersedes: str | None = None,
        idempotency_key: str | None = None,
        chunk_bytes: int | None = None,
        uploaded: Sequence[UploadReceipt] = (),
    ) -> SealedSubmission:
        """Phase 2 of the sealed flow: submit a prepared seal — quote →
        price-cap check → per-item ciphertext upload (skipping items covered
        by validated ``uploaded`` receipts) → quote refresh if an upload
        outlived the price lock → encode (optionally sign) → publish.

        Uploads carry a deterministic per-item idempotency key derived from
        the prepared artifact, so a crash-and-retry of the same prepared item
        can never pay for its storage twice.

        Raises :class:`cardanowall.client.sealed.SubmitSealedError`; when the
        failure happened after any upload completed, its ``uploads`` attribute
        carries the finished receipts — persist them and resume by passing
        them back via ``uploaded``.
        """
        config = _ResolvedPublishConfig(
            api_key=self._config.api_key,
            base_url=self._config.base_url,
            http_client=self._config.http_client,
        )
        return await _submit_sealed_impl(
            config,
            prepared=prepared,
            signer=signer,
            max_usd_micros=max_usd_micros,
            quote=quote,
            supersedes=supersedes,
            idempotency_key=idempotency_key,
            chunk_bytes=chunk_bytes,
            uploaded=uploaded,
        )

    async def publish_sealed(
        self,
        *,
        items: Sequence[bytes | str],
        recipients: Sequence[bytes],
        hash_alg: SupportedHashAlg = "sha2-256",
        kem: SupportedKem = "mlkem768x25519",
        signer: Signer | None = None,
        max_usd_micros: int | None = None,
        supersedes: str | None = None,
        idempotency_key: str | None = None,
        chunk_bytes: int | None = None,
    ) -> SealedSubmission:
        """One-shot sealed publish: seal every item to the recipient public
        keys (age-style sealed envelope), then quote internally, upload each
        ciphertext to Arweave, build the multi-item Label 309 record with the
        resulting ``ar://`` URIs, sign (optional), and submit via /publish.

        Convenient when nothing needs to survive a process crash; a flow that
        must resume (CI jobs, large ciphertexts) runs the two phases itself —
        :func:`cardanowall.client.sealed.seal_prepare` and
        :py:meth:`submit_sealed` — and persists the ``PreparedSeal`` and the
        ``UploadReceipt`` s.

        ``kem`` selects the key-encapsulation mechanism and defaults to
        ``'mlkem768x25519'`` — the post-quantum-safe X-Wing hybrid (ML-KEM-768
        + X25519). Pass ``'x25519'`` for the classical, higher-capacity path.
        The recipient public-key length MUST match the chosen KEM (32 bytes
        for ``'x25519'``, 1216 bytes for ``'mlkem768x25519'``); one KEM covers
        every item and mixing KEMs is not permitted.

        The sender SHOULD include their own recipient public key in
        ``recipients`` to retain decrypt access — the SDK does NOT inject
        the sender silently.

        ``max_usd_micros`` refuses to publish when the internally fetched
        quote exceeds the cap (USD micro-cents; 1 USD = 1,000,000). A
        ciphertext above the resumable threshold (~48 MiB) is uploaded as a
        resumable session; ``chunk_bytes`` requests its chunk size (the
        server clamps to its ``max_chunk_bytes``).
        """
        config = _ResolvedPublishConfig(
            api_key=self._config.api_key,
            base_url=self._config.base_url,
            http_client=self._config.http_client,
        )
        return await _publish_sealed_impl(
            config,
            items=items,
            recipients=recipients,
            hash_alg=hash_alg,
            kem=kem,
            signer=signer,
            max_usd_micros=max_usd_micros,
            supersedes=supersedes,
            idempotency_key=idempotency_key,
            chunk_bytes=chunk_bytes,
        )

    async def publish_merkle(
        self,
        *,
        leaves: list[bytes | str],
        signer: Signer | None = None,
        hash_alg: str = "sha2-256",
        leaf_alg: str | None = None,
        max_usd_micros: int | None = None,
        idempotency_key: str | None = None,
        chunk_bytes: int | None = None,
    ) -> PublishMerkleResponse:
        """Merkle batch publish: compute the RFC 9162 §2.1.1 root over N
        caller-supplied 32-byte leaf hashes, upload the canonical leaves-list
        CBOR to Arweave, bind the root + leaf_count into ``merkle[0]`` of an
        on-chain record, optionally sign, and submit.

        The helper owns the whole priced flow: it quotes internally from the
        exact-width record-size estimate, enforces ``max_usd_micros`` (USD
        micro-cents), uploads the leaves-list under a deterministic
        idempotency key derived from its bytes (a retry of the same batch
        never pays for its storage twice), refreshes the price lock when the
        upload outlived it, and publishes. The response carries the exact
        published record bytes.

        ``leaf_alg`` is the advisory claim written into the uploaded
        leaves-list naming how the leaves were computed (e.g. ``'sha2-256'``);
        omitted when the leaves carry no such claim. Only ``'sha2-256'``
        leaves are supported in v1.

        A leaves-list above the resumable threshold (~48 MiB) is uploaded as a
        resumable session; ``chunk_bytes`` requests its chunk size (the server
        clamps to its ``max_chunk_bytes``).
        """
        config = _ResolvedPublishConfig(
            api_key=self._config.api_key,
            base_url=self._config.base_url,
            http_client=self._config.http_client,
        )
        # Cast at the boundary: the helper's signature pins `Literal['sha2-256']`,
        # while this wrapper takes `str` so callers don't have to import the
        # Literal alias.
        return await _publish_merkle_impl(
            config,
            leaves=leaves,
            signer=signer,
            hash_alg=cast("Any", hash_alg),
            leaf_alg=leaf_alg,
            max_usd_micros=max_usd_micros,
            idempotency_key=idempotency_key,
            chunk_bytes=chunk_bytes,
        )


__all__ = ["PoeNamespace"]
