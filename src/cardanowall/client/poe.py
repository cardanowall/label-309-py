"""Wraps the mutating ``/api/v1/poe/*`` REST surface:

- POST ``/api/v1/poe/quote`` — lock a USD price for an upcoming publish
- POST ``/api/v1/poe/uploads`` — multipart binary upload to a backend
- POST ``/api/v1/poe/publish`` — single finalised record (JSON)
- POST ``/api/v1/poe/publish-batch`` — 1..50 finalised records (JSON)

Plus high-level helpers that compose the above into common flows:

- :py:meth:`PoeNamespace.publish_content` — hash-only
- :py:meth:`PoeNamespace.publish_prehashed` — caller already holds digest
- :py:meth:`PoeNamespace.publish_sealed` — encrypt + uploads + publish
- :py:meth:`PoeNamespace.publish_merkle` — uploads + publish, Merkle root

Reads and verifications live under
:class:`cardanowall.client.records.RecordsNamespace`.

All methods are coroutines (async). Use ``asyncio.run(...)`` for sync use.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any, cast

import httpx

from .parse_http_error import parse_http_error
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
from .publish import (
    publish_sealed as _publish_sealed_impl,
)
from .types import (
    PublishBatchResponse,
    PublishResponse,
    QuoteResponse,
    RecordSignature,
    StorageTarget,
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

        Pass the returned ``quote_id`` to ``publish()`` (or one of the
        high-level ``publish_content`` / ``publish_sealed`` /
        ``publish_merkle`` helpers).
        """
        body = {
            "record_bytes": record_bytes,
            "recipient_count": recipient_count,
            "file_bytes_total": file_bytes_total,
        }
        response = await self._config.http_client.post(
            f"{self._config.base_url}/api/v1/poe/quote",
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
        /api/v1/poe/quote → POST /api/v1/poe/publish) and is debited once
        at publish time against the locked price snapshot.

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
            f"{self._config.base_url}/api/v1/poe/uploads",
            data={"target": target},
            files=files,
            headers=_build_multipart_headers(self._config.api_key, idempotency_key),
        )
        _raise_for_status(response)
        return cast(UploadsResponse, response.json())

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
            f"{self._config.base_url}/api/v1/poe/publish",
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
            f"{self._config.base_url}/api/v1/poe/publish-batch",
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

    async def publish_sealed(
        self,
        *,
        content: bytes | str,
        recipients: Sequence[bytes],
        quote_id: str,
        signer: Signer | None = None,
        hash_alg: SupportedHashAlg = "sha2-256",
        kem: SupportedKem = "mlkem768x25519",
        idempotency_key: str | None = None,
    ) -> PublishResponse:
        """Sealed-PoE: encrypt content to the recipient public keys (age-style
        sealed envelope), upload the ciphertext to Arweave via /uploads, build a
        Label 309 record with the resulting ``ar://`` URI, sign (optional), and
        submit via /publish.

        ``kem`` selects the key-encapsulation mechanism and defaults to
        ``'mlkem768x25519'`` — the post-quantum-safe X-Wing hybrid (ML-KEM-768 +
        X25519). Pass ``'x25519'`` for the classical, higher-capacity path. The
        recipient public-key length MUST match the chosen KEM (32 bytes for
        ``'x25519'``, 1216 bytes for ``'mlkem768x25519'``); mixing KEMs across
        recipients is not permitted.

        The sender SHOULD include their own recipient public key in
        ``recipients`` to retain decrypt access — the SDK does NOT inject
        the sender silently.
        """
        config = _ResolvedPublishConfig(
            api_key=self._config.api_key,
            base_url=self._config.base_url,
            http_client=self._config.http_client,
        )
        return await _publish_sealed_impl(
            config,
            content=content,
            recipients=recipients,
            quote_id=quote_id,
            signer=signer,
            hash_alg=hash_alg,
            kem=kem,
            idempotency_key=idempotency_key,
        )

    async def publish_merkle(
        self,
        *,
        leaves: list[bytes | str],
        quote_id: str,
        signer: Signer | None = None,
        hash_alg: str = "sha2-256",
        idempotency_key: str | None = None,
    ) -> PublishMerkleResponse:
        """Merkle batch publish: compute the RFC 9162 §2.1.1 root over N
        caller-supplied 32-byte leaf hashes, upload the canonical leaves-list
        CBOR to Arweave via /uploads, bind the root + leaf_count into
        ``merkle[0]`` of an on-chain record, optionally sign, and submit.

        Only ``'sha2-256'`` leaves are supported in v1.
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
            quote_id=quote_id,
            signer=signer,
            hash_alg=cast("Any", hash_alg),
            idempotency_key=idempotency_key,
        )


__all__ = ["PoeNamespace"]
