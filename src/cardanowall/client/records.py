"""``client.records.*`` — open-standard indexer read surface.

Wraps the canonical record routes:

* ``GET  /api/v1/records``                   → :meth:`RecordsNamespace.list`
* ``GET  /api/v1/records/{tx_hash}``         → :meth:`RecordsNamespace.get`
* ``POST /api/v1/records/{tx_hash}/verify``  → :meth:`RecordsNamespace.verify`

The ``poe`` namespace owns the mutation methods (``uploads``, ``publish``,
``publish_batch`` + the high-level ``publish_content`` / ``publish_sealed``
/ ``publish_merkle`` helpers); reads and verifications live here under
Records — same tag grouping the OpenAPI registry uses.

Auth is optional: chain data is public. When an API key is configured the
SDK forwards it as ``Authorization: Bearer …`` so owner-only fields
(currently just ``account_id``) surface for the caller's own rows, and so the
``sealed`` list filter can resolve records addressed to the caller.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, cast

import httpx

from .parse_http_error import parse_http_error
from .types import PoeVerifyInput, RecordResource, RecordsListInput, RecordsListResponse


@dataclass(frozen=True)
class _ResolvedConfig:
    api_key: str | None
    base_url: str
    http_client: httpx.AsyncClient


def _build_headers(api_key: str | None) -> dict[str, str]:
    headers = {"content-type": "application/json", "accept": "application/json"}
    if api_key is not None:
        headers["authorization"] = f"Bearer {api_key}"
    return headers


def _derive_tip_block_height(records: list[RecordResource]) -> int | None:
    """Derive the chain tip from a record page as
    ``max(block_height + num_confirmations - 1)`` over the rows that carry a
    block height. Returns ``None`` for an empty page or one with no anchored
    rows.
    """
    tip: int | None = None
    for record in records:
        block_height = record.get("block_height")
        if block_height is None:
            continue
        candidate = block_height + record.get("num_confirmations", 0) - 1
        tip = candidate if tip is None else max(tip, candidate)
    return tip


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


class RecordsNamespace:
    """``GET /api/v1/records``, ``GET /api/v1/records/{tx_hash}`` +
    ``POST /api/v1/records/{tx_hash}/verify``."""

    def __init__(self, config: _ResolvedConfig) -> None:
        self._config = config

    async def list(
        self, input: RecordsListInput | None = None
    ) -> RecordsListResponse:
        """List records as a paginated :class:`RecordsListResponse` whose
        ``data[]`` entries are the same :class:`RecordResource` projection
        :meth:`get` returns.

        Pass ``{"sealed": True}`` to restrict the page to sealed records
        addressed to the authenticated caller (the gateway resolves the
        recipient from the bearer identity); omit it to list every record the
        caller may read. Page with ``{"cursor": previous["next_cursor"]}``
        until ``has_more`` is false.
        """
        params: dict[str, Any] = {}
        if input is not None:
            if input.get("sealed") is True:
                params["sealed"] = "true"
            limit = input.get("limit")
            if limit is not None:
                params["limit"] = limit
            cursor = input.get("cursor")
            if cursor is not None:
                params["cursor"] = cursor
        response = await self._config.http_client.get(
            f"{self._config.base_url}/api/v1/records",
            params=params,
            headers=_build_headers(self._config.api_key),
        )
        _raise_for_status(response)
        page = cast(RecordsListResponse, response.json())
        # A gateway that reports ``tip_block_height`` populates confirmation
        # data directly; otherwise derive it from the page rows so a
        # sealed-record sync has a tip to compute confirmation depth against.
        if page.get("tip_block_height") is None:
            page["tip_block_height"] = _derive_tip_block_height(page["data"])
        return page

    async def get(self, tx_hash: str) -> RecordResource:
        """Fetch a record by Cardano transaction hash.

        Returns the canonical JSON :class:`RecordResource` projection — the
        same shape every entry of :meth:`list` returns inside ``data[]``.

        404 (:class:`RecordNotFoundError`) on tx_hashes the indexer has not
        seen, OR on un-anchored rows when the caller is not their owner
        (oracle-safe indistinguishable response per the route's privacy
        invariant).
        """
        response = await self._config.http_client.get(
            f"{self._config.base_url}/api/v1/records/{tx_hash}",
            headers=_build_headers(self._config.api_key),
        )
        _raise_for_status(response)
        return response.json()  # type: ignore[no-any-return]

    async def verify(
        self, tx_hash: str, input: PoeVerifyInput | None = None
    ) -> dict[str, Any]:
        """Run the canonical Label 309 verifier against the record at ``tx_hash``.

        Returns the same ``VerifyReport`` JSON shape the standalone verifier
        emits — ``VerifyReport`` IS the wire body of this endpoint, no
        transformer in between (see the verifier types in
        ``cardanowall.verifier.types``).

        Auth required (Bearer with ``poe:read`` scope, or NextAuth session
        cookie). Optional ``verify_uris`` toggles URI hash-equivalence checks;
        ``decryption[]`` drives trial-decrypt of sealed envelopes per item.
        """
        response = await self._config.http_client.post(
            f"{self._config.base_url}/api/v1/records/{tx_hash}/verify",
            content=json.dumps(input or {}, separators=(",", ":")),
            headers=_build_headers(self._config.api_key),
        )
        _raise_for_status(response)
        return response.json()  # type: ignore[no-any-return]


__all__ = ["RecordsNamespace"]
