"""Unit tests for client.records.* — the records read namespace that wraps
``GET /api/v1/records`` and ``GET /api/v1/records/{tx_hash}``.

Test shape mirrors the server fixture: we assert on the actual HTTP request
shape (URL, method, headers, body) AND on the response being parsed into the
typed ``RecordResource`` JSON.

The previous incarnation of these tests (under ``client.poe.get``) was
mock-asserts-input — it would have continued to pass even when the methods
hit a non-existent ``/api/v1/poe/{tx_hash}`` URL. The fixtures below come
from the real server response shape (the RecordResource projection the
indexer serves).
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import httpx
import pytest

from cardanowall.client.label309_client import Label309Client
from cardanowall.client.record_not_found_error import RecordNotFoundError

# Stable opaque bearer token — forwarded verbatim, never parsed by the client.
FIXTURE_API_KEY = "opaque-bearer-fixture-token"
TX_HASH = "a" * 64
ACCOUNT_ID = "acct_06bqrjg0csvqfanaqexvqexvqc"


def _client_with_handler(
    handler: Callable[[httpx.Request], httpx.Response],
    *,
    api_key: str | None = FIXTURE_API_KEY,
) -> Label309Client:
    transport = httpx.MockTransport(handler)
    return Label309Client(
        api_key=api_key,
        # Full versioned base: the version segment lives here, not in the
        # client's per-request URL building. Resource suffixes append to it,
        # so the served path stays /api/v1/records/… and the cross-SDK parity
        # fixtures remain byte-identical.
        base_url="http://test.example/api/v1",
        http_client=httpx.AsyncClient(transport=transport),
    )


def _record_fixture(**overrides: Any) -> dict[str, Any]:
    """Realistic RecordResource fixture — fields match the server projection
    (chain-anchored row at the confirmation threshold)."""
    base: dict[str, Any] = {
        "tx_hash": TX_HASH,
        "status": "confirmed",
        "block_height": 12_345_678,
        "block_time": "2026-01-01T00:00:00.000Z",
        "num_confirmations": 100,
        "scheme": 0,
        "item_count": 1,
        "signer_ed25519": None,
        "metadata_cbor_base64": "oWNmb29jYmFy",
    }
    base.update(overrides)
    return base


def _records_list_envelope(rows: list[dict[str, Any]], **overrides: Any) -> dict[str, Any]:
    """Stripe-style envelope returned by GET /api/v1/records."""
    base: dict[str, Any] = {
        "object": "list",
        "data": rows,
        "has_more": False,
        "next_cursor": None,
        "url": "/api/v1/records?sealed=true",
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# list()
# ---------------------------------------------------------------------------


def test_list_sealed_true_targets_records_with_query_and_returns_page() -> None:
    async def run() -> None:
        captured: dict[str, object] = {}

        page = _records_list_envelope(
            [_record_fixture(), _record_fixture(tx_hash="b" * 64)],
            has_more=True,
            next_cursor="opaque-next",
        )

        def handler(req: httpx.Request) -> httpx.Response:
            captured["url"] = str(req.url)
            captured["query"] = dict(req.url.params)
            return httpx.Response(200, json=page)

        async with _client_with_handler(handler) as client:
            out = await client.records.list({"sealed": True, "cursor": "eyJjdXIiOjF9", "limit": 25})

        # Page projects to the same RecordResource shape records.get returns.
        assert out["object"] == "list"
        assert len(out["data"]) == 2
        assert out["data"][0]["tx_hash"] == TX_HASH
        assert out["data"][0]["metadata_cbor_base64"] == "oWNmb29jYmFy"
        assert out["data"][1]["tx_hash"] == "b" * 64
        assert out["next_cursor"] == "opaque-next"
        assert out["has_more"] is True
        # The gateway omits ``tip_block_height``, so the SDK derives it from the
        # page as max(block_height + num_confirmations - 1) = 12_345_678 + 100 - 1.
        assert out["tip_block_height"] == 12_345_777

        assert captured["query"] == {
            "sealed": "true",
            "limit": "25",
            "cursor": "eyJjdXIiOjF9",
        }
        assert "/api/v1/poe/" not in str(captured["url"])

    asyncio.run(run())


def test_list_omits_sealed_filter_and_query_when_no_input() -> None:
    async def run() -> None:
        captured: dict[str, object] = {}

        def handler(req: httpx.Request) -> httpx.Response:
            captured["url"] = str(req.url)
            captured["query"] = dict(req.url.params)
            return httpx.Response(200, json=_records_list_envelope([]))

        async with _client_with_handler(handler) as client:
            out = await client.records.list()

        assert out["data"] == []
        # An empty page has no anchored rows to derive a tip from.
        assert out["tip_block_height"] is None
        # No query string at all when input is omitted.
        assert captured["query"] == {}
        assert "sealed" not in str(captured["url"])

    asyncio.run(run())


def test_list_honours_gateway_supplied_tip_block_height() -> None:
    async def run() -> None:
        page = _records_list_envelope([_record_fixture()], tip_block_height=9000)

        def handler(req: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json=page)

        async with _client_with_handler(handler) as client:
            out = await client.records.list()

        # Gateway-reported tip wins over the derived 12_345_678 + 100 - 1.
        assert out["tip_block_height"] == 9000

    asyncio.run(run())


def test_list_401_raises_unauthorized() -> None:
    from cardanowall.client.unauthorized_error import UnauthorizedError

    async def run() -> None:
        def handler(_req: httpx.Request) -> httpx.Response:
            return httpx.Response(
                401,
                json={
                    "type": "about:blank",
                    "title": "Unauthorized",
                    "status": 401,
                    "detail": "Authentication required.",
                    "code": "unauthorized",
                    "trace_id": "01977c00-0000-7000-8000-000000000000",
                },
            )

        async with _client_with_handler(handler) as client:
            with pytest.raises(UnauthorizedError):
                await client.records.list({"sealed": True})

    asyncio.run(run())


# ---------------------------------------------------------------------------
# get()
# ---------------------------------------------------------------------------


def test_get_targets_records_endpoint_and_returns_typed_record_resource() -> None:
    async def run() -> None:
        captured: dict[str, object] = {}

        def handler(req: httpx.Request) -> httpx.Response:
            captured["method"] = req.method
            captured["path"] = req.url.path
            captured["url"] = str(req.url)
            captured["authorization"] = req.headers.get("authorization")
            return httpx.Response(200, json=_record_fixture())

        async with _client_with_handler(handler) as client:
            out = await client.records.get(TX_HASH)

        assert out["tx_hash"] == TX_HASH
        assert out["status"] == "confirmed"
        assert out["scheme"] == 0
        assert out["metadata_cbor_base64"] == "oWNmb29jYmFy"

        assert captured["method"] == "GET"
        assert captured["path"] == f"/api/v1/records/{TX_HASH}"
        # The dead /api/v1/poe/{tx_hash} URL must never appear.
        assert "/api/v1/poe/" not in str(captured["url"])
        assert captured["authorization"] == f"Bearer {FIXTURE_API_KEY}"

    asyncio.run(run())


def test_get_surfaces_owner_only_account_id_when_server_includes_it() -> None:
    async def run() -> None:
        def handler(_req: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json=_record_fixture(account_id=ACCOUNT_ID))

        async with _client_with_handler(handler) as client:
            out = await client.records.get(TX_HASH)
            assert out["account_id"] == ACCOUNT_ID

    asyncio.run(run())


def test_get_404_raises_record_not_found() -> None:
    async def run() -> None:
        def handler(_req: httpx.Request) -> httpx.Response:
            return httpx.Response(
                404,
                json={
                    "type": "https://cardanowall.com/problems/record-not-found",
                    "title": "Record Not Found",
                    "status": 404,
                    "detail": "No record is indexed under that transaction hash.",
                    "code": "record-not-found",
                    "trace_id": "01977c00-0000-7000-8000-000000000000",
                },
            )

        async with _client_with_handler(handler) as client:
            with pytest.raises(RecordNotFoundError):
                await client.records.get(TX_HASH)

    asyncio.run(run())


def test_records_get_request_shape_matches_cross_sdk_parity_fixture() -> None:
    """Both SDKs (TS + Py) must produce a byte-identical HTTP request shape
    for the canonical ``client.records.get(TX_HASH)`` call. The fixture lives
    at ``tests/fixtures/records-request/records-get-request.json`` (one copy
    per SDK; both committed identical). A divergence between the two
    languages surfaces as a test failure on at least one side.
    """
    parity_key = "sk-cw-live-" + "b" * 52

    async def run() -> None:
        captured: dict[str, object] = {}

        def handler(req: httpx.Request) -> httpx.Response:
            captured["method"] = req.method
            captured["url"] = str(req.url)
            captured["authorization"] = req.headers.get("authorization")
            captured["accept"] = req.headers.get("accept")
            return httpx.Response(200, json=_record_fixture())

        async with _client_with_handler(handler, api_key=parity_key) as client:
            await client.records.get(TX_HASH)

        fixture_path = (
            Path(__file__).parent / "fixtures" / "records-request" / "records-get-request.json"
        )
        fixture = json.loads(fixture_path.read_text("utf-8"))

        assert captured["method"] == fixture["method"]
        assert captured["url"] == fixture["url"]
        assert captured["authorization"] == fixture["authorization"]
        assert captured["accept"] == fixture["accept"]

    asyncio.run(run())


# ---------------------------------------------------------------------------
# records.count() — GET /records/count, signer required.
# ---------------------------------------------------------------------------


def test_count_returns_typed_count() -> None:
    async def run() -> None:
        captured: dict[str, object] = {}

        def handler(req: httpx.Request) -> httpx.Response:
            captured["url"] = str(req.url)
            return httpx.Response(
                200,
                json={"object": "count", "count": 42, "url": "/api/v1/records/count"},
            )

        async with _client_with_handler(handler) as client:
            out = await client.records.count({"signer": "a" * 64})
            assert out["object"] == "count"
            assert out["count"] == 42
            assert out["url"] == "/api/v1/records/count"

        url = str(captured["url"])
        assert "/api/v1/records/count" in url
        assert "signer=" + "a" * 64 in url

    asyncio.run(run())


def test_count_forwards_all_narrowers() -> None:
    async def run() -> None:
        captured: dict[str, object] = {}

        def handler(req: httpx.Request) -> httpx.Response:
            captured["params"] = dict(req.url.params)
            return httpx.Response(
                200, json={"object": "count", "count": 3, "url": "/api/v1/records/count"}
            )

        async with _client_with_handler(handler) as client:
            await client.records.count(
                {
                    "signer": "b" * 64,
                    "scheme": 1,
                    "sealed": True,
                    "from_block": 100,
                    "to_block": 200,
                    "from_time": "2026-01-01T00:00:00Z",
                    "to_time": "2026-02-01T00:00:00Z",
                }
            )

        params = captured["params"]
        assert isinstance(params, dict)
        # Exact wire query names mirror the list/count gateway grammar.
        assert params["signer"] == "b" * 64
        assert params["scheme"] == "1"
        assert params["sealed"] == "true"
        assert params["from_block"] == "100"
        assert params["to_block"] == "200"
        assert params["from_time"] == "2026-01-01T00:00:00Z"
        assert params["to_time"] == "2026-02-01T00:00:00Z"

    asyncio.run(run())


def test_count_rejects_non_hex_signer_client_side() -> None:
    async def run() -> None:
        def handler(_req: httpx.Request) -> httpx.Response:  # pragma: no cover - never called
            raise AssertionError("count must reject a bad signer before any request")

        async with _client_with_handler(handler) as client:
            # Uppercase / wrong-length signers are rejected before the request.
            with pytest.raises(ValueError, match="signer"):
                await client.records.count({"signer": "A" * 64})
            with pytest.raises(ValueError, match="signer"):
                await client.records.count({"signer": "abc"})

    asyncio.run(run())


def test_count_sealed_false_serializes_false() -> None:
    async def run() -> None:
        captured: dict[str, object] = {}

        def handler(req: httpx.Request) -> httpx.Response:
            captured["params"] = dict(req.url.params)
            return httpx.Response(
                200, json={"object": "count", "count": 0, "url": "/api/v1/records/count"}
            )

        async with _client_with_handler(handler) as client:
            await client.records.count({"signer": "c" * 64, "sealed": False})

        params = captured["params"]
        assert isinstance(params, dict)
        assert params["sealed"] == "false"

    asyncio.run(run())
