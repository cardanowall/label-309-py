from __future__ import annotations

import asyncio

import httpx
import pytest

from cardanowall.client.account import AccountNamespace
from cardanowall.client.label309_client import (
    InvalidClientConfigError,
    Label309Client,
)
from cardanowall.client.poe import PoeNamespace
from cardanowall.client.records import RecordsNamespace

# Opaque bearer token — the client forwards it verbatim and never parses it.
FIXTURE_API_KEY = "opaque-bearer-fixture-token"

_RECORDS_LIST_BODY = {
    "object": "list",
    "data": [],
    "has_more": False,
    "next_cursor": None,
    "url": "/api/v1/records?sealed=true",
}


def test_namespaces_wired() -> None:
    async def run() -> None:
        async with Label309Client(base_url="https://gateway.example.com") as client:
            assert isinstance(client.poe, PoeNamespace)
            assert isinstance(client.records, RecordsNamespace)
            assert isinstance(client.account, AccountNamespace)

    asyncio.run(run())


def test_custom_base_url_strips_trailing_slash() -> None:
    async def run() -> None:
        captured: dict[str, str] = {}

        def handler(req: httpx.Request) -> httpx.Response:
            captured["url"] = str(req.url)
            return httpx.Response(200, json=_RECORDS_LIST_BODY)

        async with Label309Client(
            base_url="http://localhost:3000/",
            http_client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
        ) as client:
            await client.records.list({"sealed": True})
        assert captured["url"].startswith("http://localhost:3000/api/v1/records")
        assert "sealed=true" in captured["url"]
        assert "localhost:3000//" not in captured["url"]

    asyncio.run(run())


def test_threads_api_key_into_authorization_header() -> None:
    async def run() -> None:
        captured: dict[str, str | None] = {}

        def handler(req: httpx.Request) -> httpx.Response:
            captured["auth"] = req.headers.get("authorization")
            return httpx.Response(
                202,
                json={
                    "id": "poe_06bqrjg0csvqfanaqexvqexvqc",
                    "tx_hash": None,
                    "status": "submitting",
                    "items_count": 1,
                    "signed": False,
                    "sealed": False,
                    "items": [],
                    "conformance_profile": "core",
                    "balance_after_usd_micros": "4500000",
                },
            )

        async with Label309Client(
            api_key=FIXTURE_API_KEY,
            base_url="http://test",
            http_client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
        ) as client:
            await client.poe.publish(record="aa", quote_id="01956b41-7c00-7000-8000-000000000001")
        assert captured["auth"] == f"Bearer {FIXTURE_API_KEY}"

    asyncio.run(run())


def test_forwards_arbitrary_opaque_key_verbatim() -> None:
    async def run() -> None:
        captured: dict[str, str | None] = {}

        def handler(req: httpx.Request) -> httpx.Response:
            captured["auth"] = req.headers.get("authorization")
            return httpx.Response(200, json=_RECORDS_LIST_BODY)

        # A third-party gateway may issue keys in any format; the client must
        # not validate or reshape the bearer token.
        opaque = "vendor.token~with/odd+chars=123"
        async with Label309Client(
            base_url="https://gateway.example.com",
            api_key=opaque,
            http_client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
        ) as client:
            await client.records.list({"sealed": True})
        assert captured["auth"] == f"Bearer {opaque}"

    asyncio.run(run())


def test_anonymous_client_sends_no_authorization_header() -> None:
    async def run() -> None:
        captured: dict[str, str | None] = {}

        def handler(req: httpx.Request) -> httpx.Response:
            captured["auth"] = req.headers.get("authorization")
            return httpx.Response(200, json=_RECORDS_LIST_BODY)

        async with Label309Client(
            base_url="https://gateway.example.com",
            http_client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
        ) as client:
            await client.records.list({"sealed": True})
        assert captured["auth"] is None

    asyncio.run(run())


def test_targets_explicit_base_url_verbatim() -> None:
    async def run() -> None:
        captured: dict[str, str] = {}

        def handler(req: httpx.Request) -> httpx.Response:
            captured["url"] = str(req.url)
            return httpx.Response(200, json=_RECORDS_LIST_BODY)

        async with Label309Client(
            base_url="https://gateway.example.com",
            api_key=FIXTURE_API_KEY,
            http_client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
        ) as client:
            await client.records.list({"sealed": True})
        assert captured["url"].startswith("https://gateway.example.com/api/v1/records")

    asyncio.run(run())


def test_raises_when_base_url_missing() -> None:
    with pytest.raises(InvalidClientConfigError) as ei:
        Label309Client(api_key=FIXTURE_API_KEY)
    assert "base_url is required" in str(ei.value)


def test_raises_when_base_url_empty() -> None:
    with pytest.raises(InvalidClientConfigError):
        Label309Client(base_url="   ")
