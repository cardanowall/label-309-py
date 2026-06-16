from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

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
        async with Label309Client(base_url="https://gateway.example.com/api/v1") as client:
            assert isinstance(client.poe, PoeNamespace)
            assert isinstance(client.records, RecordsNamespace)
            assert isinstance(client.account, AccountNamespace)

    asyncio.run(run())


def test_custom_base_url_strips_exactly_one_trailing_slash() -> None:
    async def run() -> None:
        captured: dict[str, str] = {}

        def handler(req: httpx.Request) -> httpx.Response:
            captured["url"] = str(req.url)
            return httpx.Response(200, json=_RECORDS_LIST_BODY)

        # A single trailing slash on the configured versioned base is stripped
        # so the resource suffix joins cleanly to one slash.
        async with Label309Client(
            base_url="http://localhost:3000/api/v1/",
            http_client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
        ) as client:
            await client.records.list({"sealed": True})
        assert captured["url"].startswith("http://localhost:3000/api/v1/records")
        assert "sealed=true" in captured["url"]
        assert "/api/v1//records" not in captured["url"]

    asyncio.run(run())


def test_custom_base_url_strips_at_most_one_trailing_slash() -> None:
    """Parity vector with sdk-ts/sdk-rs: a base ending in a DOUBLE slash keeps
    exactly one slash (only one trailing slash is stripped), so the joined URL
    retains the empty path segment rather than collapsing it. The three SDKs
    must produce byte-identical output for this input.
    """

    async def run() -> None:
        captured: dict[str, str] = {}

        def handler(req: httpx.Request) -> httpx.Response:
            captured["url"] = str(req.url)
            return httpx.Response(200, json=_RECORDS_LIST_BODY)

        async with Label309Client(
            base_url="http://localhost:3000/api/v1//",
            http_client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
        ) as client:
            await client.records.list({"sealed": True})
        # base "…/api/v1//" → strip one slash → "…/api/v1/" → + "/records"
        # → "…/api/v1//records" (the doubled slash survives verbatim).
        assert captured["url"].startswith("http://localhost:3000/api/v1//records")
        assert "sealed=true" in captured["url"]

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
            base_url="http://test/api/v1",
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
            base_url="https://gateway.example.com/api/v1",
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
            base_url="https://gateway.example.com/api/v1",
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
            base_url="https://gateway.example.com/api/v1",
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


# ---------------------------------------------------------------------------
# Shared cross-SDK base_url-join parity matrix
# ---------------------------------------------------------------------------

# A 64-char hex tx hash, matching the ``/records/<tx_hash>`` suffixes the shared
# matrix pins. The same literal is baked into the fixture's suffix/expected_url,
# so the driver MUST call with this exact value for the joined URL to match.
_PARITY_TX_HASH = "a" * 64

_QUOTE_BODY = {
    "quote_id": "01956b41-7c00-7000-8000-000000000001",
    "amount": "180000",
    "currency": "USD",
    "expires_at": "2026-05-26T12:15:00.000Z",
}
_PUBLISH_BODY: dict[str, Any] = {
    "id": "poe_06bqrjg0csvqfanaqexvqexvqc",
    "tx_hash": None,
    "status": "submitting",
    "items_count": 1,
    "signed": False,
    "sealed": False,
    "items": [],
    "conformance_profile": "core",
    "balance_after_usd_micros": "4500000",
}
_PUBLISH_BATCH_BODY = {"results": [], "balance_after_usd_micros": "4500000"}
_UPLOADS_BODY = {
    "uploads": [{"idx": 0, "ok": True, "uri": f"ar://{'A' * 43}", "sha256": "00" * 32, "bytes": 1}]
}

# Maps each resource suffix in the shared matrix to (real namespace call, stub
# response body) so the parity test drives the ACTUAL client join path (resolve
# base + concat) for every suffix rather than re-implementing the concatenation.
# The set is exactly the suffixes present in all three SDK client modules.
_SUFFIX_DRIVERS: dict[
    str,
    tuple[Any, dict[str, Any]],
] = {
    "/records": (lambda c: c.records.list(), _RECORDS_LIST_BODY),
    f"/records/{_PARITY_TX_HASH}": (lambda c: c.records.get(_PARITY_TX_HASH), {}),
    "/account/balance": (lambda c: c.account.balance(), {"balance_usd_micros": "0"}),
    "/poe/quote": (
        lambda c: c.poe.quote(record_bytes=1, recipient_count=0, file_bytes_total=0),
        _QUOTE_BODY,
    ),
    "/poe/publish": (
        lambda c: c.poe.publish(record="aa", quote_id=_QUOTE_BODY["quote_id"]),
        _PUBLISH_BODY,
    ),
    "/poe/publish-batch": (
        lambda c: c.poe.publish_batch(
            records=[{"record": "aa", "quote_id": _QUOTE_BODY["quote_id"]}]
        ),
        _PUBLISH_BATCH_BODY,
    ),
    "/poe/uploads": (
        lambda c: c.poe.uploads(target="arweave", data=[b"\xaa"]),
        _UPLOADS_BODY,
    ),
}


def test_base_url_join_matches_shared_cross_sdk_parity_matrix() -> None:
    """The gateway base_url-join convention is byte-identical across sdk-ts,
    sdk-py and sdk-rs. Each appends ONLY the resource suffix to the configured
    FULL versioned ``base_url`` (plain string concat after trimming surrounding
    whitespace and stripping at most one trailing slash); the version segment
    lives only in ``base_url``. The shared matrix at
    ``tests/fixtures/client-url-join/base-url-join-vectors.json`` — mirrored
    BYTE-IDENTICALLY across the three SDKs — pins the expected full URL for every
    (base, suffix) pair, including the ``base + "//"`` double-slash rows that
    prove the at-most-one-slash strip and the ``origin-only`` rows that prove the
    client injects no ``/api/v1`` of its own. Every suffix is driven through the
    real namespace call so the assertion exercises the production join path.
    """
    vectors_path = (
        Path(__file__).parent / "fixtures" / "client-url-join" / "base-url-join-vectors.json"
    )
    vectors = json.loads(vectors_path.read_text("utf-8"))
    # Every suffix in the matrix must have a real driver, and every driver must
    # be exercised — a divergence means a suffix was added/removed on one side.
    assert {case["suffix"] for case in vectors["cases"]} == set(_SUFFIX_DRIVERS)

    async def run() -> None:
        for case in vectors["cases"]:
            driver, body = _SUFFIX_DRIVERS[case["suffix"]]
            captured: dict[str, str] = {}

            def handler(
                req: httpx.Request,
                _c: dict[str, str] = captured,
                _body: dict[str, Any] = body,
            ) -> httpx.Response:
                _c["url"] = str(req.url)
                return httpx.Response(200, json=_body)

            async with Label309Client(
                api_key=FIXTURE_API_KEY,
                base_url=case["base_url"],
                http_client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
            ) as client:
                await driver(client)

            # The request URL equals normalize(base) + suffix byte-for-byte (the
            # driver calls append no query string).
            assert captured["url"] == case["expected_url"], case["name"]

    asyncio.run(run())
