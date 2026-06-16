"""Unit tests for client.account.* — the account read namespace that wraps
``GET /api/v1/account/balance``.

Asserts on the actual HTTP request shape (URL, method, auth header) AND on the
response being parsed into the typed ``AccountBalance``. The wire field
``balance_usd_micros`` is returned verbatim as a string so the bigint
micro-cents value survives without precision loss.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable

import httpx
import pytest

from cardanowall.client.insufficient_scope_error import InsufficientScopeError
from cardanowall.client.label309_client import Label309Client
from cardanowall.client.unauthorized_error import UnauthorizedError

# Stable opaque bearer token — forwarded verbatim, never parsed by the client.
FIXTURE_API_KEY = "opaque-bearer-fixture-token"


def _client_with_handler(
    handler: Callable[[httpx.Request], httpx.Response],
    *,
    api_key: str | None = FIXTURE_API_KEY,
) -> Label309Client:
    transport = httpx.MockTransport(handler)
    return Label309Client(
        api_key=api_key,
        # Full versioned base: the version segment lives here. The served path
        # stays /api/v1/account/balance after the suffix join.
        base_url="http://test.example/api/v1",
        http_client=httpx.AsyncClient(transport=transport),
    )


def test_balance_targets_account_balance_endpoint_and_returns_typed_string() -> None:
    async def run() -> None:
        captured: dict[str, object] = {}

        def handler(req: httpx.Request) -> httpx.Response:
            captured["method"] = req.method
            captured["path"] = req.url.path
            captured["url"] = str(req.url)
            captured["authorization"] = req.headers.get("authorization")
            captured["accept"] = req.headers.get("accept")
            return httpx.Response(200, json={"balance_usd_micros": "1234567"})

        async with _client_with_handler(handler) as client:
            out = await client.account.balance()

        assert out == {"balance_usd_micros": "1234567"}
        # The value MUST stay a string — never coerced to an int.
        assert isinstance(out["balance_usd_micros"], str)

        assert captured["method"] == "GET"
        assert captured["path"] == "/api/v1/account/balance"
        assert captured["authorization"] == f"Bearer {FIXTURE_API_KEY}"
        assert captured["accept"] == "application/json"

    asyncio.run(run())


def test_balance_preserves_value_past_2_to_the_53_verbatim() -> None:
    async def run() -> None:
        # 2**53 + 1 — the first integer a float64 cannot represent exactly.
        huge = "9007199254740993"

        def handler(_req: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"balance_usd_micros": huge})

        async with _client_with_handler(handler) as client:
            out = await client.account.balance()
            assert out["balance_usd_micros"] == huge

    asyncio.run(run())


def test_balance_reads_zero_for_account_with_no_ledger_activity() -> None:
    async def run() -> None:
        def handler(_req: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"balance_usd_micros": "0"})

        async with _client_with_handler(handler) as client:
            out = await client.account.balance()
            assert out["balance_usd_micros"] == "0"

    asyncio.run(run())


def test_balance_403_raises_insufficient_scope() -> None:
    async def run() -> None:
        def handler(_req: httpx.Request) -> httpx.Response:
            return httpx.Response(
                403,
                json={
                    "type": "https://cardanowall.com/api/v1/errors#insufficient-scope",
                    "title": "Insufficient Scope",
                    "status": 403,
                    "detail": "The API key does not grant the account:read scope.",
                    "code": "insufficient-scope",
                    "required": ["account:read"],
                    "granted": ["poe:read"],
                    "trace_id": "01977c00-0000-7000-8000-000000000000",
                },
            )

        async with _client_with_handler(handler) as client:
            with pytest.raises(InsufficientScopeError):
                await client.account.balance()

    asyncio.run(run())


def test_balance_401_raises_unauthorized() -> None:
    async def run() -> None:
        def handler(_req: httpx.Request) -> httpx.Response:
            return httpx.Response(
                401,
                json={
                    "type": "https://cardanowall.com/api/v1/errors#unauthorized",
                    "title": "Unauthorized",
                    "status": 401,
                    "detail": "This endpoint requires authentication.",
                    "code": "unauthorized",
                    "trace_id": "01977c00-0000-7000-8000-000000000000",
                },
            )

        async with _client_with_handler(handler) as client:
            with pytest.raises(UnauthorizedError):
                await client.account.balance()

    asyncio.run(run())
