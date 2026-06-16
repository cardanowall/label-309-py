"""Unit tests for the low-level client.poe.* surface — quote(), uploads(),
publish(), publish_batch().
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import httpx
import pytest

from cardanowall.client.insufficient_funds_error import InsufficientFundsError
from cardanowall.client.label309_client import Label309Client
from cardanowall.client.quote_already_consumed_error import QuoteAlreadyConsumedError
from cardanowall.client.quote_expired_error import QuoteExpiredError
from cardanowall.client.quote_not_found_error import QuoteNotFoundError
from cardanowall.client.rate_limited_error import RateLimitedError
from cardanowall.client.service_unavailable_error import ServiceUnavailableError
from cardanowall.client.unauthorized_error import UnauthenticatedError

# Stable opaque bearer token — forwarded verbatim, never parsed by the client.
FIXTURE_API_KEY = "opaque-bearer-fixture-token"
QUOTE_ID = "01956b41-7c00-7000-8000-000000000001"

PUBLISH_BODY: dict[str, Any] = {
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

# Opaque price lock: an id, the locked total ``amount`` in ``currency``, and an
# expiry — no pricing breakdown on the public surface.
QUOTE_BODY: dict[str, Any] = {
    "quote_id": QUOTE_ID,
    "amount": "180000",
    "currency": "USD",
    "expires_at": "2026-05-26T12:15:00.000Z",
}


def _client_with_handler(handler: Callable[[httpx.Request], httpx.Response]) -> Label309Client:
    transport = httpx.MockTransport(handler)
    return Label309Client(
        api_key=FIXTURE_API_KEY,
        # Full versioned base: the resource suffixes append to it, so the
        # served path stays /api/v1/poe/… and the parity fixture matches.
        base_url="http://test.example/api/v1",
        http_client=httpx.AsyncClient(transport=transport),
    )


# ---------------------------------------------------------------------------
# quote()
# ---------------------------------------------------------------------------


def test_quote_posts_json_and_returns_opaque_price_lock() -> None:
    async def run() -> None:
        captured: dict[str, object] = {}

        def handler(req: httpx.Request) -> httpx.Response:
            captured["url"] = str(req.url)
            captured["body"] = json.loads(req.content)
            return httpx.Response(200, json=QUOTE_BODY)

        async with _client_with_handler(handler) as client:
            out = await client.poe.quote(
                record_bytes=256,
                recipient_count=1,
                file_bytes_total=1_048_576,
            )
            assert out["quote_id"] == QUOTE_ID
            assert out["amount"] == "180000"
            assert out["currency"] == "USD"
            assert out["expires_at"] == "2026-05-26T12:15:00.000Z"
            # The opaque price lock exposes no pricing internals.
            assert "breakdown" not in out
            assert "margin_pct" not in out
            assert "fx_age_seconds" not in out

        assert "/api/v1/poe/quote" in str(captured["url"])
        body = captured["body"]
        assert isinstance(body, dict)
        assert body == {
            "record_bytes": 256,
            "recipient_count": 1,
            "file_bytes_total": 1_048_576,
        }

    asyncio.run(run())


def test_quote_503_pricing_outage_maps_to_service_unavailable() -> None:
    async def run() -> None:
        # A gateway that prices on a live oracle may return ``fx-stale``; the
        # vendor-neutral client surfaces it as the generic service-unavailable.
        def handler(_req: httpx.Request) -> httpx.Response:
            return httpx.Response(
                503,
                json={
                    "type": "about:blank",
                    "title": "Service Unavailable",
                    "status": 503,
                    "detail": "Pricing temporarily unavailable.",
                    "code": "fx-stale",
                    "trace_id": "01977c00-0000-7000-8000-000000000000",
                },
            )

        async with _client_with_handler(handler) as client:
            with pytest.raises(ServiceUnavailableError):
                await client.poe.quote(record_bytes=256, recipient_count=0, file_bytes_total=0)

    asyncio.run(run())


# ---------------------------------------------------------------------------
# uploads()
# ---------------------------------------------------------------------------


def test_uploads_posts_multipart_with_target_and_file_fields() -> None:
    async def run() -> None:
        captured: dict[str, object] = {}

        def handler(req: httpx.Request) -> httpx.Response:
            captured["url"] = str(req.url)
            captured["content_type"] = req.headers.get("content-type", "")
            captured["body"] = req.content.decode("utf-8", errors="replace")
            return httpx.Response(
                200,
                json={
                    "uploads": [
                        {
                            "idx": 0,
                            "ok": True,
                            "uri": f"ar://{'A' * 43}",
                            "sha256": "00" * 32,
                            "bytes": 1,
                        }
                    ],
                },
            )

        async with _client_with_handler(handler) as client:
            out = await client.poe.uploads(
                target="arweave",
                data=[b"\xaa", b"\xbb"],
            )
            assert len(out["uploads"]) == 1

        assert "/api/v1/poe/uploads" in str(captured["url"])
        assert "multipart/form-data" in str(captured["content_type"])
        body = str(captured["body"])
        assert 'name="target"' in body
        assert "arweave" in body
        assert 'name="file_0"' in body
        assert 'name="file_1"' in body
        assert 'name="file_2"' not in body

    asyncio.run(run())


def test_uploads_threads_idempotency_key_header() -> None:
    async def run() -> None:
        captured: dict[str, str | None] = {}

        def handler(req: httpx.Request) -> httpx.Response:
            captured["idem"] = req.headers.get("idempotency-key")
            return httpx.Response(
                200,
                json={"uploads": []},
            )

        async with _client_with_handler(handler) as client:
            await client.poe.uploads(
                target="arweave",
                data=[b"\xaa"],
                idempotency_key="idem-u-1",
            )
        assert captured["idem"] == "idem-u-1"

    asyncio.run(run())


def test_uploads_returns_partial_failure_response_verbatim() -> None:
    """uploads() itself does NOT raise on per-file failures — callers see
    the response and decide. publish_sealed / publish_merkle escalate to
    PartialUploadError.
    """

    async def run() -> None:
        mixed = {
            "uploads": [
                {
                    "idx": 0,
                    "ok": True,
                    "uri": f"ar://{'A' * 43}",
                    "sha256": "00" * 32,
                    "bytes": 1,
                },
                {
                    "idx": 1,
                    "ok": False,
                    "error": {"code": "upload-failed", "detail": "arweave timeout"},
                },
            ],
        }

        def handler(_req: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json=mixed)

        async with _client_with_handler(handler) as client:
            out = await client.poe.uploads(
                target="arweave",
                data=[b"\xaa", b"\xbb"],
            )
            assert len(out["uploads"]) == 2
            assert out["uploads"][0]["ok"] is True
            assert out["uploads"][1]["ok"] is False

    asyncio.run(run())


# ---------------------------------------------------------------------------
# publish()
# ---------------------------------------------------------------------------


def test_publish_posts_json_with_quote_id_and_hex_encodes_record() -> None:
    async def run() -> None:
        captured: dict[str, object] = {}

        def handler(req: httpx.Request) -> httpx.Response:
            captured["url"] = str(req.url)
            captured["body"] = json.loads(req.content)
            return httpx.Response(202, json=PUBLISH_BODY)

        async with _client_with_handler(handler) as client:
            out = await client.poe.publish(record=b"\xaa\xbb", quote_id=QUOTE_ID)
            assert out["id"] == PUBLISH_BODY["id"]
            assert out["balance_after_usd_micros"] == "4500000"
            assert out["dedup_hit"] is False

        assert "/api/v1/poe/publish" in str(captured["url"])
        body = captured["body"]
        assert isinstance(body, dict)
        assert body["record"] == "aabb"
        assert body["quote_id"] == QUOTE_ID

    asyncio.run(run())


def test_publish_accepts_hex_string_record_verbatim() -> None:
    async def run() -> None:
        captured: dict[str, object] = {}

        def handler(req: httpx.Request) -> httpx.Response:
            captured["body"] = json.loads(req.content)
            return httpx.Response(202, json=PUBLISH_BODY)

        async with _client_with_handler(handler) as client:
            await client.poe.publish(record="deadbeef", quote_id=QUOTE_ID)
        body = captured["body"]
        assert isinstance(body, dict)
        assert body["record"] == "deadbeef"
        assert body["quote_id"] == QUOTE_ID

    asyncio.run(run())


def test_publish_reports_dedup_hit_true_on_200() -> None:
    async def run() -> None:
        def handler(_req: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json=PUBLISH_BODY)

        async with _client_with_handler(handler) as client:
            out = await client.poe.publish(record="aa", quote_id=QUOTE_ID)
            assert out["dedup_hit"] is True

    asyncio.run(run())


def test_publish_reports_dedup_hit_false_on_202() -> None:
    async def run() -> None:
        def handler(_req: httpx.Request) -> httpx.Response:
            return httpx.Response(202, json=PUBLISH_BODY)

        async with _client_with_handler(handler) as client:
            out = await client.poe.publish(record="aa", quote_id=QUOTE_ID)
            assert out["dedup_hit"] is False

    asyncio.run(run())


def test_publish_threads_idempotency_key_into_header() -> None:
    async def run() -> None:
        captured: dict[str, str | None] = {}

        def handler(req: httpx.Request) -> httpx.Response:
            captured["idem"] = req.headers.get("idempotency-key")
            return httpx.Response(202, json=PUBLISH_BODY)

        async with _client_with_handler(handler) as client:
            await client.poe.publish(record="aa", quote_id=QUOTE_ID, idempotency_key="idem-p-1")
        assert captured["idem"] == "idem-p-1"

    asyncio.run(run())


def test_publish_forwards_signatures_verbatim() -> None:
    async def run() -> None:
        captured: dict[str, object] = {}

        def handler(req: httpx.Request) -> httpx.Response:
            captured["body"] = json.loads(req.content)
            return httpx.Response(202, json=PUBLISH_BODY)

        async with _client_with_handler(handler) as client:
            await client.poe.publish(
                record="aa",
                quote_id=QUOTE_ID,
                signatures=[{"cose_sign1": "beef", "cose_key": "cafe"}],
            )
        body = captured["body"]
        assert isinstance(body, dict)
        assert body["signatures"] == [{"cose_sign1": "beef", "cose_key": "cafe"}]

    asyncio.run(run())


def test_publish_402_raises_insufficient_funds() -> None:
    async def run() -> None:
        def handler(_req: httpx.Request) -> httpx.Response:
            return httpx.Response(
                402,
                json={
                    "type": "https://cardanowall.com/problems/insufficient-funds",
                    "title": "Payment Required",
                    "status": 402,
                    "detail": "Required $0.18 for this publish; balance is $0.00.",
                    "code": "insufficient-funds",
                    "trace_id": "01977c00-0000-7000-8000-000000000000",
                    "balance_usd_micros": "0",
                    "required_usd_micros": "180000",
                    "top_up_url": "/billing/top-up",
                },
            )

        async with _client_with_handler(handler) as client:
            with pytest.raises(InsufficientFundsError) as excinfo:
                await client.poe.publish(record="aa", quote_id=QUOTE_ID)
            assert excinfo.value.balance_usd_micros == 0
            assert excinfo.value.required_usd_micros == 180_000
            assert excinfo.value.top_up_url == "/billing/top-up"

    asyncio.run(run())


def test_publish_410_quote_expired_raises_quote_expired_error() -> None:
    async def run() -> None:
        def handler(_req: httpx.Request) -> httpx.Response:
            return httpx.Response(
                410,
                json={
                    "type": "https://cardanowall.com/problems/quote-expired",
                    "title": "Gone",
                    "status": 410,
                    "detail": "Quote expired.",
                    "code": "quote-expired",
                    "trace_id": "01977c00-0000-7000-8000-000000000000",
                    "quote_id": QUOTE_ID,
                },
            )

        async with _client_with_handler(handler) as client:
            with pytest.raises(QuoteExpiredError) as excinfo:
                await client.poe.publish(record="aa", quote_id=QUOTE_ID)
            assert excinfo.value.quote_id == QUOTE_ID

    asyncio.run(run())


def test_publish_409_quote_already_consumed_raises_typed_error() -> None:
    async def run() -> None:
        def handler(_req: httpx.Request) -> httpx.Response:
            return httpx.Response(
                409,
                json={
                    "type": "https://cardanowall.com/problems/quote-already-consumed",
                    "title": "Conflict",
                    "status": 409,
                    "detail": "Quote already used.",
                    "code": "quote-already-consumed",
                    "trace_id": "01977c00-0000-7000-8000-000000000000",
                    "quote_id": QUOTE_ID,
                },
            )

        async with _client_with_handler(handler) as client:
            with pytest.raises(QuoteAlreadyConsumedError) as excinfo:
                await client.poe.publish(record="aa", quote_id=QUOTE_ID)
            assert excinfo.value.quote_id == QUOTE_ID

    asyncio.run(run())


def test_publish_404_quote_not_found_raises_typed_error() -> None:
    async def run() -> None:
        def handler(_req: httpx.Request) -> httpx.Response:
            return httpx.Response(
                404,
                json={
                    "type": "https://cardanowall.com/problems/quote-not-found",
                    "title": "Not Found",
                    "status": 404,
                    "detail": "Quote not found.",
                    "code": "quote-not-found",
                    "trace_id": "01977c00-0000-7000-8000-000000000000",
                    "quote_id": QUOTE_ID,
                },
            )

        async with _client_with_handler(handler) as client:
            with pytest.raises(QuoteNotFoundError) as excinfo:
                await client.poe.publish(record="aa", quote_id=QUOTE_ID)
            assert excinfo.value.quote_id == QUOTE_ID

    asyncio.run(run())


def test_publish_429_raises_rate_limited() -> None:
    async def run() -> None:
        def handler(_req: httpx.Request) -> httpx.Response:
            return httpx.Response(
                429,
                headers={"Retry-After": "7"},
                json={
                    "type": "https://cardanowall.com/problems/rate-limited",
                    "title": "Too Many Requests",
                    "status": 429,
                    "detail": "Rate limit exceeded for this API key.",
                    "code": "rate-limited",
                    "trace_id": "01977c00-0000-7000-8000-000000000000",
                },
            )

        async with _client_with_handler(handler) as client:
            with pytest.raises(RateLimitedError) as excinfo:
                await client.poe.publish(record="aa", quote_id=QUOTE_ID)
            assert excinfo.value.retry_after_seconds == 7

    asyncio.run(run())


def test_publish_401_raises_unauthenticated() -> None:
    async def run() -> None:
        def handler(_req: httpx.Request) -> httpx.Response:
            return httpx.Response(
                401,
                json={
                    "type": "https://cardanowall.com/problems/unauthorized",
                    "title": "Unauthorized",
                    "status": 401,
                    "detail": "API key is missing or invalid.",
                    "code": "unauthorized",
                    "trace_id": "01977c00-0000-7000-8000-000000000000",
                },
            )

        async with _client_with_handler(handler) as client:
            with pytest.raises(UnauthenticatedError):
                await client.poe.publish(record="aa", quote_id=QUOTE_ID)

    asyncio.run(run())


# ---------------------------------------------------------------------------
# publish_batch()
# ---------------------------------------------------------------------------


def test_publish_batch_posts_json_with_quote_ids_and_hex_encodes_records() -> None:
    async def run() -> None:
        captured: dict[str, object] = {}

        def handler(req: httpx.Request) -> httpx.Response:
            captured["url"] = str(req.url)
            captured["body"] = json.loads(req.content)
            return httpx.Response(
                200,
                json={
                    "results": [
                        {
                            "record_idx": 0,
                            "id": "poe_06bqrjg0csvqfanaqexvqexvqc",
                            "tx_hash": None,
                            "status": "submitting",
                            "items_count": 1,
                            "signed": False,
                            "sealed": False,
                            "items": [],
                            "conformance_profile": "core",
                        },
                    ],
                    "balance_after_usd_micros": "4320000",
                },
            )

        async with _client_with_handler(handler) as client:
            out = await client.poe.publish_batch(
                records=[
                    {"record": b"\xaa", "quote_id": QUOTE_ID},
                    {"record": "bbcc", "quote_id": "01956b41-7c00-7000-8000-000000000002"},
                ],
            )
            assert out["balance_after_usd_micros"] == "4320000"

        assert "/api/v1/poe/publish-batch" in str(captured["url"])
        body = captured["body"]
        assert isinstance(body, dict)
        assert body["records"][0]["record"] == "aa"
        assert body["records"][0]["quote_id"] == QUOTE_ID
        assert body["records"][1]["record"] == "bbcc"
        assert body["records"][1]["quote_id"] == "01956b41-7c00-7000-8000-000000000002"

    asyncio.run(run())


# ---------------------------------------------------------------------------
# Cross-SDK parity fixture
# ---------------------------------------------------------------------------


def test_poe_publish_request_shape_matches_cross_sdk_parity_fixture() -> None:
    """Both SDKs (TS + Py) must produce the same HTTP request shape for the
    canonical ``client.poe.publish(record=<16 bytes>, quote_id=...)`` call.
    The fixture lives at ``tests/fixtures/poe-request/poe-publish-request.json``
    (one copy per SDK; both committed byte-identical). URL / method /
    authorization / content-type / accept / body are all asserted
    byte-identical. Py ``json.dumps`` is pinned to compact
    ``separators=(",", ":")`` matching TS ``JSON.stringify``, so the body bytes
    match literally.
    """
    parity_key = "sk-cw-live-" + "b" * 52

    async def run() -> None:
        captured: dict[str, object] = {}

        def handler(req: httpx.Request) -> httpx.Response:
            captured["method"] = req.method
            captured["url"] = str(req.url)
            captured["authorization"] = req.headers.get("authorization")
            captured["content_type"] = req.headers.get("content-type")
            captured["accept"] = req.headers.get("accept")
            captured["body"] = req.content.decode("utf-8")
            return httpx.Response(202, json=PUBLISH_BODY)

        transport = httpx.MockTransport(handler)
        async with Label309Client(
            api_key=parity_key,
            base_url="http://test.example/api/v1",
            http_client=httpx.AsyncClient(transport=transport),
        ) as client:
            # 16 bytes of canonical-CBOR-shaped placeholder — the fixture only
            # pins wire shape, not record contents.
            await client.poe.publish(record="aa" * 16, quote_id=QUOTE_ID)

        fixture_path = (
            Path(__file__).parent / "fixtures" / "poe-request" / "poe-publish-request.json"
        )
        fixture = json.loads(fixture_path.read_text("utf-8"))

        assert captured["method"] == fixture["method"]
        assert captured["url"] == fixture["url"]
        assert captured["authorization"] == fixture["authorization"]
        assert captured["content_type"] == fixture["content_type"]
        assert captured["accept"] == fixture["accept"]
        assert captured["body"] == fixture["body"]

    asyncio.run(run())


def test_quote_parses_optional_breakdown_when_present() -> None:
    # A gateway that exposes its pricing internals returns the breakdown
    # fields alongside the core four; the SDK surfaces them additively.
    async def run() -> None:
        breakdown_body: dict[str, Any] = {
            "quote_id": QUOTE_ID,
            "amount": "180000",
            "currency": "USD",
            "expires_at": "2026-05-26T12:15:00.000Z",
            "usd_micros": "180000",
            "breakdown": {
                "network_usd_micros": "100000",
                "storage_usd_micros": "60000",
                "service_usd_micros": "20000",
            },
            "margin_pct": 12.5,
            "margin_source": "override",
            "fx_age_seconds": 42,
        }

        def handler(_req: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json=breakdown_body)

        async with _client_with_handler(handler) as client:
            out = await client.poe.quote(
                record_bytes=256, recipient_count=1, file_bytes_total=1_048_576
            )
        # Core fields plus the optional breakdown all survive.
        assert out["quote_id"] == QUOTE_ID
        assert out["usd_micros"] == "180000"
        assert out["breakdown"]["network_usd_micros"] == "100000"
        assert out["breakdown"]["storage_usd_micros"] == "60000"
        assert out["breakdown"]["service_usd_micros"] == "20000"
        assert out["margin_pct"] == 12.5
        assert out["margin_source"] == "override"
        assert out["fx_age_seconds"] == 42

    asyncio.run(run())
