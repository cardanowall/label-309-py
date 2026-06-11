from __future__ import annotations

import asyncio
from typing import Any

import httpx
import pytest

from cardanowall.verifier import (
    DEFAULT_OUTBOUND_MAX_BYTES,
    BodyTooLargeError,
    DenyHostError,
    FetchOutboundOptions,
    FetchOutboundResult,
    HttpCallRecord,
    OutboundExhaustedError,
    UnsupportedMethodError,
    UnsupportedProtocolError,
    wrap_fetch_outbound,
)
from cardanowall.verifier.fetch import matches_deny_list


def test_matches_deny_list_exact() -> None:
    assert matches_deny_list("operator.example", ["operator.example"]) is True
    assert matches_deny_list("other.com", ["operator.example"]) is False


def test_matches_deny_list_glob_subdomain() -> None:
    assert matches_deny_list("api.operator.example", ["*.operator.example"]) is True
    # Bare host does NOT match glob.
    assert matches_deny_list("operator.example", ["*.operator.example"]) is False


def test_matches_deny_list_case_insensitive_trailing_dot() -> None:
    assert matches_deny_list("OPERATOR.EXAMPLE.", ["operator.example"]) is True


# --- IP-literal expansion -----------------------------------------------------


def test_matches_deny_list_ipv6_loopback() -> None:
    assert matches_deny_list("[::1]", ["localhost"]) is True
    assert matches_deny_list("::1", ["localhost"]) is True


def test_matches_deny_list_zero_zero_zero_zero() -> None:
    assert matches_deny_list("0.0.0.0", ["localhost"]) is True  # noqa: S104


def test_matches_deny_list_127_subnet() -> None:
    assert matches_deny_list("127.1.2.3", ["127.0.0.1"]) is True
    assert matches_deny_list("127.99.0.5", ["127.0.0.1"]) is True


def test_matches_deny_list_metadata_ip() -> None:
    assert matches_deny_list("169.254.169.254", ["localhost"]) is True


def test_matches_deny_list_8_8_8_8_not_blocked() -> None:
    assert matches_deny_list("8.8.8.8", ["localhost", "127.0.0.1"]) is False


# --- success + failure rows ---------------------------------------------------


async def _ok_inner(url: str, opts: FetchOutboundOptions) -> FetchOutboundResult:
    return FetchOutboundResult(status=200, bytes=b"hello", duration_ms=5)


async def _raise_inner(url: str, opts: FetchOutboundOptions) -> FetchOutboundResult:
    raise RuntimeError("boom")


def test_wrap_records_success_row() -> None:
    audit: list[HttpCallRecord] = []
    wrapped = wrap_fetch_outbound(_ok_inner, audit)
    result = asyncio.run(
        wrapped("https://example.com/x", FetchOutboundOptions(method="GET", purpose="cardano"))
    )
    assert result.status == 200
    assert len(audit) == 1
    assert audit[0].status == 200
    assert audit[0].bytes == 5
    assert audit[0].purpose == "cardano"


def test_wrap_records_failure_row() -> None:
    audit: list[HttpCallRecord] = []
    wrapped = wrap_fetch_outbound(_raise_inner, audit)
    with pytest.raises(RuntimeError):
        asyncio.run(
            wrapped("https://example.com/x", FetchOutboundOptions(method="GET", purpose="cardano"))
        )
    assert len(audit) == 1
    assert audit[0].status is None
    assert audit[0].bytes == 0


# --- deny-host ---------------------------------------------------------------


def test_wrap_deny_host_short_circuit() -> None:
    audit: list[HttpCallRecord] = []
    wrapped = wrap_fetch_outbound(_ok_inner, audit, deny_hosts=("operator.example",))
    with pytest.raises(DenyHostError) as exc:
        asyncio.run(
            wrapped(
                "https://operator.example/x",
                FetchOutboundOptions(method="GET", purpose="cardano"),
            )
        )
    assert exc.value.host == "operator.example"
    assert exc.value.code == "SERVICE_INDEPENDENCE_VIOLATION"
    assert len(audit) == 1
    assert audit[0].status is None
    assert audit[0].duration_ms == 0


# --- protocol allowlist ------------------------------------------------------


def test_wrap_rejects_data_url_with_UnsupportedProtocolError() -> None:
    audit: list[HttpCallRecord] = []
    wrapped = wrap_fetch_outbound(_ok_inner, audit)
    with pytest.raises(UnsupportedProtocolError) as exc:
        asyncio.run(
            wrapped(
                "data:text/plain;base64,SGVsbG8=",
                FetchOutboundOptions(method="GET", purpose="cardano"),
            )
        )
    assert exc.value.code == "UNSUPPORTED_PROTOCOL"
    assert exc.value.protocol == "data:"
    assert len(audit) == 1
    assert audit[0].status is None


def test_wrap_rejects_file_url_with_UnsupportedProtocolError() -> None:
    audit: list[HttpCallRecord] = []
    wrapped = wrap_fetch_outbound(_ok_inner, audit)
    with pytest.raises(UnsupportedProtocolError):
        asyncio.run(
            wrapped(
                "file:///etc/passwd",
                FetchOutboundOptions(method="GET", purpose="cardano"),
            )
        )


# --- method allowlist --------------------------------------------------------


def test_wrap_rejects_put_method_with_UnsupportedMethodError() -> None:
    audit: list[HttpCallRecord] = []
    wrapped = wrap_fetch_outbound(_ok_inner, audit)
    with pytest.raises(UnsupportedMethodError) as exc:
        asyncio.run(
            wrapped(
                "https://example.com/x",
                FetchOutboundOptions(method="PUT", purpose="cardano"),  # type: ignore[arg-type]
            )
        )
    assert exc.value.code == "UNSUPPORTED_METHOD"
    assert exc.value.method == "PUT"
    assert len(audit) == 1


# --- retry / backoff ---------------------------------------------------------


def test_wrap_retries_on_503_then_succeeds_on_200(monkeypatch: pytest.MonkeyPatch) -> None:
    sleeps: list[float] = []

    async def fake_sleep(s: float) -> None:
        sleeps.append(s)

    monkeypatch.setattr("cardanowall.verifier.fetch.asyncio.sleep", fake_sleep)
    monkeypatch.setattr("cardanowall.verifier.fetch.random.random", lambda: 0.5)

    call_count = {"n": 0}

    async def inner(url: str, opts: FetchOutboundOptions) -> FetchOutboundResult:
        call_count["n"] += 1
        if call_count["n"] == 1:
            return FetchOutboundResult(status=503, bytes=b"", duration_ms=1)
        return FetchOutboundResult(status=200, bytes=b"ok", duration_ms=1)

    audit: list[HttpCallRecord] = []
    wrapped = wrap_fetch_outbound(inner, audit, retries=3)
    result = asyncio.run(
        wrapped("https://example.com/", FetchOutboundOptions(method="GET", purpose="cardano"))
    )
    assert result.status == 200
    assert len(audit) == 2
    assert audit[0].status == 503
    assert audit[1].status == 200
    assert len(sleeps) == 1
    # baseline 1.0s with jitter at 0.5 (random.random()==0.5 → jitter==1.0).
    assert sleeps[0] == pytest.approx(1.0, abs=0.01)


def test_wrap_retries_exhausted_raises_OutboundExhaustedError(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def fake_sleep(s: float) -> None:
        return None

    monkeypatch.setattr("cardanowall.verifier.fetch.asyncio.sleep", fake_sleep)

    async def inner(url: str, opts: FetchOutboundOptions) -> FetchOutboundResult:
        return FetchOutboundResult(status=503, bytes=b"", duration_ms=1)

    audit: list[HttpCallRecord] = []
    wrapped = wrap_fetch_outbound(inner, audit, retries=3)
    with pytest.raises(OutboundExhaustedError) as exc:
        asyncio.run(
            wrapped("https://example.com/", FetchOutboundOptions(method="GET", purpose="cardano"))
        )
    assert exc.value.code == "OUTBOUND_EXHAUSTED"
    assert exc.value.attempts == 4
    assert exc.value.last_status == 503
    assert len(audit) == 4


def test_wrap_backoff_uses_asyncio_sleep_with_jittered_values(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sleeps: list[float] = []

    async def fake_sleep(s: float) -> None:
        sleeps.append(s)

    monkeypatch.setattr("cardanowall.verifier.fetch.asyncio.sleep", fake_sleep)

    async def inner(url: str, opts: FetchOutboundOptions) -> FetchOutboundResult:
        return FetchOutboundResult(status=503, bytes=b"", duration_ms=1)

    audit: list[HttpCallRecord] = []
    wrapped = wrap_fetch_outbound(inner, audit, retries=3)
    with pytest.raises(OutboundExhaustedError):
        asyncio.run(
            wrapped("https://example.com/", FetchOutboundOptions(method="GET", purpose="cardano"))
        )
    # Three sleeps (before attempts 2, 3, 4) — baselines 1.0, 2.0, 4.0 s ±25%.
    assert len(sleeps) == 3
    baselines = (1.0, 2.0, 4.0)
    for actual, base in zip(sleeps, baselines, strict=True):
        assert base * 0.75 <= actual <= base * 1.25


def test_wrap_timeout_attempt_is_retried(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_sleep(s: float) -> None:
        return None

    monkeypatch.setattr("cardanowall.verifier.fetch.asyncio.sleep", fake_sleep)

    async def inner(url: str, opts: FetchOutboundOptions) -> FetchOutboundResult:
        raise httpx.TimeoutException("timeout")

    audit: list[HttpCallRecord] = []
    wrapped = wrap_fetch_outbound(inner, audit, retries=3)
    with pytest.raises(OutboundExhaustedError) as exc:
        asyncio.run(
            wrapped("https://example.com/", FetchOutboundOptions(method="GET", purpose="cardano"))
        )
    assert exc.value.attempts == 4
    assert isinstance(exc.value.last_error, httpx.TimeoutException)
    assert len(audit) == 4


# --- Default fetch via MockTransport (existing) ------------------------------


def test_default_fetch_via_mock_transport() -> None:
    from cardanowall.verifier.fetch import default_fetch_outbound

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"mocked")

    transport = httpx.MockTransport(handler)

    # Inject MockTransport by monkey-patching httpx.AsyncClient default.
    original = httpx.AsyncClient.__init__

    def patched_init(self: httpx.AsyncClient, *args: Any, **kwargs: Any) -> None:
        kwargs["transport"] = transport
        original(self, *args, **kwargs)

    httpx.AsyncClient.__init__ = patched_init  # type: ignore[method-assign]
    try:
        result = asyncio.run(
            default_fetch_outbound(
                "https://test/", FetchOutboundOptions(method="GET", purpose="cardano")
            )
        )
    finally:
        httpx.AsyncClient.__init__ = original  # type: ignore[method-assign]
    assert result.status == 200
    assert result.bytes == b"mocked"


# --- Response-size cap (OOM defence against hostile gateways) -----------------


def _run_with_mock_transport(
    handler: Any, url: str, opts: FetchOutboundOptions
) -> FetchOutboundResult:
    from cardanowall.verifier.fetch import default_fetch_outbound

    transport = httpx.MockTransport(handler)
    original = httpx.AsyncClient.__init__

    def patched_init(self: httpx.AsyncClient, *args: Any, **kwargs: Any) -> None:
        kwargs["transport"] = transport
        original(self, *args, **kwargs)

    httpx.AsyncClient.__init__ = patched_init  # type: ignore[method-assign]
    try:
        return asyncio.run(default_fetch_outbound(url, opts))
    finally:
        httpx.AsyncClient.__init__ = original  # type: ignore[method-assign]


def test_default_outbound_max_bytes_constant() -> None:
    # 64 MiB — documented in fetch.py. Pinned so a regression that silently drops
    # the cap (back to unbounded) is caught, and to assert TS/Python parity.
    assert DEFAULT_OUTBOUND_MAX_BYTES == 64 * 1024 * 1024


def test_body_over_cap_raises_body_too_large() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        # 4 KiB body, but the caller caps at 1 KiB.
        return httpx.Response(200, content=b"x" * 4096)

    with pytest.raises(BodyTooLargeError) as exc:
        _run_with_mock_transport(
            handler,
            "https://gw.example/blob",
            FetchOutboundOptions(method="GET", purpose="arweave", max_bytes=1024),
        )
    assert exc.value.code == "OUTBOUND_BODY_TOO_LARGE"
    assert exc.value.limit_bytes == 1024


def test_content_length_over_cap_raises_before_reading_body() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"content-length": "999999"},
            content=b"x" * 8,  # actual body is tiny; the declared length lies big
        )

    with pytest.raises(BodyTooLargeError):
        _run_with_mock_transport(
            handler,
            "https://gw.example/blob",
            FetchOutboundOptions(method="GET", purpose="arweave", max_bytes=1024),
        )


def test_body_at_or_under_cap_returns_full_body() -> None:
    payload = b"y" * 1024

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=payload)

    result = _run_with_mock_transport(
        handler,
        "https://gw.example/ok",
        FetchOutboundOptions(method="GET", purpose="arweave", max_bytes=1024),
    )
    assert result.status == 200
    assert result.bytes == payload
