from __future__ import annotations

import asyncio
import random
import re
import time
from collections.abc import Sequence
from typing import Final
from urllib.parse import urlparse

import httpx

from .types import (
    FetchOutbound,
    FetchOutboundOptions,
    FetchOutboundResult,
    HttpCallRecord,
    VerifyUriCheck,
)

DEFAULT_TIMEOUT_MS: Final[int] = 10_000
DEFAULT_RETRIES: Final[int] = 3
DEFAULT_RETRYABLE_STATUSES: Final[tuple[int, ...]] = (502, 503, 504)
BACKOFF_BASE_MS: Final[tuple[int, ...]] = (1000, 2000, 4000)
JITTER_RATIO: Final[float] = 0.25
# Default response-body cap for the verifier's gateway fetches. 64 MiB sits well
# above any single sealed-PoE ciphertext or merkle-leaf payload a verifier would
# realistically recompute a hash over, while bounding the memory a hostile
# gateway can force the verifier to allocate for one request. Callers that
# legitimately handle larger content raise it per-call via opts.max_bytes.
DEFAULT_OUTBOUND_MAX_BYTES: Final[int] = 64 * 1024 * 1024

_LOOPBACK_127_RE: Final[re.Pattern[str]] = re.compile(r"^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$")

# Default Arweave gateway rotation. Tried in order; the first 200 wins.
ARWEAVE_DEFAULTS: Final[tuple[str, ...]] = (
    "https://arweave.net",
    "https://ar-io.net",
    "https://g8way.io",
)

_ARWEAVE_TXID_RE: Final[re.Pattern[str]] = re.compile(r"^[A-Za-z0-9_-]{43}$")
_URI_FETCH_SET_RE: Final[re.Pattern[str]] = re.compile(r"^(ar|ipfs)://")


class DenyHostError(Exception):
    code: Final[str] = "SERVICE_INDEPENDENCE_VIOLATION"

    def __init__(self, host: str, url: str) -> None:
        super().__init__(
            f"SERVICE_INDEPENDENCE_VIOLATION: host '{host}' is in denyHosts (url={url})"
        )
        self.host: str = host
        self.url: str = url


class UnsupportedProtocolError(Exception):
    code: Final[str] = "UNSUPPORTED_PROTOCOL"

    def __init__(self, protocol: str, url: str) -> None:
        super().__init__(f"UNSUPPORTED_PROTOCOL: '{protocol}' not in {{http, https}} (url={url})")
        self.protocol: str = protocol
        self.url: str = url


class UnsupportedMethodError(Exception):
    code: Final[str] = "UNSUPPORTED_METHOD"

    def __init__(self, method: str, url: str) -> None:
        super().__init__(f"UNSUPPORTED_METHOD: '{method}' not in {{GET, POST}} (url={url})")
        self.method: str = method
        self.url: str = url


class BodyTooLargeError(Exception):
    code: Final[str] = "OUTBOUND_BODY_TOO_LARGE"

    def __init__(self, url: str, limit_bytes: int) -> None:
        super().__init__(
            f"OUTBOUND_BODY_TOO_LARGE: response exceeded {limit_bytes} bytes (url={url})"
        )
        self.url: str = url
        self.limit_bytes: int = limit_bytes


class OutboundExhaustedError(Exception):
    code: Final[str] = "OUTBOUND_EXHAUSTED"

    def __init__(
        self,
        url: str,
        attempts: int,
        last_status: int | None = None,
        last_error: BaseException | None = None,
    ) -> None:
        last_status_str = str(last_status) if last_status is not None else "-"
        super().__init__(
            f"OUTBOUND_EXHAUSTED: {attempts} attempts exhausted "
            f"(url={url}, last_status={last_status_str})"
        )
        self.url: str = url
        self.attempts: int = attempts
        self.last_status: int | None = last_status
        self.last_error: BaseException | None = last_error


def _canonicalise_host(host: str) -> str:
    h = host
    if h.startswith("["):
        h = h[1:]
    if h.endswith("]"):
        h = h[:-1]
    return h.rstrip(".").lower()


def matches_deny_list(host: str, deny: Sequence[str]) -> bool:
    h = _canonicalise_host(host)
    for raw in deny:
        pat = raw.rstrip(".").lower()
        if pat.startswith("*."):
            suffix = pat[2:]
            if h.endswith("." + suffix):
                return True
            continue
        if h == pat:
            return True
        if pat == "localhost" and h in ("::1", "0.0.0.0", "169.254.169.254"):  # noqa: S104
            return True
        if pat == "127.0.0.1" and _LOOPBACK_127_RE.fullmatch(h):
            return True
    return False


def _is_allowed_protocol(url: str) -> bool:
    try:
        scheme = urlparse(url).scheme.lower()
    except ValueError:
        return False
    return scheme in ("http", "https")


def _is_allowed_method(method: str) -> bool:
    return method in ("GET", "POST")


def _backoff_jittered_ms(attempt_index: int) -> float:
    idx = min(attempt_index, len(BACKOFF_BASE_MS) - 1)
    base = BACKOFF_BASE_MS[idx]
    jitter = 1.0 + (random.random() - 0.5) * 2 * JITTER_RATIO  # noqa: S311 non-crypto jitter
    return base * jitter


def wrap_fetch_outbound(
    inner: FetchOutbound,
    audit: list[HttpCallRecord],
    deny_hosts: Sequence[str] | None = None,
    *,
    retries: int = 0,
    timeout_ms: int = DEFAULT_TIMEOUT_MS,
    retryable_statuses: Sequence[int] = DEFAULT_RETRYABLE_STATUSES,
) -> FetchOutbound:
    # Per-request timeout is enforced inside default_fetch_outbound; accepted
    # here for signature parity with the TS wrapper.
    del timeout_ms

    async def wrapped(url: str, opts: FetchOutboundOptions) -> FetchOutboundResult:
        purpose = opts.purpose

        # Protocol allowlist.
        if not _is_allowed_protocol(url):
            try:
                scheme = urlparse(url).scheme
            except ValueError:
                scheme = ""
            audit.append(
                HttpCallRecord(
                    url=url, method="GET", status=0, bytes=0, duration_ms=0, purpose=purpose
                )
            )
            raise UnsupportedProtocolError(protocol=f"{scheme}:" if scheme else "", url=url)

        # Method allowlist.
        if not _is_allowed_method(opts.method):
            audit.append(
                HttpCallRecord(
                    url=url, method="GET", status=0, bytes=0, duration_ms=0, purpose=purpose
                )
            )
            raise UnsupportedMethodError(method=opts.method, url=url)

        # Deny-list short-circuit (covers literal hosts and IP-literal forms).
        if deny_hosts:
            try:
                host = urlparse(url).hostname or ""
            except ValueError:
                audit.append(
                    HttpCallRecord(
                        url=url,
                        method=opts.method,
                        status=0,
                        bytes=0,
                        duration_ms=0,
                        purpose=purpose,
                    )
                )
                raise
            if matches_deny_list(host, deny_hosts):
                audit.append(
                    HttpCallRecord(
                        url=url,
                        method=opts.method,
                        status=0,
                        bytes=0,
                        duration_ms=0,
                        purpose=purpose,
                    )
                )
                raise DenyHostError(host=_canonicalise_host(host), url=url)

        # Retry loop.
        last_status: int | None = None
        last_error: BaseException | None = None
        total_attempts = retries + 1
        for attempt in range(1, total_attempts + 1):
            t0_ms = int(time.monotonic() * 1000)
            try:
                result = await inner(url, opts)
            except (DenyHostError, UnsupportedProtocolError, UnsupportedMethodError) as e:
                duration_ms = int(time.monotonic() * 1000) - t0_ms
                audit.append(
                    HttpCallRecord(
                        url=url,
                        method=opts.method,
                        status=0,
                        bytes=0,
                        duration_ms=duration_ms,
                        purpose=purpose,
                    )
                )
                raise e
            except BaseException as e:
                duration_ms = int(time.monotonic() * 1000) - t0_ms
                audit.append(
                    HttpCallRecord(
                        url=url,
                        method=opts.method,
                        status=0,
                        bytes=0,
                        duration_ms=duration_ms,
                        purpose=purpose,
                    )
                )
                last_error = e
                if attempt < total_attempts:
                    await asyncio.sleep(_backoff_jittered_ms(attempt - 1) / 1000)
                    continue
                break
            else:
                audit.append(
                    HttpCallRecord(
                        url=url,
                        method=opts.method,
                        status=result.status,
                        bytes=len(result.bytes),
                        duration_ms=result.duration_ms,
                        purpose=purpose,
                    )
                )
                if result.status in retryable_statuses and retries > 0:
                    last_status = result.status
                    if attempt < total_attempts:
                        await asyncio.sleep(_backoff_jittered_ms(attempt - 1) / 1000)
                        continue
                    break
                return result

        # Single-attempt mode re-raises the original verbatim so callers can
        # match by type; retry mode wraps the terminal failure in OutboundExhaustedError.
        if retries == 0 and last_error is not None:
            raise last_error
        raise OutboundExhaustedError(
            url=url, attempts=total_attempts, last_status=last_status, last_error=last_error
        )

    return wrapped


async def default_fetch_outbound(url: str, opts: FetchOutboundOptions) -> FetchOutboundResult:
    t0 = time.monotonic()
    headers = dict(opts.headers) if opts.headers else {}
    max_bytes = opts.max_bytes if opts.max_bytes is not None else DEFAULT_OUTBOUND_MAX_BYTES
    content = opts.body.encode("utf-8") if opts.method == "POST" and opts.body else None
    async with httpx.AsyncClient(timeout=DEFAULT_TIMEOUT_MS / 1000) as client:
        # Stream the body so a hostile gateway cannot make us buffer unbounded
        # bytes. `client.stream` leaves the body unread until we iterate it; we
        # stop and tear the connection down the instant the running count exceeds
        # the cap (the underlying socket is closed when we leave the context).
        async with client.stream(opts.method, url, headers=headers, content=content) as res:
            # Fast path: a truthful Content-Length over the cap lets us bail
            # before reading a single body byte. A lying/absent header is still
            # caught by the streaming counter below.
            declared = res.headers.get("content-length")
            if declared is not None:
                try:
                    declared_len = int(declared)
                except ValueError:
                    declared_len = -1
                if declared_len > max_bytes:
                    raise BodyTooLargeError(url, max_bytes)

            chunks: list[bytes] = []
            total = 0
            async for chunk in res.aiter_bytes():
                total += len(chunk)
                if total > max_bytes:
                    raise BodyTooLargeError(url, max_bytes)
                chunks.append(chunk)
            body = b"".join(chunks)
            status = res.status_code
    duration_ms = int((time.monotonic() - t0) * 1000)
    return FetchOutboundResult(status=status, bytes=body, duration_ms=duration_ms)


class UriTargetForbiddenError(Exception):
    """Raised when none of the reconstructed URIs name an in-set retrieval
    scheme (`ar://` / `ipfs://`). Such a URI should already have been rejected
    by structural validation; rejecting it here too is defence-in-depth."""

    code: Final[str] = "URI_TARGET_FORBIDDEN"


class ContentUnavailableError(Exception):
    """Raised when an in-set URI was selected but no configured gateway could
    return its bytes (every gateway in the chain was exhausted, the Arweave
    txid was malformed, or no IPFS gateway chain was supplied)."""

    code: Final[str] = "CONTENT_UNAVAILABLE"


async def fetch_item_ciphertext(
    *,
    uris: Sequence[Sequence[str]],
    fetch_fn: FetchOutbound,
    uri_checks_out: list[VerifyUriCheck],
    item_index: int,
    arweave_gateways: Sequence[str] | None = None,
    ipfs_gateways: Sequence[str] | None = None,
) -> bytes:
    """Reconstruct the first in-set URI from a chunked ``uris[]`` list, fetch it
    over the appropriate gateway chain, and return the raw bytes.

    ``uris`` is the record-item (or merkle-entry) URI list: a list of chunk
    arrays, each of which reconstructs to one absolute URI. The first URI whose
    scheme is in the closed v1 fetch set (``ar://`` → Arweave HTTPS rotation,
    ``ipfs://`` → caller-supplied IPFS rotation) is selected. Each gateway
    attempt appends one ``VerifyUriCheck`` to ``uri_checks_out``: a failed attempt
    records ``ok=False`` with the failure reason, the winning attempt records
    ``ok=True``.

    Returns the bytes of the first gateway response with status 200. Individual
    gateway failures are non-terminal (the chain advances); a fully exhausted
    chain raises :class:`ContentUnavailableError` so the caller can emit the
    terminal verdict. A URI with no in-set scheme raises
    :class:`UriTargetForbiddenError`.
    """
    reconstructed = ["".join(chunks) for chunks in uris]
    candidate = next((u for u in reconstructed if _URI_FETCH_SET_RE.match(u)), None)
    if candidate is None:
        # No in-set URI present — defence-in-depth rejection.
        for u in reconstructed:
            uri_checks_out.append(
                VerifyUriCheck(
                    item_index=item_index, uri=u, ok=False, reason="URI_TARGET_FORBIDDEN"
                )
            )
        raise UriTargetForbiddenError("no in-set URI scheme in uris[]")

    if candidate.startswith("ar://"):
        txid = candidate[5:]
        if not _ARWEAVE_TXID_RE.match(txid):
            uri_checks_out.append(
                VerifyUriCheck(
                    item_index=item_index, uri=candidate, ok=False, reason="CONTENT_UNAVAILABLE"
                )
            )
            raise ContentUnavailableError(f"malformed arweave txid: {txid}")
        gateways: Sequence[str] = (
            arweave_gateways if arweave_gateways and len(arweave_gateways) > 0 else ARWEAVE_DEFAULTS
        )
        for gw in gateways:
            try:
                res = await fetch_fn(
                    f"{gw}/{txid}", FetchOutboundOptions(method="GET", purpose="arweave")
                )
                if res.status == 200:
                    uri_checks_out.append(
                        VerifyUriCheck(item_index=item_index, uri=candidate, ok=True)
                    )
                    return res.bytes
                uri_checks_out.append(
                    VerifyUriCheck(
                        item_index=item_index,
                        uri=candidate,
                        ok=False,
                        reason="URI_FETCH_FAILED",
                    )
                )
            except Exception:
                uri_checks_out.append(
                    VerifyUriCheck(
                        item_index=item_index,
                        uri=candidate,
                        ok=False,
                        reason="URI_FETCH_FAILED",
                    )
                )
        raise ContentUnavailableError("all arweave gateways exhausted")

    # ipfs:// — the caller MUST configure an IPFS gateway chain. There is no
    # baked-in default: IPFS gateways are not the producer's storage provider,
    # and a silent fallback would couple the verifier to an off-record gateway.
    cid_part = candidate[len("ipfs://") :]
    ipfs_cid = cid_part.split("/", 1)[0] or cid_part
    if not ipfs_gateways or len(ipfs_gateways) == 0:
        uri_checks_out.append(
            VerifyUriCheck(
                item_index=item_index, uri=candidate, ok=False, reason="CONTENT_UNAVAILABLE"
            )
        )
        raise ContentUnavailableError("no ipfs gateway configured")
    for gw in ipfs_gateways:
        try:
            sep = "" if gw.endswith("/") else "/"
            url = f"{gw}{sep}ipfs/{ipfs_cid}"
            res = await fetch_fn(url, FetchOutboundOptions(method="GET", purpose="ipfs"))
            if res.status == 200:
                uri_checks_out.append(VerifyUriCheck(item_index=item_index, uri=candidate, ok=True))
                return res.bytes
            uri_checks_out.append(
                VerifyUriCheck(
                    item_index=item_index, uri=candidate, ok=False, reason="URI_FETCH_FAILED"
                )
            )
        except Exception:
            uri_checks_out.append(
                VerifyUriCheck(
                    item_index=item_index, uri=candidate, ok=False, reason="URI_FETCH_FAILED"
                )
            )
    raise ContentUnavailableError("all ipfs gateways exhausted")
