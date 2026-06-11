"""Outbound HTTP egress and content acquisition with attribution.

Two layers live here:

1. The canonical egress wrapper (``wrap_fetch_outbound`` around
   ``default_fetch_outbound``): deny-list short-circuit, protocol/method
   allowlist, bounded timeout, exp-backoff retry with jitter, and the audit
   trail — every outbound call of a verification run (success, failure,
   retry) is recorded through this single function, so the report can prove
   service-independence.

2. The shared content-acquisition engine (``iterate_blob_sources``) behind
   the three fetching consumers — plain-item digests, Merkle leaves-lists,
   and sealed ciphertext. Multiple URIs are alternative sources for the same
   bytes, processed first-success-for-availability: sources are yielded in
   order (caller-supplied out-of-band bytes first, then each URI against its
   scheme's gateway chain) and the consumer stops at the first source
   satisfying its claim. Every yielded blob knows its ATTRIBUTION — whether
   the bytes are bound to the URI's content address (or were supplied
   out-of-band) — which decides whether a mismatch condemns the record or
   merely indicts the serving provider:

     - out-of-band bytes            -> attributable;
     - ipfs:// raw-codec CIDv1      -> attributable iff the multihash
                                       recompute over the fetched bytes
                                       verifies;
     - everything else fetched      -> unattributable (no binding check
                                       implemented for ar:// L1 / ANS-104 or
                                       DAG-form CIDs), so mismatches route
                                       through URI_PROVIDER_INTEGRITY_MISMATCH.

   Per-attempt diagnostics land in the issue sink (URI_FETCH_FAILED
   warnings, URI_TARGET_FORBIDDEN refusals, SERVICE_INDEPENDENCE_VIOLATION
   on a denied host), each at the claim's ``uris[j]`` path; the per-claim
   END-state (CONTENT_UNAVAILABLE vs CONTENT_FETCH_LIMIT_EXCEEDED vs the
   claim-specific availability code) is the consumer's to emit, with
   ``flags.limit_exceeded`` recording whether an attempt aborted at the
   ``max_fetch_bytes`` ceiling. A ceiling abort ENDS the claim: every URI of
   a claim addresses the same bytes, so any other honest source would abort
   at the same ceiling.
"""

from __future__ import annotations

import asyncio
import random
import re
import time
from collections.abc import AsyncIterator, Sequence
from dataclasses import dataclass
from typing import Final
from urllib.parse import urlparse

import httpx

from .content_binding import verify_ipfs_cid_binding
from .types import (
    FetchOutbound,
    FetchOutboundOptions,
    FetchOutboundResult,
    HttpCallRecord,
    IssueSink,
    Purpose,
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

# Default Arweave gateway rotation, tried in order; the first 200 wins. IPFS
# has NO baked-in default: IPFS gateways are not the producer's storage
# provider, and a silent fallback would couple the verifier to an off-record
# gateway — a deployment that fetches ipfs:// must configure its own chain,
# and one that does not is a deployment that declines IPFS
# (URI_TARGET_FORBIDDEN at fetch time).
ARWEAVE_GATEWAY_DEFAULTS: Final[tuple[str, ...]] = (
    "https://arweave.net",
    "https://ar-io.net",
    "https://g8way.io",
)

_ARWEAVE_TXID_RE: Final[re.Pattern[str]] = re.compile(r"^[A-Za-z0-9_-]{43}$")


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
    # here for signature parity with the TypeScript wrapper.
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
                    url=url, method="GET", status=None, bytes=0, duration_ms=0, purpose=purpose
                )
            )
            raise UnsupportedProtocolError(protocol=f"{scheme}:" if scheme else "", url=url)

        # Method allowlist.
        if not _is_allowed_method(opts.method):
            audit.append(
                HttpCallRecord(
                    url=url, method="GET", status=None, bytes=0, duration_ms=0, purpose=purpose
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
                        status=None,
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
                        status=None,
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
                        status=None,
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
                        status=None,
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


# -----------------------------------------------------------------------------
# Claim-level content acquisition (the shared engine behind items / merkle /
# ciphertext fetching)
# -----------------------------------------------------------------------------


@dataclass(frozen=True, kw_only=True)
class ContentFetchContext:
    """The per-run fetch configuration shared by every content-acquiring
    pipeline step, plus the run's issue sink."""

    fetch_fn: FetchOutbound
    arweave_gateways: tuple[str, ...]
    ipfs_gateways: tuple[str, ...]
    issues: IssueSink
    max_fetch_bytes: int | None = None


@dataclass(kw_only=True)
class AcquiredBlob:
    """One candidate byte string for a claim, plus its content-address
    attribution. ``attributable`` is computed lazily and memoised: the digest
    work only runs when a consumer actually needs attribution, i.e. on the
    mismatch path — bytes that satisfy the record's own commitment never need
    it (the record's commitment is at least as strong as the storage
    layer's)."""

    bytes: bytes
    source: str  # "out_of_band" | "fetched"
    uri: str | None = None
    uri_index: int | None = None
    _binding: str | None = None  # "verified" | "failed" | "unsupported"
    _cid: str | None = None
    _cid_path: str = ""

    def attributable(self) -> bool:
        if self._binding is None:
            if self.source == "out_of_band":
                self._binding = "verified"
            elif self._cid is not None:
                self._binding = verify_ipfs_cid_binding(
                    cid=self._cid, path=self._cid_path, data=self.bytes
                )
            else:
                self._binding = "unsupported"
        return self._binding == "verified"


@dataclass
class BlobIterationFlags:
    limit_exceeded: bool = False


@dataclass(frozen=True)
class _ParsedFetchUri:
    scheme: str  # "ar" | "ipfs"
    address: str  # ar: the txid. ipfs: the CID (authority).
    path: str  # ipfs only: the '/'-prefixed path within the DAG, '' when absent.


_URI_SCHEME_RE: Final[re.Pattern[str]] = re.compile(r"^([A-Za-z][A-Za-z0-9+.-]*)://")


# Scheme matching is case-insensitive (the scheme alone is folded); the
# remainder of the URI is a case-sensitive content address and is used
# verbatim.
def _parse_fetch_uri(uri: str) -> _ParsedFetchUri | None:
    m = _URI_SCHEME_RE.match(uri)
    if m is None:
        return None
    scheme = m.group(1).lower()
    rest = uri[m.end() :]
    if scheme == "ar":
        if not _ARWEAVE_TXID_RE.fullmatch(rest):
            return None
        return _ParsedFetchUri(scheme="ar", address=rest, path="")
    if scheme == "ipfs":
        slash = rest.find("/")
        if slash == -1:
            return _ParsedFetchUri(scheme="ipfs", address=rest, path="")
        return _ParsedFetchUri(scheme="ipfs", address=rest[:slash], path=rest[slash:])
    return None


def _join_gateway(base: str, suffix: str) -> str:
    return f"{base}{suffix}" if base.endswith("/") else f"{base}/{suffix}"


async def iterate_blob_sources(
    *,
    uris: Sequence[str],
    allow_fetch: bool,
    base_path: tuple[str | int, ...],
    ctx: ContentFetchContext,
    flags: BlobIterationFlags,
    out_of_band: bytes | None = None,
) -> AsyncIterator[AcquiredBlob]:
    """Yield candidate blobs for one claim, in source order: caller-supplied
    out-of-band bytes first, then (when ``allow_fetch``) each URI in record
    order against its scheme's gateway chain, first 200 per URI. The consumer
    breaks out at the first acceptable blob; exhaustion of the generator means
    the claim is left unchecked and the consumer emits the applicable
    availability end-state."""
    if out_of_band is not None:
        yield AcquiredBlob(bytes=out_of_band, source="out_of_band")
    if not allow_fetch:
        return

    for uri_index, uri in enumerate(uris):
        uri_path: tuple[str | int, ...] = (*base_path, "uris", uri_index)
        parsed = _parse_fetch_uri(uri)
        if parsed is None:
            # Defence-in-depth: a target outside the closed fetch set can only
            # reach here by bypassing structural validation.
            ctx.issues.add(
                "URI_TARGET_FORBIDDEN",
                uri_path,
                f'refusing to fetch "{uri}": not a conformant ar:// or ipfs:// content address',
            )
            continue

        purpose: Purpose
        if parsed.scheme == "ar":
            gateways: Sequence[str] = ctx.arweave_gateways
            suffix = parsed.address
            purpose = "arweave"
        else:
            gateways = ctx.ipfs_gateways
            suffix = f"ipfs/{parsed.address}{parsed.path}"
            purpose = "ipfs"
            if len(gateways) == 0:
                # This deployment declines every IPFS fetch — a policy
                # statement about the verifier, never about the record.
                ctx.issues.add(
                    "URI_TARGET_FORBIDDEN",
                    uri_path,
                    f'refusing to fetch "{uri}": no IPFS gateway chain is configured',
                )
                continue

        for gateway in gateways:
            url = _join_gateway(gateway, suffix)
            try:
                res = await ctx.fetch_fn(
                    url,
                    FetchOutboundOptions(
                        method="GET", purpose=purpose, max_bytes=ctx.max_fetch_bytes
                    ),
                )
            except BodyTooLargeError:
                # Aborted at the deployment's per-URI fetch ceiling. Every URI
                # of a claim addresses the same bytes, so any other honest
                # source would abort at the same ceiling: end the claim. The
                # consumer's end-state surfaces CONTENT_FETCH_LIMIT_EXCEEDED.
                flags.limit_exceeded = True
                return
            except DenyHostError:
                ctx.issues.add(
                    "SERVICE_INDEPENDENCE_VIOLATION",
                    uri_path,
                    f"outbound call to {url} targets a denyHosts entry",
                )
                continue
            except Exception as e:
                ctx.issues.add(
                    "URI_FETCH_FAILED",
                    uri_path,
                    f'fetch of "{uri}" via {gateway} failed: {e}',
                )
                continue
            if res.status != 200:
                ctx.issues.add(
                    "URI_FETCH_FAILED",
                    uri_path,
                    f'fetch of "{uri}" via {gateway} returned HTTP {res.status}',
                )
                continue
            yield AcquiredBlob(
                bytes=res.bytes,
                source="fetched",
                uri=uri,
                uri_index=uri_index,
                _cid=parsed.address if parsed.scheme == "ipfs" else None,
                _cid_path=parsed.path,
            )
            # The consumer pulled the next source: this blob did not settle
            # the claim (an unattributable mismatch indicts the gateway, not
            # the address), so the remaining gateways of the same URI are
            # tried next.


__all__ = [
    "ARWEAVE_GATEWAY_DEFAULTS",
    "DEFAULT_OUTBOUND_MAX_BYTES",
    "DEFAULT_RETRIES",
    "DEFAULT_RETRYABLE_STATUSES",
    "DEFAULT_TIMEOUT_MS",
    "AcquiredBlob",
    "BlobIterationFlags",
    "BodyTooLargeError",
    "ContentFetchContext",
    "DenyHostError",
    "OutboundExhaustedError",
    "UnsupportedMethodError",
    "UnsupportedProtocolError",
    "default_fetch_outbound",
    "iterate_blob_sources",
    "matches_deny_list",
    "wrap_fetch_outbound",
]
