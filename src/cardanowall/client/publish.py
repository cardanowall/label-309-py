"""High-level publish helpers — collapse the quote + uploads + publish flow
into single calls for the common shapes:

1. :py:meth:`PoeNamespace.publish_content` — anchor a single content blob by
   its ``sha2-256`` (or ``blake2b-256``) digest. No Arweave, no /uploads —
   the record is constructed entirely client-side and posted directly to
   /publish against a caller-supplied quote.

2. :py:meth:`PoeNamespace.publish_prehashed` — the caller already holds the
   digest(s).

3. :py:meth:`PoeNamespace.publish_merkle` — anchor an arbitrary number of
   leaf hashes under a single RFC 9162 §2.1.1 root, with the leaves-list
   CBOR uploaded to Arweave via /uploads. The helper quotes internally from
   the exact-width record-size estimate, enforces the caller's price cap,
   and refreshes the price lock when the upload outlived it.

The sealed-PoE flow lives in :mod:`cardanowall.client.sealed`: the two-phase
``seal_prepare`` / ``submit_sealed`` pair plus the one-shot
``publish_sealed`` wrapper.

Signer architecture: the SDK does NOT hold identity keys (privacy contract
in ``off_host_sign.py``). The helpers take an optional :class:`Signer` that
owns the Ed25519 private key (in-memory PyNaCl, AWS KMS, GCP HSM, ...). The
SDK never sees the private key — it builds the canonical-CBOR
``Sig_structure`` and hands the bytes to the signer.

Parity twin: the publish helpers in ``@cardanowall/sdk-ts``.
"""

from __future__ import annotations

import json
import time
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass
from typing import Any, Literal, Protocol, TypedDict, cast, runtime_checkable

import httpx

from cardanowall._crypto.hash import blake2b_256, sha256
from cardanowall._crypto.merkle_leaves_list import encode_leaves_list
from cardanowall._crypto.merkle_sha2_256 import merkle_sha2_256_root
from cardanowall._crypto.sealed_poe import (
    SealedEnvelope as _SealedEnvelopeDataclass,
)
from cardanowall.estimate import MerkleShape, RecordShape, estimate_record_bytes
from cardanowall.poe_standard import (
    EncryptionEnvelope,
    MerkleCommit,
    PoeRecord,
    encode_poe_record,
)

from .max_usd_exceeded_error import MaxUsdExceededError
from .off_host_sign import assemble_cose_sign1, prepare_sig_structure
from .parse_http_error import parse_http_error
from .partial_upload_error import PartialUploadError
from .resumable_upload import (
    RESUMABLE_THRESHOLD_BYTES,
    upload_resumable,
)
from .resumable_upload import (
    _ResolvedConfig as _ResumableResolvedConfig,
)
from .types import (
    PoeStatus,
    PublishResponse,
    QuoteResponse,
    StorageTarget,
    UploadsResponse,
)

_ED25519_PUBLIC_KEY_LENGTH = 32
_ED25519_SIGNATURE_LENGTH = 64
_LEAF_DIGEST_LENGTH = 32
_STORAGE_TARGET_ARWEAVE: Literal["arweave"] = "arweave"

# An Arweave transaction id is always 43 base64url characters, so a not-yet-
# minted `ar://<tx>` URI has a fixed final width. Charging a placeholder of
# exactly that width in a pre-upload record-size estimate keeps the quoted
# `record_bytes` an upper bound of the published record.
_ARWEAVE_TX_ID_CHARS = 43

# The prefix of the deterministic leaves-list upload idempotency key.
_MERKLE_UPLOAD_KEY_PREFIX = "merkle1-"
# How many leading hex characters of the leaves-list digest the key carries.
_MERKLE_UPLOAD_KEY_DIGEST_CHARS = 32

# The quote-expiry safety margin: a quote expiring within this window is
# refreshed rather than raced against the gateway's TTL check at consume time.
_QUOTE_EXPIRY_SKEW_SECONDS = 30

SupportedHashAlg = Literal["sha2-256", "blake2b-256"]

# KEM selector for sealed-PoE. Defaults to the post-quantum-safe X-Wing hybrid;
# 'x25519' is the explicit classical opt-out. Mirrors the TS PublishSealedInput.kem.
SupportedKem = Literal["x25519", "mlkem768x25519"]


SignerCallback = Callable[[bytes], Awaitable[bytes]] | Callable[[bytes], bytes]


@runtime_checkable
class Signer(Protocol):
    """Pluggable Ed25519 signer for the high-level publish helpers.

    ``signer_pubkey`` MUST be the 32-byte raw Ed25519 public key.

    ``sign(sig_structure_bytes)`` receives the canonical-CBOR
    ``[ "Signature1", protected_bytes, h'' (empty external_aad), to_sign ]``
    bytes and MUST return a 64-byte raw Ed25519 signature (NOT a DER-encoded
    one). May be a coroutine; the helpers ``await`` if needed. Byte-identical
    to the input accepted by AWS KMS ``Sign`` for Ed25519 keys.
    """

    @property
    def signer_pubkey(self) -> bytes: ...

    def sign(self, sig_structure_bytes: bytes, /) -> bytes | Awaitable[bytes]: ...


class PublishError(Exception):
    """Raised when the publish helpers receive malformed input.

    ``code`` discriminator values:

    - ``"INVALID_SIGNER_PUBKEY"`` — ``signer.signer_pubkey`` is not 32 bytes.
    - ``"INVALID_SIGNER_SIGNATURE"`` — ``signer.sign()`` returned wrong-length bytes.
    - ``"INVALID_LEAVES"`` — leaves array is empty or wrong-shaped.
    - ``"INVALID_DIGEST"`` — supplied hex digest is wrong length / non-hex.
    - ``"INVALID_RECIPIENT"`` — recipient public key is wrong length.
    - ``"UNSUPPORTED_HASH_ALG"`` — hash algorithm not registered.
    """

    INVALID_SIGNER_PUBKEY = "INVALID_SIGNER_PUBKEY"
    INVALID_SIGNER_SIGNATURE = "INVALID_SIGNER_SIGNATURE"
    INVALID_LEAVES = "INVALID_LEAVES"
    INVALID_DIGEST = "INVALID_DIGEST"
    INVALID_RECIPIENT = "INVALID_RECIPIENT"
    UNSUPPORTED_HASH_ALG = "UNSUPPORTED_HASH_ALG"

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code: str = code


@dataclass(frozen=True)
class _ResolvedPublishConfig:
    api_key: str | None
    base_url: str
    http_client: httpx.AsyncClient


@dataclass(frozen=True)
class _QuoteRequest:
    """The byte counts a ``POST /poe/quote`` prices: the estimated canonical
    record size, the total sealed-slot count, and the total off-chain storage
    bytes."""

    record_bytes: int
    recipient_count: int
    file_bytes_total: int


class PublishContentInput(TypedDict, total=False):
    content: bytes | str  # required
    quote_id: str  # required — UUID from POST /poe/quote
    hash_alg: SupportedHashAlg
    signer: Signer
    idempotency_key: str


class PublishPrehashedInput(TypedDict, total=False):
    """Caller-supplied digest map for :py:meth:`PoeNamespace.publish_prehashed`.

    ``hashes`` is keyed by Label 309 algorithm id (``sha2-256``, ``blake2b-256``).
    At least one entry is required; values are hex-encoded digests of the
    expected byte length (32 bytes / 64 hex chars for both registered v1
    algorithms).
    """

    hashes: dict[SupportedHashAlg, str]  # required
    quote_id: str  # required — UUID from POST /poe/quote
    signer: Signer
    idempotency_key: str


class PublishMerkleInput(TypedDict, total=False):
    """Keyword arguments of :py:meth:`PoeNamespace.publish_merkle`.

    The helper quotes internally from the exact-width record-size estimate;
    there is no caller-supplied quote id.
    """

    leaves: list[bytes | str]  # required
    hash_alg: Literal["sha2-256"]
    # The advisory `leaf_alg` written into the uploaded leaves-list, naming
    # how the leaves were computed (e.g. 'sha2-256'). Omitted when the leaves
    # carry no such claim (pass-through digests computed elsewhere).
    leaf_alg: str
    signer: Signer
    # Refuse to publish when the quoted price exceeds this many USD
    # micro-cents (1 USD = 1,000,000).
    max_usd_micros: int
    # Idempotency key for the publish call. The leaves-list upload uses its
    # own deterministic key derived from the leaves-list bytes.
    idempotency_key: str
    # Requested chunk size when the leaves-list exceeds the single-shot
    # threshold and is uploaded as a resumable session; the server clamps it
    # to its max_chunk_bytes.
    chunk_bytes: int


class PublishMerkleResponse(TypedDict):
    id: str
    tx_hash: str | None
    status: PoeStatus
    root: str
    leaf_count: int
    ar_uri: str
    # The exact canonical-CBOR record bytes that were published — archive
    # them (e.g. as `record_hex` in a receipt).
    record_bytes: bytes
    # Account balance after the debit, USD micro-cents (decimal string).
    balance_after_usd_micros: str


def _to_bytes(content: bytes | str) -> bytes:
    if isinstance(content, str):
        return content.encode("utf-8")
    return content


def _hex_to_bytes(hex_str: str, *, error_code: str = PublishError.INVALID_DIGEST) -> bytes:
    """Decode a hex string, raising :class:`PublishError` with the caller's
    code on malformed input. A precomputed content digest is an
    ``INVALID_DIGEST``; a Merkle leaf hash is an ``INVALID_LEAVES``."""
    try:
        return bytes.fromhex(hex_str)
    except ValueError as e:
        raise PublishError(error_code, f"invalid hex: {e}") from e


def _hash_content(content: bytes, alg: SupportedHashAlg) -> bytes:
    if alg == "sha2-256":
        return sha256(content)
    if alg == "blake2b-256":
        return blake2b_256(content)
    raise PublishError(
        PublishError.UNSUPPORTED_HASH_ALG,
        f"hash_alg must be 'sha2-256' or 'blake2b-256', got {alg!r}",
    )


def _assert_signer(signer: Signer) -> bytes:
    if (
        not isinstance(signer.signer_pubkey, (bytes, bytearray))
        or len(signer.signer_pubkey) != _ED25519_PUBLIC_KEY_LENGTH
    ):
        raise PublishError(
            PublishError.INVALID_SIGNER_PUBKEY,
            f"signer.signer_pubkey must be {_ED25519_PUBLIC_KEY_LENGTH} bytes",
        )
    if not callable(signer.sign):
        raise PublishError(
            PublishError.INVALID_SIGNER_PUBKEY,
            "signer.sign must be callable",
        )
    return bytes(signer.signer_pubkey)


async def _invoke_signer(signer: Signer, sig_structure_bytes: bytes) -> bytes:
    result = signer.sign(sig_structure_bytes)
    # Accept both sync and async signers — KMS clients are typically async,
    # in-memory ones are sync.
    if hasattr(result, "__await__"):
        sig = await result
    else:
        sig = result
    if not isinstance(sig, (bytes, bytearray)) or len(sig) != _ED25519_SIGNATURE_LENGTH:
        length_repr = str(len(sig)) if isinstance(sig, (bytes, bytearray)) else "unknown"
        raise PublishError(
            PublishError.INVALID_SIGNER_SIGNATURE,
            f"signer.sign() must return {_ED25519_SIGNATURE_LENGTH} bytes; got "
            f"{type(sig).__name__} of length {length_repr}",
        )
    return bytes(sig)


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


async def _sign_record(record: PoeRecord, signer: Signer) -> PoeRecord:
    """Sign a record path-1 (in-memory Ed25519 / KMS / HSM) and return a new
    record with the COSE_Sign1 entry embedded in ``sigs[]``.
    """
    signer_pubkey = _assert_signer(signer)
    sig_structure_bytes, _protected_header_bytes = prepare_sig_structure(
        record=record,
        signer_pubkey=signer_pubkey,
    )
    signature = await _invoke_signer(signer, sig_structure_bytes)
    _cose_sign1_bytes, sig_entry = assemble_cose_sign1(
        record=record,
        signer_pubkey=signer_pubkey,
        signature=signature,
    )
    return {**record, "sigs": [sig_entry]}


async def _encode_record(record: PoeRecord, signer: Signer | None) -> bytes:
    if signer is None:
        return encode_poe_record(record)
    signed = await _sign_record(record, signer)
    return encode_poe_record(signed)


async def _post_publish(
    config: _ResolvedPublishConfig,
    record_bytes_hex: str,
    quote_id: str,
    idempotency_key: str | None,
) -> PublishResponse:
    body = {"record": record_bytes_hex, "quote_id": quote_id}
    response = await config.http_client.post(
        f"{config.base_url}/poe/publish",
        content=json.dumps(body, separators=(",", ":")),
        headers=_build_json_headers(config.api_key, idempotency_key),
    )
    _raise_for_status(response)
    parsed: dict[str, object] = response.json()
    parsed["dedup_hit"] = response.status_code == 200
    return cast("PublishResponse", parsed)


async def _post_quote(
    config: _ResolvedPublishConfig,
    request: _QuoteRequest,
) -> QuoteResponse:
    """POST a quote request and return the price lock."""
    body = {
        "record_bytes": request.record_bytes,
        "recipient_count": request.recipient_count,
        "file_bytes_total": request.file_bytes_total,
    }
    response = await config.http_client.post(
        f"{config.base_url}/poe/quote",
        content=json.dumps(body, separators=(",", ":")),
        headers=_build_json_headers(config.api_key),
    )
    _raise_for_status(response)
    return cast("QuoteResponse", response.json())


def _arweave_uri_placeholder() -> str:
    """A worst-case-width stand-in for a not-yet-minted ``ar://<tx>`` URI,
    used in pre-upload record-size estimates."""
    return "ar://" + "A" * _ARWEAVE_TX_ID_CHARS


def _quote_is_fresh(quote: QuoteResponse, *, now: int | None = None) -> bool:
    """Whether the price lock is still comfortably inside its TTL. An
    unparseable ``expires_at`` reads as fresh: the client cannot assess it, a
    re-quote would carry an equally unparseable one, and the gateway stays
    the authority at consume time."""
    expires = _rfc3339_to_epoch_seconds(quote.get("expires_at", ""))
    if expires is None:
        return True
    current = int(time.time()) if now is None else now
    return current + _QUOTE_EXPIRY_SKEW_SECONDS < expires


def _enforce_max_usd_micros(max_usd_micros: int | None, quote: QuoteResponse) -> None:
    """Refuse to proceed when the quoted price exceeds the caller's cap in
    USD micro-cents. Money stays an integer in-process and a decimal string
    on the wire, so the comparison parses the gateway's ``amount`` string
    exactly (digits only — no sign, no whitespace, no fraction)."""
    if max_usd_micros is None:
        return
    amount = quote["amount"]
    if not (amount.isascii() and amount.isdigit()):
        raise ValueError(f"quote amount {amount!r} is not a decimal micro-USD string")
    if int(amount) > max_usd_micros:
        raise MaxUsdExceededError(amount, max_usd_micros)


async def _refresh_quote_if_stale(
    config: _ResolvedPublishConfig,
    quote: QuoteResponse,
    request: _QuoteRequest,
    max_usd_micros: int | None,
) -> QuoteResponse:
    """Re-establish the price lock when a slow step (a storage upload)
    outlived the quote's TTL: fetch a fresh quote for the same shape and
    re-enforce the price cap against the NEW price — FX may have moved while
    the upload ran, and the cap is a promise about what gets spent."""
    if _quote_is_fresh(quote):
        return quote
    fresh = await _post_quote(config, request)
    _enforce_max_usd_micros(max_usd_micros, fresh)
    return fresh


def _rfc3339_to_epoch_seconds(text: str) -> int | None:
    """Parse an RFC 3339 timestamp (``YYYY-MM-DDTHH:MM:SS``, optional
    fractional seconds, a ``Z`` or ``±HH:MM`` offset) to POSIX seconds.

    Hand-rolled to pin one cross-SDK behaviour for the freshness gate rather
    than inheriting a host library's leniencies (naive timestamps, exotic
    separators). Returns ``None`` for anything malformed — the freshness
    check treats that as "cannot assess", never as an error.
    """
    raw = text.strip().encode("utf-8")
    if len(raw) < 20:
        return None

    def digits(start: int, end: int) -> int | None:
        chunk = raw[start:end]
        if not chunk.isdigit():
            return None
        return int(chunk)

    def expect(index: int, allowed: bytes) -> bool:
        return raw[index] in allowed

    year = digits(0, 4)
    month = digits(5, 7)
    day = digits(8, 10)
    hour = digits(11, 13)
    minute = digits(14, 16)
    second = digits(17, 19)
    if (
        year is None
        or month is None
        or day is None
        or hour is None
        or minute is None
        or second is None
    ):
        return None
    if not (
        expect(4, b"-")
        and expect(7, b"-")
        and expect(10, b"Tt ")
        and expect(13, b":")
        and expect(16, b":")
    ):
        return None
    if not 1 <= month <= 12 or not 1 <= day <= _days_in_month(year, month):
        return None
    # Second 60 (a leap second) is accepted and clamped by the arithmetic.
    if hour > 23 or minute > 59 or second > 60:
        return None

    # Skip an optional fractional-seconds part (whole-second precision is
    # enough for the skew window).
    i = 19
    if raw[i : i + 1] == b".":
        i += 1
        start = i
        while i < len(raw) and raw[i : i + 1].isdigit():
            i += 1
        if i == start:
            return None

    tail = raw[i:]
    if tail in (b"Z", b"z"):
        offset_seconds = 0
    elif len(tail) == 6 and tail[0:1] in (b"+", b"-") and tail[3:4] == b":":
        offset_hours = digits(i + 1, i + 3)
        offset_minutes = digits(i + 4, i + 6)
        if offset_hours is None or offset_minutes is None:
            return None
        if offset_hours > 23 or offset_minutes > 59:
            return None
        magnitude = offset_hours * 3600 + offset_minutes * 60
        offset_seconds = magnitude if tail[0:1] == b"+" else -magnitude
    else:
        return None

    days = _days_from_civil(year, month, day)
    return days * 86_400 + hour * 3600 + minute * 60 + second - offset_seconds


def _days_from_civil(year: int, month: int, day: int) -> int:
    """Days since 1970-01-01 for a proleptic-Gregorian civil date (the
    standard days-from-civil algorithm; Python's floor division matches the
    Euclidean division the algorithm assumes for a positive divisor)."""
    y = year - 1 if month <= 2 else year
    era = y // 400
    yoe = y - era * 400  # [0, 399]
    mp = (month + 9) % 12  # March = 0
    doy = (153 * mp + 2) // 5 + day - 1  # [0, 365]
    doe = yoe * 365 + yoe // 4 - yoe // 100 + doy  # [0, 146096]
    return era * 146_097 + doe - 719_468


def _days_in_month(year: int, month: int) -> int:
    if month in (1, 3, 5, 7, 8, 10, 12):
        return 31
    if month in (4, 6, 9, 11):
        return 30
    leap = (year % 4 == 0 and year % 100 != 0) or year % 400 == 0
    return 29 if leap else 28


async def _post_uploads(
    config: _ResolvedPublishConfig,
    blobs: Sequence[bytes],
    idempotency_key: str | None,
) -> UploadsResponse:
    files: list[tuple[str, tuple[str, bytes, str]]] = []
    for idx, payload in enumerate(blobs):
        files.append(
            (
                f"file_{idx}",
                (f"file_{idx}.bin", payload, "application/octet-stream"),
            )
        )
    response = await config.http_client.post(
        f"{config.base_url}/poe/uploads",
        data={"target": _STORAGE_TARGET_ARWEAVE},
        files=files,
        headers=_build_multipart_headers(config.api_key, idempotency_key),
    )
    _raise_for_status(response)
    result: UploadsResponse = response.json()
    if any(u["ok"] is False for u in result["uploads"]):
        raise PartialUploadError(result)
    return result


async def _upload_blob(
    config: _ResolvedPublishConfig,
    data: bytes,
    idempotency_key: str | None,
    chunk_bytes: int | None,
) -> str:
    """Upload one blob (sealed ciphertext or Merkle leaves-list) and return its
    ``ar://`` URI.

    A blob at or below the resumable threshold takes the unchanged single-shot
    multipart path; a larger blob transparently uses the resumable session flow
    so a multi-GB ciphertext clears CDN/proxy single-request caps. Both paths
    end at the same URI, so the publish helpers' signatures and on-chain record
    shape are unaffected by the blob's size. ``chunk_bytes`` is the requested
    session chunk size on the resumable path; the server clamps it to its
    ``max_chunk_bytes`` and its echo is authoritative.
    """
    if len(data) <= RESUMABLE_THRESHOLD_BYTES:
        uploads_resp = await _post_uploads(config, [data], idempotency_key)
        first = uploads_resp["uploads"][0]
        # narrowed: _post_uploads raised on any failure, so every entry has ok=True
        return cast("str", first.get("uri"))

    resumable_config = _ResumableResolvedConfig(
        api_key=config.api_key,
        base_url=config.base_url,
        http_client=config.http_client,
    )

    async def single_shot(
        *,
        target: StorageTarget,
        data: bytes,
        idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        del target  # the publish blobs always go to the default Arweave target
        result = await _post_uploads(config, [data], idempotency_key)
        first = result["uploads"][0]
        return {
            "uri": first.get("uri"),
            "sha256": first.get("sha256"),
            "bytes": first.get("bytes"),
        }

    result = await upload_resumable(
        resumable_config,
        single_shot,
        source=data,
        chunk_bytes=chunk_bytes,
        idempotency_key=idempotency_key,
    )
    return result["uri"]


async def publish_content(
    config: _ResolvedPublishConfig,
    *,
    content: bytes | str,
    quote_id: str,
    signer: Signer | None = None,
    hash_alg: SupportedHashAlg = "sha2-256",
    idempotency_key: str | None = None,
) -> PublishResponse:
    """Hash-only PoE — anchor a single content blob's digest, optionally with
    one path-1 signature. No Arweave, no /uploads.
    """
    if signer is not None:
        _assert_signer(signer)
    content_bytes = _to_bytes(content)
    digest = _hash_content(content_bytes, hash_alg)

    record: PoeRecord = {
        "v": 1,
        "items": [{"hashes": {hash_alg: digest}}],
    }
    record_bytes = await _encode_record(record, signer)
    return await _post_publish(config, record_bytes.hex(), quote_id, idempotency_key)


# Both registered hash algorithms produce 32-byte digests. Kept as a per-alg
# map for forward-compat when wider hash registries land.
_DIGEST_BYTE_LENGTH: dict[SupportedHashAlg, int] = {
    "sha2-256": 32,
    "blake2b-256": 32,
}


async def publish_prehashed(
    config: _ResolvedPublishConfig,
    *,
    hashes: dict[SupportedHashAlg, str],
    quote_id: str,
    signer: Signer | None = None,
    idempotency_key: str | None = None,
) -> PublishResponse:
    """Hash-already-computed PoE — anchor a precomputed content digest
    (hex-encoded), optionally signed.
    """
    if signer is not None:
        _assert_signer(signer)
    present = [(alg, hex_digest) for alg, hex_digest in hashes.items() if hex_digest]
    if not present:
        raise PublishError(
            PublishError.INVALID_DIGEST,
            "publish_prehashed requires at least one digest in `hashes`",
        )
    decoded: dict[SupportedHashAlg, bytes] = {}
    for alg, hex_digest in present:
        if alg not in _DIGEST_BYTE_LENGTH:
            raise PublishError(
                PublishError.UNSUPPORTED_HASH_ALG,
                f"unsupported hash algorithm '{alg}' (expected 'sha2-256' or 'blake2b-256')",
            )
        digest_bytes = _hex_to_bytes(hex_digest)
        expected = _DIGEST_BYTE_LENGTH[alg]
        if len(digest_bytes) != expected:
            raise PublishError(
                PublishError.INVALID_DIGEST,
                f"hashes[{alg}] must be a {expected}-byte digest (got {len(digest_bytes)} bytes)",
            )
        decoded[alg] = digest_bytes

    record: PoeRecord = {
        "v": 1,
        "items": [{"hashes": decoded}],
    }
    record_bytes = await _encode_record(record, signer)
    return await _post_publish(config, record_bytes.hex(), quote_id, idempotency_key)


def _envelope_to_wire(envelope: _SealedEnvelopeDataclass) -> EncryptionEnvelope:
    """Convert the dataclass-shaped wrap output to the TypedDict the encoder
    expects. Field names are wire-identical; only the runtime container shape
    differs.
    """
    # The TypedDict declares scheme/aead/kem as narrow Literal types matching
    # the dataclass's runtime values; cast pins the narrower type at the
    # boundary so downstream encoders typecheck.
    # Per-slot wire shape is KEM-driven (the dataclass carries epk XOR kem_ct):
    #   - x25519:         { epk: bstr(32), wrap: bstr(48) }
    #   - mlkem768x25519: { kem_ct: bstr(1120), wrap: bstr(48) } — the X-Wing
    #     ciphertext as a single byte string, NO per-slot epk.
    slots: list[dict[str, object]]
    if envelope.kem == "mlkem768x25519":
        slots = [{"kem_ct": s.kem_ct or b"", "wrap": s.wrap} for s in envelope.slots]
    else:
        slots = [{"epk": s.epk, "wrap": s.wrap} for s in envelope.slots]
    return cast(
        "EncryptionEnvelope",
        {
            "scheme": envelope.scheme,
            "aead": envelope.aead,
            "kem": envelope.kem,
            "nonce": envelope.nonce,
            "slots": slots,
            "slots_mac": envelope.slots_mac,
        },
    )


async def publish_merkle(
    config: _ResolvedPublishConfig,
    *,
    leaves: list[bytes | str],
    signer: Signer | None = None,
    hash_alg: Literal["sha2-256"] = "sha2-256",
    leaf_alg: str | None = None,
    max_usd_micros: int | None = None,
    idempotency_key: str | None = None,
    chunk_bytes: int | None = None,
) -> PublishMerkleResponse:
    """Batch publish via a Merkle root — N leaves under one transaction.
    The leaves-list CBOR is uploaded to Arweave; the on-chain record carries
    ``merkle[0] = {alg: 'rfc9162-sha256', root, leaf_count, uris: [ar://<tx>]}``.

    The helper owns the whole priced flow: it quotes internally from the
    exact-width record-size estimate (the ``ar://`` URI exists only after
    the upload, but an Arweave transaction id is fixed-width, so the
    estimate is exact), enforces ``max_usd_micros``, uploads the canonical
    leaves-list under a deterministic idempotency key derived from the
    leaves-list bytes (a retry of the same batch never pays for its storage
    twice), refreshes the price lock when the upload outlived it, and
    publishes. The response carries the exact published record bytes.

    ``leaf_alg`` is the advisory claim written into the uploaded leaves-list
    naming how the leaves were computed; omitted when the leaves carry no
    such claim. Only ``'sha2-256'`` leaves are supported because
    ``rfc9162-sha256`` is the only registered tree algorithm and its
    underlying hash is SHA-256 (32-byte leaves).
    """
    if signer is not None:
        _assert_signer(signer)
    if hash_alg != "sha2-256":
        raise PublishError(
            PublishError.UNSUPPORTED_HASH_ALG,
            f"publish_merkle only supports 'sha2-256' leaves; got {hash_alg!r}",
        )
    if len(leaves) < 1:
        raise PublishError(
            PublishError.INVALID_LEAVES,
            "publish_merkle requires at least one leaf hash",
        )

    leaves_bytes: list[bytes] = []
    for idx, leaf in enumerate(leaves):
        b = (
            _hex_to_bytes(leaf, error_code=PublishError.INVALID_LEAVES)
            if isinstance(leaf, str)
            else bytes(leaf)
        )
        if len(b) != _LEAF_DIGEST_LENGTH:
            raise PublishError(
                PublishError.INVALID_LEAVES,
                f"leaves[{idx}] must be a {_LEAF_DIGEST_LENGTH}-byte sha2-256 digest",
            )
        leaves_bytes.append(b)

    root = merkle_sha2_256_root(leaves_bytes)
    leaves_list_cbor = encode_leaves_list(leaves=leaves_bytes, root=root, leaf_alg=leaf_alg)

    # The record side of the quote is the exact-width upper-bound estimate
    # with the fixed-width URI placeholder; the storage side is the exact
    # leaves-list byte count.
    shape = RecordShape(
        items=(),
        signed=signer is not None,
        supersedes=False,
        merkle=MerkleShape(alg="rfc9162-sha256", uris=(_arweave_uri_placeholder(),)),
    )
    quote_request = _QuoteRequest(
        record_bytes=estimate_record_bytes(shape),
        recipient_count=0,
        file_bytes_total=len(leaves_list_cbor),
    )
    quote = await _post_quote(config, quote_request)
    _enforce_max_usd_micros(max_usd_micros, quote)

    upload_key = _merkle_upload_idempotency_key(leaves_list_cbor)
    uri = await _upload_blob(config, leaves_list_cbor, upload_key, chunk_bytes)

    # A large upload can outlive the price lock; publish only against a live
    # one, re-enforcing the cap against the refreshed price.
    quote = await _refresh_quote_if_stale(config, quote, quote_request, max_usd_micros)

    # `rfc9162-sha256` is the only registered tree algorithm string.
    merkle_entry: MerkleCommit = {
        "alg": "rfc9162-sha256",
        "root": root,
        "leaf_count": len(leaves_bytes),
        "uris": [uri],
    }
    record: PoeRecord = {"v": 1, "merkle": [merkle_entry]}
    record_bytes = await _encode_record(record, signer)
    published = await _post_publish(config, record_bytes.hex(), quote["quote_id"], idempotency_key)

    return {
        "id": published["id"],
        "tx_hash": published["tx_hash"],
        "status": published["status"],
        "root": root.hex(),
        "leaf_count": len(leaves_bytes),
        "ar_uri": uri,
        "record_bytes": record_bytes,
        "balance_after_usd_micros": published["balance_after_usd_micros"],
    }


def _merkle_upload_idempotency_key(leaves_list: bytes) -> str:
    """The deterministic leaves-list upload idempotency key:
    ``"merkle1-" + sha256(leaves_list_bytes)[:32]``. The leaves-list encoding
    is canonical, so the same batch always presents the same key and a
    crash-and-retry can never double-pay its storage upload."""
    digest = sha256(leaves_list).hex()
    return _MERKLE_UPLOAD_KEY_PREFIX + digest[:_MERKLE_UPLOAD_KEY_DIGEST_CHARS]


__all__ = [
    "MaxUsdExceededError",
    "PublishContentInput",
    "PublishError",
    "PublishMerkleInput",
    "PublishMerkleResponse",
    "PublishPrehashedInput",
    "PublishResponse",
    "Signer",
    "SignerCallback",
    "SupportedHashAlg",
    "SupportedKem",
    "publish_content",
    "publish_merkle",
    "publish_prehashed",
]
