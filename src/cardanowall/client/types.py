"""Shared types for the Python Label309Client HTTP surface.

Mirror of the ``@cardanowall/sdk-ts`` client types. Field names mirror the wire
format (snake_case) byte-equivalently — both languages emit snake_case on the
wire, the TypeScript twin only diverges on SDK-introduced helper arg names.

Money on the wire: USD micro-cents serialised as decimal strings
(1 USD = 1,000,000 micros). The SDK returns the wire-shape strings; callers
promote to ``int`` at the application boundary where they need arithmetic.
"""

from __future__ import annotations

from typing import Any, Literal, NotRequired, TypedDict

# Publish-record lifecycle status. The known values are enumerated for
# discoverability, but the alias stays `str`-tolerant: the gateway may introduce
# a new status (e.g. an intermediate ``confirming``) without breaking an older
# SDK, so an unknown value flows through verbatim rather than failing
# deserialisation. Compare against the documented literals; treat anything else
# as forward-compatible.
PoeStatus = (
    Literal["submitting", "submitted", "confirming", "confirmed", "failed", "permanent_failure"]
    | str
)
ConformanceProfile = Literal["core", "signed", "sealed", "recipient-sealed"]
StorageTarget = Literal["arweave"]


# =============================================================================
# POST /poe/uploads — multipart binary upload to a storage backend
# =============================================================================
#
# The SDK presents the wire shape directly: caller passes a ``target`` enum
# and a list of byte blobs; the SDK assembles the multipart form. Up to 32
# files per call. The response carries a per-file outcome entry — successful
# files land as ``{ok: true, uri, sha256, bytes}``, failed ones as
# ``{ok: false, error}``.
#
# Billing: free. The storage cost is part of the publish quote (POST
# /poe/quote → POST /poe/publish); it is debited once at publish time against
# the locked price snapshot.


class UploadSuccessEntry(TypedDict):
    idx: int
    ok: Literal[True]
    uri: str
    sha256: str
    bytes: int


class UploadFailureErrorBlock(TypedDict):
    code: str
    detail: str


class UploadFailureEntry(TypedDict):
    idx: int
    ok: Literal[False]
    error: UploadFailureErrorBlock


UploadEntry = UploadSuccessEntry | UploadFailureEntry


class UploadsResponse(TypedDict):
    uploads: list[UploadEntry]


# =============================================================================
# Resumable / chunked upload sessions — /poe/uploads/sessions + /attempts
# =============================================================================
#
# A file at or below ``RESUMABLE_THRESHOLD_BYTES`` is sent with the single-shot
# multipart ``uploads()`` call; a larger file is uploaded as a content-addressed
# session — create, PUT each fixed-size chunk, complete — converging on one
# ``ar://`` URI. These TypedDicts are the wire shapes of the session/attempt
# routes; the driver lives in :mod:`cardanowall.client.resumable_upload`.


class UploadSessionCreateResponse(TypedDict):
    """``POST /poe/uploads/sessions`` — a fresh session was created."""

    session_id: str
    chunk_bytes: int
    chunk_count: int
    # Indices already held server-side; empty on a fresh create.
    received: list[int]
    expires_at: str
    # The gateway's authoritative ceiling; it may clamp ``chunk_bytes`` to this.
    max_chunk_bytes: int


class UploadSessionDeduplicatedResponse(TypedDict):
    """``POST /poe/uploads/sessions`` — create-time dedup: the bytes already exist."""

    deduplicated: Literal[True]
    uri: str
    sha256: str
    bytes: int
    charged_usd_micros: int


class UploadSessionStatus(TypedDict, total=False):
    """``GET /poe/uploads/sessions/{sid}`` — the live session state."""

    session_id: str
    # 'pending' | 'assembling' | 'completed' | 'failed' | 'expired' (string-tolerant).
    state: str
    sha256: str
    total_bytes: int
    chunk_bytes: int
    chunk_count: int
    received: list[int]
    # The authoritative set of indices still to send. Older gateways may omit it,
    # in which case the driver derives the gap from ``received`` + ``chunk_count``.
    missing: list[int]
    attempt_id: str | None
    uri: str | None


class UploadSessionChunkResponse(TypedDict):
    """``PUT /poe/uploads/sessions/{sid}/chunks/{index}`` — chunk accepted."""

    index: int
    received: list[int]
    remaining: int
    complete: bool


class UploadSessionCompleteOk(TypedDict, total=False):
    """``POST .../complete`` — synchronous terminal success."""

    ok: Literal[True]
    uri: str
    sha256: str
    bytes: int
    # 0 for a dedup-on-commit (bytes already stored); the held amount otherwise.
    charged_usd_micros: int


class UploadSessionCompleteAccepted(TypedDict):
    """``POST .../complete`` — completion accepted asynchronously; poll the attempt."""

    accepted: Literal[True]
    attempt_id: str


UploadSessionCompleteResponse = UploadSessionCompleteOk | UploadSessionCompleteAccepted


class UploadAttemptReserved(TypedDict):
    """``GET /poe/uploads/attempts/{id}`` — in flight (the only non-terminal state)."""

    attempt_id: str
    state: Literal["reserved"]
    sha256: str
    bytes: int
    backend: str


class UploadAttemptCommitted(TypedDict):
    """``GET /poe/uploads/attempts/{id}`` — terminal success; carries the URI."""

    attempt_id: str
    state: Literal["committed"]
    sha256: str
    bytes: int
    backend: str
    uri: str
    charged_usd_micros: int


class UploadAttemptReleased(TypedDict):
    """``GET /poe/uploads/attempts/{id}`` — terminal failure; carries the reason."""

    attempt_id: str
    state: Literal["released"]
    sha256: str
    bytes: int
    backend: str
    reason: str


UploadAttemptStatus = UploadAttemptReserved | UploadAttemptCommitted | UploadAttemptReleased


class UploadProgress(TypedDict):
    """Progress snapshot delivered to ``on_progress`` after each chunk PUT.

    ``bytes_sent`` / ``chunk_index`` count completed chunks against
    ``total_bytes`` / ``chunks_total``. On the single-shot path a single 100%
    snapshot is delivered on success.
    """

    bytes_sent: int
    total_bytes: int
    chunk_index: int
    chunks_total: int


class UploadResumableResult(TypedDict):
    """Terminal result of :meth:`PoeNamespace.upload_resumable`."""

    # Canonical ``ar://<tx>`` URI of the stored content.
    uri: str
    # Whole-file SHA-256, lowercase hex.
    sha256: str
    # Stored byte count.
    bytes: int
    # ``True`` when the bytes were already stored (create-time or commit-time dedup).
    deduplicated: bool
    # Which ingress path carried the bytes.
    mode: Literal["single-shot", "chunked"]


# =============================================================================
# POST /poe/quote — lock the price for an upcoming /publish call
# =============================================================================
#
# The gateway prices the described publish (from the supplied byte counts),
# records the price lock, and returns an OPAQUE quote: an id, the total
# ``amount`` in the gateway's ``currency``, and an expiry. The quote is a
# sealed price token — the gateway's pricing internals are deliberately NOT
# part of the public response. ``/publish`` consumes the quote atomically by
# id and rejects expired / already-consumed quotes.


class QuoteBreakdown(TypedDict):
    """Per-component USD micro-cents cost of a priced publish.

    Present only on the optional ``breakdown`` field of :class:`QuoteResponse`,
    populated by a gateway that exposes its pricing components; each value is a
    decimal string of USD micro-cents.
    """

    network_usd_micros: str
    storage_usd_micros: str
    service_usd_micros: str


class QuoteResponse(TypedDict, total=False):
    """A price lock returned by ``POST /poe/quote``.

    The four core fields (``quote_id`` / ``amount`` / ``currency`` /
    ``expires_at``) are always present: pass ``quote_id`` to ``/publish`` and
    surface ``amount`` / ``currency`` / ``expires_at`` to the user. A gateway
    that chooses to expose its pricing internals MAY additionally return an
    optional breakdown (``usd_micros``, ``breakdown``, ``margin_pct``,
    ``margin_source``, ``fx_age_seconds``); a gateway that treats the quote as a
    sealed opaque token omits them. The breakdown fields are read-only diagnostic
    surface — ``/publish`` consumes only ``quote_id``.
    """

    # Opaque id of the persisted price lock; pass to /publish. (Always present.)
    quote_id: str
    # Total locked price, as a decimal string (promote to int as needed).
    # (Always present.)
    amount: str
    # Currency the ``amount`` is denominated in (e.g. ISO 4217 ``USD``).
    # (Always present.)
    currency: str
    # ISO8601 expiry timestamp after which the gateway rejects the quote.
    # (Always present.)
    expires_at: str
    # ---- Optional pricing breakdown (present only on a gateway that exposes it) ----
    # Total locked price in USD micro-cents (decimal string); the breakdown
    # counterpart of ``amount`` when the gateway prices in micro-cents.
    usd_micros: str
    # Per-component cost split.
    breakdown: QuoteBreakdown
    # Effective margin percentage applied to the cost-pass-through base.
    margin_pct: float
    # Which precedence path produced ``margin_pct`` (e.g. ``"override"``,
    # ``"default"``, a ``"delegation:"``-prefixed string), verbatim from the gateway.
    margin_source: str
    # Age (seconds) of the gateway's FX snapshot at quote time.
    fx_age_seconds: int


# =============================================================================
# POST /poe/publish — finalised single-record submission (JSON only)
# =============================================================================


class RecordSignature(TypedDict, total=False):
    cose_sign1: str  # required
    cose_key: str


class PoeItemResponse(TypedDict, total=False):
    item_idx: int
    hashes: dict[str, str]
    uris: list[str]
    enc: dict[str, Any]


class PublishResponse(TypedDict):
    # Wire-format prefixed id (``poe_<26-char-crockford-base32>``) of the
    # freshly-inserted ``poe_record`` row. Stable across the submit→confirm
    # lifecycle.
    id: str
    tx_hash: str | None
    status: PoeStatus
    items_count: int
    signed: bool
    sealed: bool
    items: list[PoeItemResponse]
    conformance_profile: ConformanceProfile
    # Account balance after the debit, USD micro-cents (decimal string).
    balance_after_usd_micros: str
    # ``True`` when the server returned 200 (dedup hit on the prior submission
    # of an identical record by this account) rather than 202 (freshly
    # enqueued).
    dedup_hit: bool


# =============================================================================
# POST /poe/publish-batch — 1..50 finalised records
# =============================================================================


class PublishBatchSuccessEntry(TypedDict):
    record_idx: int
    id: str
    tx_hash: str | None
    status: PoeStatus
    items_count: int
    signed: bool
    sealed: bool
    items: list[PoeItemResponse]
    conformance_profile: ConformanceProfile


class PublishBatchFailureError(TypedDict, total=False):
    code: str  # required
    detail: str  # required
    errors: list[dict[str, str]]
    extensions: dict[str, Any]


class PublishBatchFailureEntry(TypedDict):
    record_idx: int
    error: PublishBatchFailureError


PublishBatchResultEntry = PublishBatchSuccessEntry | PublishBatchFailureEntry


class PublishBatchResponse(TypedDict):
    results: list[PublishBatchResultEntry]
    # Aggregate balance after every successful debit in the batch.
    balance_after_usd_micros: str


# =============================================================================
# GET /records/{tx_hash} — single record resource
# =============================================================================
#
# ``RecordResource`` is the canonical wire shape served by
# ``GET /records/{tx_hash}`` AND projected into every entry of
# ``data[]`` in ``GET /records``.
#
# ``status`` is chain-derived ('confirming' / 'confirmed') for all viewers
# on anchored rows; un-anchored rows (block_height is None) only surface to
# their owner with 'submitting' / 'failed'. The field is None only as
# defense-in-depth for the impossible un-anchored-leaked-to-non-owner case.

RecordStatus = Literal["submitting", "confirming", "confirmed", "failed"]
RecordScheme = Literal[0, 1, 2]


class RecordResource(TypedDict, total=False):
    tx_hash: str
    status: RecordStatus | None
    block_height: int | None
    block_time: str | None
    num_confirmations: int
    scheme: RecordScheme
    item_count: int
    signer_ed25519: str | None
    metadata_cbor_base64: str
    # Owner-only — present iff the caller authenticated as the row's owner.
    account_id: str


# =============================================================================
# GET /records — paginated record list (client.records.list)
# =============================================================================
#
# The optional ``sealed`` filter narrows the page to sealed records addressed
# to the authenticated caller (the gateway resolves "addressed to me" from the
# identity behind the bearer token); omitting it lists every record the caller
# may read. Each page entry is the same ``RecordResource`` projection
# ``records.get`` returns.


class RecordsListInput(TypedDict, total=False):
    # Opaque pagination cursor — pass back the ``next_cursor`` from a prior page.
    cursor: str | None
    # Page size (the gateway may clamp).
    limit: int
    # When ``True``, restrict the page to sealed records addressed to the
    # authenticated caller. When omitted, list every record the caller may read.
    sealed: bool


class RecordsListResponse(TypedDict):
    object: Literal["list"]
    data: list[RecordResource]
    has_more: bool
    next_cursor: str | None
    url: str
    # The chain tip block height observed when this page was served, used to
    # compute confirmation depth during a sealed-record sync. Optional: a
    # gateway that reports it (JSON key ``tip_block_height``) populates
    # confirmation data directly; otherwise the SDK derives it from the page
    # rows as ``max(block_height + num_confirmations - 1)``, falling back to
    # None for an empty page or rows without a block height.
    tip_block_height: NotRequired[int | None]


# =============================================================================
# GET /records/count — exact count of records matching a filter
# =============================================================================
#
# The counting counterpart to ``GET /records``: the cursor-paginated feed never
# carries a total, so a consumer that needs "how many records match this filter"
# (a public profile's proof count, an explorer facet) asks here.
#
# The gateway REQUIRES a ``signer``: a count's cost is the cardinality of the
# matching set, and only a publisher key bounds it (a block/time window can span
# the whole chain; ``scheme``/``sealed`` only partition it). A count without a
# ``signer`` is rejected (HTTP 422), so ``signer`` is non-optional in the input.
# The remaining filters are the same narrowing grammar as the list route.


class RecordsCountInput(TypedDict):
    """Filter for :meth:`RecordsNamespace.count`.

    ``signer`` is REQUIRED (64 lowercase-hex Ed25519 verification-key bytes); the
    rest are optional narrowers on top of the signer scope, using the same wire
    query names as the list route.
    """

    # REQUIRED. 64 lowercase-hex characters (the publisher's Ed25519 verification
    # key). The gateway 422s a count without it.
    signer: str
    # Optional narrowers (all NotRequired via total=False semantics below).
    scheme: NotRequired[RecordScheme]
    sealed: NotRequired[bool]
    from_block: NotRequired[int]
    to_block: NotRequired[int]
    # ISO-8601 datetime strings.
    from_time: NotRequired[str]
    to_time: NotRequired[str]


class RecordsCountResponse(TypedDict):
    object: Literal["count"]
    count: int
    url: str


# =============================================================================
# GET /account/balance
# =============================================================================


class AccountBalance(TypedDict):
    # The account's current prepaid USD balance in micro-cents, as a decimal
    # string. A string (never an int) so the bigint value survives JSON without
    # precision loss; an account with no ledger activity yet reads "0".
    balance_usd_micros: str


__all__ = [
    "AccountBalance",
    "ConformanceProfile",
    "PoeItemResponse",
    "PoeStatus",
    "PublishBatchFailureEntry",
    "PublishBatchFailureError",
    "PublishBatchResponse",
    "PublishBatchResultEntry",
    "PublishBatchSuccessEntry",
    "PublishResponse",
    "QuoteBreakdown",
    "QuoteResponse",
    "RecordResource",
    "RecordScheme",
    "RecordSignature",
    "RecordStatus",
    "RecordsCountInput",
    "RecordsCountResponse",
    "RecordsListInput",
    "RecordsListResponse",
    "StorageTarget",
    "UploadAttemptCommitted",
    "UploadAttemptReleased",
    "UploadAttemptReserved",
    "UploadAttemptStatus",
    "UploadEntry",
    "UploadFailureEntry",
    "UploadFailureErrorBlock",
    "UploadProgress",
    "UploadResumableResult",
    "UploadSessionChunkResponse",
    "UploadSessionCompleteAccepted",
    "UploadSessionCompleteOk",
    "UploadSessionCompleteResponse",
    "UploadSessionCreateResponse",
    "UploadSessionDeduplicatedResponse",
    "UploadSessionStatus",
    "UploadSuccessEntry",
    "UploadsResponse",
]
