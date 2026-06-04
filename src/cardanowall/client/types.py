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

PoeStatus = Literal["submitting", "submitted", "confirmed", "permanent_failure"]
ConformanceProfile = Literal["core", "signed", "sealed", "recipient-sealed"]
StorageTarget = Literal["arweave"]


# =============================================================================
# POST /api/v1/poe/uploads — multipart binary upload to a storage backend
# =============================================================================
#
# The SDK presents the wire shape directly: caller passes a ``target`` enum
# and a list of byte blobs; the SDK assembles the multipart form. Up to 32
# files per call. The response carries a per-file outcome entry — successful
# files land as ``{ok: true, uri, sha256, bytes}``, failed ones as
# ``{ok: false, error}``.
#
# Billing: free. The storage cost is part of the publish quote (POST
# /api/v1/poe/quote → POST /api/v1/poe/publish); it is debited once at
# publish time against the locked price snapshot.


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
# POST /api/v1/poe/quote — lock the price for an upcoming /publish call
# =============================================================================
#
# The gateway prices the described publish (from the supplied byte counts),
# records the price lock, and returns an OPAQUE quote: an id, the total
# ``amount`` in the gateway's ``currency``, and an expiry. The quote is a
# sealed price token — the gateway's pricing internals are deliberately NOT
# part of the public response. ``/publish`` consumes the quote atomically by
# id and rejects expired / already-consumed quotes.


class QuoteResponse(TypedDict):
    """An opaque price lock returned by ``POST /api/v1/poe/quote``.

    It is a sealed price token, not a pricing breakdown: pass ``quote_id`` to
    ``/publish`` and surface ``amount`` / ``currency`` / ``expires_at`` to the
    user. The gateway's pricing internals (FX, margins, per-component costs)
    are not exposed.
    """

    # Opaque id of the persisted price lock; pass to /publish.
    quote_id: str
    # Total locked price, as a decimal string (promote to int as needed).
    amount: str
    # Currency the ``amount`` is denominated in (e.g. ISO 4217 ``USD``).
    currency: str
    # ISO8601 expiry timestamp after which the gateway rejects the quote.
    expires_at: str


# =============================================================================
# POST /api/v1/poe/publish — finalised single-record submission (JSON only)
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
# POST /api/v1/poe/publish-batch — 1..50 finalised records
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
# GET /api/v1/records/{tx_hash} — single record resource
# =============================================================================
#
# ``RecordResource`` is the canonical wire shape served by
# ``GET /api/v1/records/{tx_hash}`` AND projected into every entry of
# ``data[]`` in ``GET /api/v1/records``.
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
# GET /api/v1/records — paginated record list (client.records.list)
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
# GET /api/v1/account/balance
# =============================================================================


class AccountBalance(TypedDict):
    # The account's current prepaid USD balance in micro-cents, as a decimal
    # string. A string (never an int) so the bigint value survives JSON without
    # precision loss; an account with no ledger activity yet reads "0".
    balance_usd_micros: str


# =============================================================================
# POST /api/v1/records/{tx_hash}/verify
# =============================================================================


class PoeVerifyDecryption(TypedDict, total=False):
    item_idx: int
    recipient_secret_key: str
    passphrase: str


class PoeVerifyInput(TypedDict, total=False):
    verify_uris: bool
    decryption: list[PoeVerifyDecryption]


__all__ = [
    "AccountBalance",
    "ConformanceProfile",
    "PoeItemResponse",
    "PoeStatus",
    "PoeVerifyDecryption",
    "PoeVerifyInput",
    "PublishBatchFailureEntry",
    "PublishBatchFailureError",
    "PublishBatchResponse",
    "PublishBatchResultEntry",
    "PublishBatchSuccessEntry",
    "PublishResponse",
    "QuoteResponse",
    "RecordResource",
    "RecordScheme",
    "RecordSignature",
    "RecordStatus",
    "RecordsListInput",
    "RecordsListResponse",
    "StorageTarget",
    "UploadEntry",
    "UploadFailureEntry",
    "UploadFailureErrorBlock",
    "UploadSuccessEntry",
    "UploadsResponse",
]
