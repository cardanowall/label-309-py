"""Two-phase sealed publishing: prepare determinism, the portable
``prepared_seal_json_v1`` artifact, receipt-validated resume, quote
consumption/refresh, the price cap, and the reworked merkle flow.
Assertions target request sequences, request bodies, receipts, and record
bytes — never log strings.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
from dataclasses import dataclass
from typing import Any, cast

import cbor2
import httpx
import pytest

from cardanowall._crypto.sealed_poe import ecies_sealed_poe_wrap
from cardanowall._crypto.seed_derive import derive_x25519_keypair_from_seed
from cardanowall.client.insufficient_funds_error import InsufficientFundsError
from cardanowall.client.invalid_upload_receipt_error import InvalidUploadReceiptError
from cardanowall.client.label309_client import Label309Client
from cardanowall.client.max_usd_exceeded_error import MaxUsdExceededError
from cardanowall.client.partial_upload_error import PartialUploadError
from cardanowall.client.publish import PublishError
from cardanowall.client.sealed import (
    PassphraseKdfParams,
    PreparedPassphraseSeal,
    PreparedSeal,
    PreparedSealJsonError,
    RngFill,
    SealPrepareError,
    SubmitSealedError,
    UploadReceipt,
    _document_of,
    _fingerprint,
    _validate_receipts,
    encode_passphrase_sealed_record,
    encode_sealed_record,
    passphrase_seal_prepare_with_rng,
    passphrase_sealed_record,
    seal_prepare,
    seal_prepare_with_rng,
    sealed_record,
)
from cardanowall.poe_standard import ValidateOk, encode_poe_record, validate

FIXTURE_API_KEY = "opaque-bearer-fixture-token"
QUOTE_ID = "01956b41-7c00-7000-8000-000000000001"

PUBLISH_BODY: dict[str, Any] = {
    "id": "poe_06bqrjg0csvqfanaqexvqexvqc",
    "tx_hash": None,
    "status": "submitting",
    "items_count": 1,
    "signed": False,
    "sealed": True,
    "items": [],
    "conformance_profile": "sealed",
    "balance_after_usd_micros": "4500000",
}


def _counter_rng(start: int) -> RngFill:
    """A deterministic byte source for reproducible prepares: byte ``n`` of
    the stream is ``(start + n) & 0xff``. Trivially replicated in any
    language, so the cross-SDK vectors pin against the same stream."""
    state = start

    def fill(count: int) -> bytes:
        nonlocal state
        out = bytes((state + i) & 0xFF for i in range(count))
        state += count
        return out

    return fill


def _x25519_recipients(count: int) -> list[bytes]:
    """Derive ``count`` classical recipient public keys from fixed seeds."""
    return [
        derive_x25519_keypair_from_seed(bytes([i]) * 32)["public_key"] for i in range(1, count + 1)
    ]


def _deterministic_prepared(plaintexts: list[bytes], recipient_count: int) -> PreparedSeal:
    """A reproducible classical prepared seal over the given plaintexts."""
    return seal_prepare_with_rng(
        items=plaintexts,
        recipients=_x25519_recipients(recipient_count),
        kem="x25519",
        rng=_counter_rng(0),
    )


def _quote_body(
    quote_id: str = QUOTE_ID,
    amount: str = "42",
    expires_at: str = "2100-01-01T00:00:00Z",
) -> dict[str, Any]:
    return {
        "quote_id": quote_id,
        "amount": amount,
        "currency": "USD",
        "expires_at": expires_at,
    }


def _uploads_body(uri: str) -> dict[str, Any]:
    return {
        "uploads": [{"idx": 0, "ok": True, "uri": uri, "sha256": "00" * 32, "bytes": 1}],
    }


_FAILED_UPLOADS_BODY: dict[str, Any] = {
    "uploads": [
        {
            "idx": 0,
            "ok": False,
            "error": {"code": "storage-provider-rejected", "detail": "arweave timeout"},
        }
    ],
}


@dataclass(frozen=True)
class _Captured:
    """One captured request: its path, headers, and raw body bytes."""

    path: str
    headers: httpx.Headers
    content: bytes

    def json(self) -> dict[str, Any]:
        return cast("dict[str, Any]", json.loads(self.content))

    def multipart_file_bytes(self) -> bytes:
        """The multipart ``file_0`` bytes of a captured /poe/uploads request."""
        marker = b'name="file_0"'
        idx = self.content.find(marker)
        assert idx >= 0, "uploads request carries file_0"
        tail = self.content[idx:]
        data_start = tail.find(b"\r\n\r\n") + 4
        data_end = tail.find(b"\r\n--", data_start)
        return tail[data_start:data_end]


class _ScriptedHandler:
    """Serves a scripted response sequence and captures every request, so a
    test asserts the exact call order, bodies, and headers the helper
    produced."""

    def __init__(self, responses: list[tuple[int, dict[str, Any]]]) -> None:
        self._responses = list(responses)
        self.captured: list[_Captured] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.captured.append(
            _Captured(path=request.url.path, headers=request.headers, content=request.content)
        )
        if not self._responses:
            raise AssertionError(f"unexpected request beyond the script: {request.url.path}")
        status, body = self._responses.pop(0)
        return httpx.Response(status, json=body)

    @property
    def call_count(self) -> int:
        return len(self.captured)


def _client(handler: _ScriptedHandler) -> Label309Client:
    transport = httpx.MockTransport(handler)
    return Label309Client(
        api_key=FIXTURE_API_KEY,
        base_url="http://test.example/api/v1",
        http_client=httpx.AsyncClient(transport=transport),
    )


def _refusing_handler() -> _ScriptedHandler:
    return _ScriptedHandler([])


# ---------------------------------------------------------------------------
# Phase 1: determinism, derivations, and the portable artifact
# ---------------------------------------------------------------------------


def test_seal_prepare_with_rng_is_deterministic_and_derivations_are_pinned() -> None:
    plaintexts = [b"item zero", b"item one"]
    a = _deterministic_prepared(plaintexts, 2)
    b = _deterministic_prepared(plaintexts, 2)
    # The same rng stream reproduces the artifact byte-for-byte.
    assert a == b
    assert a.to_json() == b.to_json()
    assert a.prepared_sha256 == b.prepared_sha256

    # item_id is the lowercase-hex SHA-256 of the item's ciphertext.
    for item in a.items:
        assert item.item_id == hashlib.sha256(item.ciphertext).hexdigest()
    # The per-item upload idempotency key is derived from the fingerprint.
    for index in range(len(a.items)):
        assert a.upload_idempotency_key(index) == f"seal1-{a.prepared_sha256[:32]}-{index}"

    # The secure entry point draws fresh randomness: two prepares of the same
    # input must differ (a repeat would mean a repeated content key).
    secure_a = seal_prepare(items=[b"item zero"], recipients=_x25519_recipients(1), kem="x25519")
    secure_b = seal_prepare(items=[b"item zero"], recipients=_x25519_recipients(1), kem="x25519")
    assert secure_a.prepared_sha256 != secure_b.prepared_sha256


def test_prepared_seal_json_round_trips_and_rejects_corruption() -> None:
    prepared = _deterministic_prepared([b"round trip"], 2)
    serialized = prepared.to_json()

    # Round trip: parse → identical artifact → identical canonical JSON.
    parsed = PreparedSeal.from_json(serialized)
    assert parsed == prepared
    assert parsed.to_json() == serialized

    document = json.loads(serialized)

    # A flipped fingerprint is rejected as corruption.
    tampered_fp = dict(document)
    fp = tampered_fp["prepared_sha256"]
    tampered_fp["prepared_sha256"] = ("1" + fp[1:]) if fp.startswith("0") else ("0" + fp[1:])
    with pytest.raises(PreparedSealJsonError) as exc:
        PreparedSeal.from_json(json.dumps(tampered_fp))
    assert exc.value.code == PreparedSealJsonError.FINGERPRINT_MISMATCH

    # Unknown members are rejected: the strict schema is what makes the
    # fingerprint meaningful (an ignored field would be unauthenticated).
    extra = dict(document)
    extra["surprise"] = True
    with pytest.raises(PreparedSealJsonError) as exc:
        PreparedSeal.from_json(json.dumps(extra))
    assert exc.value.code == PreparedSealJsonError.PARSE

    # A foreign version string is refused before any structural work.
    wrong_version = dict(document)
    wrong_version["version"] = "prepared_seal_json_v2"
    with pytest.raises(PreparedSealJsonError) as exc:
        PreparedSeal.from_json(json.dumps(wrong_version))
    assert exc.value.code == PreparedSealJsonError.UNSUPPORTED_VERSION


def test_prepared_seal_json_rejects_ciphertext_swap_even_with_recomputed_fingerprint() -> None:
    """Tampering with the ciphertext while recomputing a "valid" fingerprint
    test-side must still be rejected by the item_id ↔ ciphertext invariant.
    The test-side recomputation doubles as an independent check of the
    canonical-form definition (sorted keys, compact, fingerprint omitted)."""
    prepared = _deterministic_prepared([b"tamper me"], 1)
    document = json.loads(prepared.to_json())

    def canonical_fingerprint(doc: dict[str, Any]) -> str:
        unfp = {k: v for k, v in doc.items() if k != "prepared_sha256"}
        canonical = json.dumps(unfp, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    # Sanity: recomputing the fingerprint over the canonical form reproduces
    # the SDK's own value.
    assert canonical_fingerprint(document) == prepared.prepared_sha256

    # Swap the ciphertext for different bytes and recompute the fingerprint
    # like an attacker fixing up the checksum would.
    document["items"][0]["ciphertext"] = "AAAA"
    document["prepared_sha256"] = canonical_fingerprint(document)
    with pytest.raises(PreparedSealJsonError) as exc:
        PreparedSeal.from_json(json.dumps(document))
    assert exc.value.code == PreparedSealJsonError.INVALID


# ---------------------------------------------------------------------------
# Pure assembly seams
# ---------------------------------------------------------------------------


def _uniform_index_below(fill: RngFill, modulus: int) -> int:
    ceiling = (1 << 32) - ((1 << 32) % modulus)
    while True:
        draw = int.from_bytes(fill(4), "little")
        if draw < ceiling:
            return draw % modulus


def test_sealed_record_bytes_are_identical_to_the_direct_construction() -> None:
    """The two-phase path must produce byte-identical records to the direct
    single-item construction the one-shot helper always used: same envelope,
    same hashes, same URI → same canonical bytes. The direct side replays the
    pinned rng draw order (content key → nonce → per-slot scalars → shuffle
    index draws) independently of the sealed module, so it doubles as a check
    of that contract."""
    plaintext = b"byte identity"
    recipients = _x25519_recipients(2)
    uri = "ar://" + "B" * 43

    # The prepared path.
    prepared = _deterministic_prepared([plaintext], 2)
    via_prepared = asyncio.run(encode_sealed_record(prepared, [uri]))

    # The direct construction, over the same deterministic wrap output.
    digest = hashlib.sha256(plaintext).digest()
    hashes = {"sha2-256": digest}
    fill = _counter_rng(0)
    cek = fill(32)
    nonce = fill(24)
    secrets = [fill(32) for _ in recipients]
    order = list(range(len(recipients)))
    for i in range(len(order) - 1, 0, -1):
        j = _uniform_index_below(fill, i + 1)
        order[i], order[j] = order[j], order[i]
    sealed = ecies_sealed_poe_wrap(
        plaintext=plaintext,
        recipient_public_keys=[recipients[i] for i in order],
        hashes=hashes,
        kem="x25519",
        cek=cek,
        nonce=nonce,
        ephemeral_secrets=[secrets[i] for i in order],
        skip_shuffle=True,
    )
    record = {
        "v": 1,
        "items": [
            {
                "hashes": hashes,
                "uris": [uri],
                "enc": {
                    "scheme": sealed.envelope.scheme,
                    "aead": sealed.envelope.aead,
                    "kem": sealed.envelope.kem,
                    "nonce": sealed.envelope.nonce,
                    "slots": [{"epk": s.epk, "wrap": s.wrap} for s in sealed.envelope.slots],
                    "slots_mac": sealed.envelope.slots_mac,
                },
            }
        ],
    }
    direct = encode_poe_record(cast("Any", record))
    assert via_prepared == direct


def test_sealed_record_supports_multi_item_and_validates_uri_count_and_supersedes() -> None:
    prepared = _deterministic_prepared([b"one", b"two", b"three"], 2)
    uris = ["ar://" + str(i) * 43 for i in range(3)]
    supersedes = "ab" * 32

    record_bytes = asyncio.run(encode_sealed_record(prepared, uris, supersedes=supersedes))
    result = validate(record_bytes)
    assert result.ok
    items = result.record["items"]
    assert len(items) == 3
    for index, item in enumerate(items):
        assert item["uris"] == [uris[index]]
        assert "enc" in item
    assert result.record["supersedes"] == b"\xab" * 32

    # One URI per item is a hard contract.
    with pytest.raises(SealPrepareError) as exc:
        sealed_record(prepared, uris[:2])
    assert exc.value.code == SealPrepareError.URI_COUNT_MISMATCH
    # Supersedes must be a 64-hex transaction hash.
    with pytest.raises(SealPrepareError) as exc:
        sealed_record(prepared, uris, supersedes="not-hex")
    assert exc.value.code == SealPrepareError.INVALID_SUPERSEDES


# ---------------------------------------------------------------------------
# Quoting
# ---------------------------------------------------------------------------


def test_quote_prepared_seal_prices_the_exact_prepared_shape() -> None:
    async def run() -> None:
        prepared = _deterministic_prepared([b"priced one", b"priced two"], 2)
        handler = _ScriptedHandler([(200, _quote_body(amount="123"))])
        async with _client(handler) as client:
            quote = await client.poe.quote_prepared_seal(prepared=prepared)
        assert quote["amount"] == "123"

        sent = handler.captured[0].json()
        # Storage side: the exact ciphertext total. Recipient side: one slot
        # per recipient per item.
        assert sent["file_bytes_total"] == sum(len(i.ciphertext) for i in prepared.items)
        assert sent["recipient_count"] == 4
        # Record side: an upper bound of the real encoded record with real URIs.
        uris = ["ar://" + str(i) * 43 for i in range(2)]
        actual = len(await encode_sealed_record(prepared, uris))
        assert sent["record_bytes"] >= actual

    asyncio.run(run())


# ---------------------------------------------------------------------------
# Phase 2: submit_sealed
# ---------------------------------------------------------------------------


def test_submit_sealed_uploads_each_item_under_its_deterministic_key_and_publishes() -> None:
    async def run() -> None:
        prepared = _deterministic_prepared([b"first plaintext", b"second plaintext"], 1)
        uri_a = "ar://" + "D" * 43
        uri_b = "ar://" + "E" * 43
        handler = _ScriptedHandler(
            [
                (200, _quote_body()),
                (200, _uploads_body(uri_a)),
                (200, _uploads_body(uri_b)),
                (202, PUBLISH_BODY),
            ]
        )
        async with _client(handler) as client:
            submission = await client.poe.submit_sealed(prepared=prepared)

        assert handler.call_count == 4
        # Each upload carries its item's ciphertext under its deterministic key.
        for index in range(2):
            upload_req = handler.captured[1 + index]
            assert upload_req.path == "/api/v1/poe/uploads"
            assert upload_req.headers.get("idempotency-key") == prepared.upload_idempotency_key(
                index
            )
            assert upload_req.multipart_file_bytes() == prepared.items[index].ciphertext
        # The publish consumed the internal quote and posted the archived bytes.
        publish_body = handler.captured[3].json()
        assert publish_body["quote_id"] == QUOTE_ID
        assert bytes.fromhex(publish_body["record"]) == submission.record_bytes
        assert submission.uris == (uri_a, uri_b)
        # Receipts mirror the uploads, in item order.
        assert len(submission.uploads) == 2
        for index, receipt in enumerate(submission.uploads):
            item = prepared.items[index]
            assert receipt.item_id == item.item_id
            assert receipt.bytes == len(item.ciphertext)
            assert receipt.ciphertext_sha256 == hashlib.sha256(item.ciphertext).digest()
        assert submission.uploads[0].uri == uri_a
        assert submission.uploads[1].uri == uri_b

    asyncio.run(run())


def test_submit_sealed_caller_idempotency_key_lands_on_the_publish_only() -> None:
    async def run() -> None:
        prepared = _deterministic_prepared([b"first plaintext", b"second plaintext"], 1)
        uri_a = "ar://" + "D" * 43
        uri_b = "ar://" + "E" * 43
        caller_key = "caller-supplied-key-abc123"
        handler = _ScriptedHandler(
            [
                (200, _quote_body()),
                (200, _uploads_body(uri_a)),
                (200, _uploads_body(uri_b)),
                (202, PUBLISH_BODY),
            ]
        )
        async with _client(handler) as client:
            await client.poe.submit_sealed(prepared=prepared, idempotency_key=caller_key)

        # Each upload rides its deterministic seal1- key, never the caller's; a
        # crash-retry dedups on content, not on the caller's publish token.
        for index in range(2):
            key = handler.captured[1 + index].headers.get("idempotency-key")
            assert key == prepared.upload_idempotency_key(index)
            assert key != caller_key
        # The publish carries exactly the caller's key.
        assert handler.captured[3].headers.get("idempotency-key") == caller_key

    asyncio.run(run())


def test_submit_sealed_skips_items_covered_by_validated_receipts() -> None:
    async def run() -> None:
        prepared = _deterministic_prepared([b"first plaintext", b"second plaintext"], 1)
        uri_a = "ar://" + "D" * 43
        uri_b = "ar://" + "E" * 43
        receipt = UploadReceipt(
            item_id=prepared.items[0].item_id,
            uri=uri_a,
            ciphertext_sha256=hashlib.sha256(prepared.items[0].ciphertext).digest(),
            bytes=len(prepared.items[0].ciphertext),
        )
        handler = _ScriptedHandler(
            [
                (200, _quote_body()),
                (200, _uploads_body(uri_b)),
                (202, PUBLISH_BODY),
            ]
        )
        async with _client(handler) as client:
            submission = await client.poe.submit_sealed(prepared=prepared, uploaded=[receipt])

        # Only the uncovered item was uploaded — and it is the SECOND item.
        assert handler.call_count == 3
        assert handler.captured[1].multipart_file_bytes() == prepared.items[1].ciphertext
        # The resumed receipt keeps its slot in item order.
        assert submission.uris == (uri_a, uri_b)
        assert submission.uploads[0] == receipt

    asyncio.run(run())


def test_submit_sealed_places_a_resumed_non_zero_index_receipt_in_its_own_slot() -> None:
    async def run() -> None:
        prepared = _deterministic_prepared([b"item zero", b"item one", b"item two"], 1)
        uri_zero = "ar://" + "0" * 43
        uri_one = "ar://" + "1" * 43
        uri_two = "ar://" + "2" * 43
        # The receipt covers the MIDDLE item (index 1); resuming only item 0
        # cannot tell correct placement apart from a receipts-first ordering.
        receipt = UploadReceipt(
            item_id=prepared.items[1].item_id,
            uri=uri_one,
            ciphertext_sha256=hashlib.sha256(prepared.items[1].ciphertext).digest(),
            bytes=len(prepared.items[1].ciphertext),
        )
        handler = _ScriptedHandler(
            [
                (200, _quote_body()),
                (200, _uploads_body(uri_zero)),
                (200, _uploads_body(uri_two)),
                (202, PUBLISH_BODY),
            ]
        )
        async with _client(handler) as client:
            submission = await client.poe.submit_sealed(prepared=prepared, uploaded=[receipt])

        # Only items 0 and 2 upload, each under its own deterministic key.
        assert handler.call_count == 4
        assert handler.captured[1].multipart_file_bytes() == prepared.items[0].ciphertext
        assert handler.captured[1].headers.get(
            "idempotency-key"
        ) == prepared.upload_idempotency_key(0)
        assert handler.captured[2].multipart_file_bytes() == prepared.items[2].ciphertext
        assert handler.captured[2].headers.get(
            "idempotency-key"
        ) == prepared.upload_idempotency_key(2)
        # The resumed receipt occupies the MIDDLE slot of the URI + receipt lists.
        assert submission.uris == (uri_zero, uri_one, uri_two)
        assert submission.uploads[1] == receipt

    asyncio.run(run())


def test_submit_sealed_rejects_invalid_receipts_before_any_network() -> None:
    async def run() -> None:
        prepared = _deterministic_prepared([b"first plaintext"], 1)
        item = prepared.items[0]
        good_digest = hashlib.sha256(item.ciphertext).digest()
        valid_uri = "ar://" + "A" * 43
        good = UploadReceipt(
            item_id=item.item_id,
            uri=valid_uri,
            ciphertext_sha256=good_digest,
            bytes=len(item.ciphertext),
        )
        cases: list[list[UploadReceipt]] = [
            # Unknown item id.
            [
                UploadReceipt(
                    item_id="00" * 32,
                    uri=valid_uri,
                    ciphertext_sha256=good_digest,
                    bytes=len(item.ciphertext),
                )
            ],
            # Digest mismatch.
            [
                UploadReceipt(
                    item_id=item.item_id,
                    uri=valid_uri,
                    ciphertext_sha256=b"\x00" * 32,
                    bytes=len(item.ciphertext),
                )
            ],
            # Byte-count mismatch.
            [
                UploadReceipt(
                    item_id=item.item_id,
                    uri=valid_uri,
                    ciphertext_sha256=good_digest,
                    bytes=1,
                )
            ],
            # Empty URI — not a valid Arweave ar://<43-char txid>.
            [
                UploadReceipt(
                    item_id=item.item_id,
                    uri="",
                    ciphertext_sha256=good_digest,
                    bytes=len(item.ciphertext),
                )
            ],
            # Malformed Arweave URI (a sealed ciphertext receipt must be a strict
            # ar://<43-char txid>): a fragment, wrong-length txid, or non-Arweave
            # scheme is rejected pre-network.
            [
                UploadReceipt(
                    item_id=item.item_id,
                    uri="ar://tooshort",
                    ciphertext_sha256=good_digest,
                    bytes=len(item.ciphertext),
                )
            ],
            # Duplicate receipt for the same item.
            [good, good],
        ]
        for uploaded in cases:
            handler = _refusing_handler()
            async with _client(handler) as client:
                with pytest.raises(SubmitSealedError) as exc:
                    await client.poe.submit_sealed(prepared=prepared, uploaded=uploaded)
            assert exc.value.uploads == ()
            assert isinstance(exc.value.cause, InvalidUploadReceiptError)
            # The rejection is pre-network: no quote was spent.
            assert handler.call_count == 0

    asyncio.run(run())


def test_submit_sealed_enforces_the_price_cap_before_uploading() -> None:
    async def run() -> None:
        prepared = _deterministic_prepared([b"capped"], 1)
        handler = _ScriptedHandler([(200, _quote_body(amount="1500000"))])
        async with _client(handler) as client:
            with pytest.raises(SubmitSealedError) as exc:
                await client.poe.submit_sealed(prepared=prepared, max_usd_micros=1_000_000)
        cause = exc.value.cause
        assert isinstance(cause, MaxUsdExceededError)
        assert cause.quoted_usd_micros == "1500000"
        assert cause.max_usd_micros == 1_000_000
        assert exc.value.uploads == ()
        # Only the quote was requested; nothing was uploaded or published.
        assert handler.call_count == 1

    asyncio.run(run())


def test_submit_sealed_caps_against_a_fresh_caller_preview() -> None:
    async def run() -> None:
        prepared = _deterministic_prepared([b"capped preview"], 1)
        # A fresh preview is consumed as the price lock without a quote request,
        # so the cap breach must be caught with zero network traffic. The
        # internal-quote cap test cannot exercise this consumption path.
        pricey = _quote_body(
            quote_id="preview-pricey", amount="1500000", expires_at="2100-01-01T00:00:00Z"
        )
        handler = _refusing_handler()
        async with _client(handler) as client:
            with pytest.raises(SubmitSealedError) as exc:
                await client.poe.submit_sealed(
                    prepared=prepared, quote=cast("Any", pricey), max_usd_micros=1_000_000
                )
        cause = exc.value.cause
        assert isinstance(cause, MaxUsdExceededError)
        assert cause.quoted_usd_micros == "1500000"
        assert cause.max_usd_micros == 1_000_000
        assert exc.value.uploads == ()
        assert handler.call_count == 0

    asyncio.run(run())


def test_submit_sealed_consumes_a_fresh_caller_quote_and_replaces_a_stale_one() -> None:
    async def run() -> None:
        prepared = _deterministic_prepared([b"quoted"], 1)
        uri = "ar://" + "F" * 43

        # A fresh preview is consumed as the price lock: no quote request goes
        # out, and the publish carries the preview's id.
        fresh = _quote_body(quote_id="preview-fresh", expires_at="2100-01-01T00:00:00Z")
        handler = _ScriptedHandler([(200, _uploads_body(uri)), (202, PUBLISH_BODY)])
        async with _client(handler) as client:
            submission = await client.poe.submit_sealed(prepared=prepared, quote=cast("Any", fresh))
        assert handler.call_count == 2
        assert handler.captured[1].json()["quote_id"] == "preview-fresh"
        assert submission.quote["quote_id"] == "preview-fresh"

        # A stale preview is silently replaced by a fresh internal quote.
        stale = _quote_body(quote_id="preview-stale", expires_at="2000-01-01T00:00:00Z")
        handler = _ScriptedHandler(
            [(200, _quote_body()), (200, _uploads_body(uri)), (202, PUBLISH_BODY)]
        )
        async with _client(handler) as client:
            await client.poe.submit_sealed(prepared=prepared, quote=cast("Any", stale))
        assert handler.call_count == 3
        assert handler.captured[2].json()["quote_id"] == QUOTE_ID

    asyncio.run(run())


def test_submit_sealed_requotes_after_uploads_when_the_lock_expired() -> None:
    async def run() -> None:
        prepared = _deterministic_prepared([b"slow upload"], 1)
        uri = "ar://" + "G" * 43
        # The internal quote arrives already expired, so after the upload the
        # helper re-quotes and publishes against the SECOND lock.
        handler = _ScriptedHandler(
            [
                (200, _quote_body(quote_id="lock-1", expires_at="2000-01-01T00:00:00Z")),
                (200, _uploads_body(uri)),
                (200, _quote_body(quote_id="lock-2", expires_at="2100-01-01T00:00:00Z")),
                (202, PUBLISH_BODY),
            ]
        )
        async with _client(handler) as client:
            submission = await client.poe.submit_sealed(prepared=prepared)
        assert handler.call_count == 4
        assert handler.captured[3].json()["quote_id"] == "lock-2"
        assert submission.quote["quote_id"] == "lock-2"

        # The refreshed price is re-checked against the cap; a breach carries
        # the completed receipts so the paid upload is not lost.
        handler = _ScriptedHandler(
            [
                (200, _quote_body(quote_id="lock-1", expires_at="2000-01-01T00:00:00Z")),
                (200, _uploads_body(uri)),
                (
                    200,
                    _quote_body(
                        quote_id="lock-2", amount="9000000", expires_at="2100-01-01T00:00:00Z"
                    ),
                ),
            ]
        )
        async with _client(handler) as client:
            with pytest.raises(SubmitSealedError) as exc:
                await client.poe.submit_sealed(prepared=prepared, max_usd_micros=1_000_000)
        assert isinstance(exc.value.cause, MaxUsdExceededError)
        assert len(exc.value.uploads) == 1
        assert exc.value.uploads[0].uri == uri

    asyncio.run(run())


def test_submit_sealed_failure_after_upload_carries_receipts_and_resume_completes() -> None:
    async def run() -> None:
        prepared = _deterministic_prepared([b"first plaintext", b"second plaintext"], 1)
        uri_a = "ar://" + "D" * 43

        # The first attempt uploads item 0, then fails on item 1's upload: the
        # error must hand back item 0's receipt.
        handler = _ScriptedHandler(
            [
                (200, _quote_body()),
                (200, _uploads_body(uri_a)),
                (200, _FAILED_UPLOADS_BODY),
            ]
        )
        async with _client(handler) as client:
            with pytest.raises(SubmitSealedError) as exc:
                await client.poe.submit_sealed(prepared=prepared)
        assert isinstance(exc.value.cause, PartialUploadError)
        assert len(exc.value.uploads) == 1
        assert exc.value.uploads[0].item_id == prepared.items[0].item_id
        assert exc.value.uploads[0].uri == uri_a

        # The retry resumes from the carried receipts: item 0 is never
        # re-uploaded, only item 1 flows, and the publish completes.
        uri_b = "ar://" + "E" * 43
        handler = _ScriptedHandler(
            [
                (200, _quote_body()),
                (200, _uploads_body(uri_b)),
                (202, PUBLISH_BODY),
            ]
        )
        async with _client(handler) as client:
            submission = await client.poe.submit_sealed(
                prepared=prepared, uploaded=exc.value.uploads
            )
        assert handler.call_count == 3
        assert handler.captured[1].multipart_file_bytes() == prepared.items[1].ciphertext
        assert submission.uris == (uri_a, uri_b)

    asyncio.run(run())


def test_submit_sealed_publish_failure_carries_all_receipts() -> None:
    """A publish failure must also carry every receipt: the record bytes are
    reproducible from the artifact, so with the receipts nothing is lost."""

    async def run() -> None:
        prepared = _deterministic_prepared([b"published"], 1)
        uri = "ar://" + "H" * 43
        handler = _ScriptedHandler(
            [
                (200, _quote_body()),
                (200, _uploads_body(uri)),
                (
                    402,
                    {
                        "status": 402,
                        "code": "insufficient-funds",
                        "title": "Insufficient funds",
                    },
                ),
            ]
        )
        async with _client(handler) as client:
            with pytest.raises(SubmitSealedError) as exc:
                await client.poe.submit_sealed(prepared=prepared)
        assert isinstance(exc.value.cause, InsufficientFundsError)
        assert len(exc.value.uploads) == 1
        assert exc.value.uploads[0].uri == uri

    asyncio.run(run())


# ---------------------------------------------------------------------------
# The reworked merkle flow (internal quote, leaf_alg, deterministic key)
# ---------------------------------------------------------------------------


def test_publish_merkle_threads_leaf_alg_into_the_uploaded_leaves_list() -> None:
    async def run() -> None:
        leaves: list[bytes | str] = [hashlib.sha256(bytes([i])).digest() for i in range(3)]
        ar_uri = "ar://" + "X" * 43

        async def run_once(leaf_alg: str | None) -> _Captured:
            handler = _ScriptedHandler(
                [
                    (200, _quote_body()),
                    (200, _uploads_body(ar_uri)),
                    (202, PUBLISH_BODY),
                ]
            )
            async with _client(handler) as client:
                await client.poe.publish_merkle(leaves=leaves, leaf_alg=leaf_alg)
            return handler.captured[1]

        # With leaf_alg: the uploaded leaves-list carries the advisory claim.
        upload_req = await run_once("sha2-256")
        with_alg_bytes = upload_req.multipart_file_bytes()
        decoded = cbor2.loads(with_alg_bytes)
        assert decoded["leaf_alg"] == "sha2-256"
        # The upload rode the deterministic content-derived idempotency key.
        expected_key = "merkle1-" + hashlib.sha256(with_alg_bytes).hexdigest()[:32]
        assert upload_req.headers.get("idempotency-key") == expected_key

        # Without leaf_alg: the field is absent, exactly as before the rework.
        without_alg_bytes = (await run_once(None)).multipart_file_bytes()
        assert "leaf_alg" not in cbor2.loads(without_alg_bytes)

    asyncio.run(run())


def test_publish_merkle_enforces_the_price_cap_and_requotes_when_stale() -> None:
    async def run() -> None:
        leaves: list[bytes | str] = [hashlib.sha256(bytes([i])).digest() for i in range(2)]

        # The cap refuses before any upload.
        handler = _ScriptedHandler([(200, _quote_body(amount="1500000"))])
        async with _client(handler) as client:
            with pytest.raises(MaxUsdExceededError):
                await client.poe.publish_merkle(leaves=leaves, max_usd_micros=1_000_000)
        assert handler.call_count == 1

        # An expired lock is refreshed after the upload; the publish consumes
        # the second quote.
        ar_uri = "ar://" + "Y" * 43
        handler = _ScriptedHandler(
            [
                (200, _quote_body(quote_id="lock-1", expires_at="2000-01-01T00:00:00Z")),
                (200, _uploads_body(ar_uri)),
                (200, _quote_body(quote_id="lock-2", expires_at="2100-01-01T00:00:00Z")),
                (202, PUBLISH_BODY),
            ]
        )
        async with _client(handler) as client:
            out = await client.poe.publish_merkle(leaves=leaves)
        assert handler.call_count == 4
        publish_body = handler.captured[3].json()
        assert publish_body["quote_id"] == "lock-2"
        # The response archives the exact published record bytes.
        assert out["record_bytes"] == bytes.fromhex(publish_body["record"])

    asyncio.run(run())


def test_publish_merkle_re_caps_after_a_stale_quote_refresh() -> None:
    """The merkle re-cap fires against the REFRESHED price: the first lock is
    stale so the leaves-list still uploads, but the post-upload requote comes
    back above the cap and the publish is refused. The prior merkle cap test
    only exercised a refreshed price that stayed within the cap."""

    async def run() -> None:
        leaves: list[bytes | str] = [hashlib.sha256(bytes([i])).digest() for i in range(2)]
        ar_uri = "ar://" + "Z" * 43
        handler = _ScriptedHandler(
            [
                (200, _quote_body(quote_id="lock-1", expires_at="2000-01-01T00:00:00Z")),
                (200, _uploads_body(ar_uri)),
                (
                    200,
                    _quote_body(
                        quote_id="lock-2", amount="1500000", expires_at="2100-01-01T00:00:00Z"
                    ),
                ),
            ]
        )
        async with _client(handler) as client:
            with pytest.raises(MaxUsdExceededError) as exc:
                await client.poe.publish_merkle(leaves=leaves, max_usd_micros=1_000_000)
        assert exc.value.quoted_usd_micros == "1500000"
        # The refusal is post-upload (quote, upload, requote) but pre-publish.
        assert handler.call_count == 3

    asyncio.run(run())


def test_publish_merkle_reports_a_non_hex_leaf_as_invalid_leaves() -> None:
    """A malformed Merkle leaf is an ``INVALID_LEAVES`` failure, not the
    ``INVALID_DIGEST`` a precomputed-content digest would raise — the decode
    error code is the leaf's, matching the reference SDKs. Rejected before any
    network call."""

    async def run() -> None:
        handler = _refusing_handler()
        async with _client(handler) as client:
            with pytest.raises(PublishError) as exc:
                await client.poe.publish_merkle(leaves=["zz" * 32])
        assert exc.value.code == PublishError.INVALID_LEAVES
        assert handler.call_count == 0

    asyncio.run(run())


# ---------------------------------------------------------------------------
# The bare-str / bare-bytes items trap
# ---------------------------------------------------------------------------


def test_seal_prepare_rejects_a_bare_str_or_bytes_as_the_items_argument() -> None:
    """A lone ``str``/``bytes`` value is itself a sequence, so iterating it
    would silently seal one item per character/byte. Both entry points reject
    the misuse; a ``str`` element inside a real sequence stays valid."""
    recipients = _x25519_recipients(1)
    for bad in ("hello", b"hello", bytearray(b"hello")):
        with pytest.raises(SealPrepareError) as exc:
            seal_prepare(items=cast("Any", bad), recipients=recipients, kem="x25519")
        assert exc.value.code == SealPrepareError.INVALID_ITEMS
        with pytest.raises(SealPrepareError) as exc:
            seal_prepare_with_rng(
                items=cast("Any", bad),
                recipients=recipients,
                kem="x25519",
                rng=_counter_rng(0),
            )
        assert exc.value.code == SealPrepareError.INVALID_ITEMS

    # A str ELEMENT is one item, sealed as its UTF-8 bytes — not five items.
    prepared = seal_prepare_with_rng(
        items=["hello"], recipients=recipients, kem="x25519", rng=_counter_rng(0)
    )
    assert len(prepared.items) == 1
    assert prepared.items[0].item_id == hashlib.sha256(prepared.items[0].ciphertext).hexdigest()


# ---------------------------------------------------------------------------
# Receipt resolution on a pathological duplicate item_id
# ---------------------------------------------------------------------------


def test_validate_receipts_resolves_a_duplicate_item_id_to_the_first_index() -> None:
    """Two prepared items with identical ciphertext share an item_id; a receipt
    for that id resolves to the earliest matching item (index 0), matching the
    reference SDK's position-based lookup rather than last-wins."""
    single = _deterministic_prepared([b"dup"], 1)
    item = single.items[0]
    # Build the (otherwise unreachable) two-identical-item artifact directly:
    # a normal prepare gives every item a fresh key, so item_ids never collide.
    document = _document_of(single.kem, (item, item))
    prepared = PreparedSeal(
        kem=single.kem, items=(item, item), prepared_sha256=_fingerprint(document)
    )
    assert prepared.items[0].item_id == prepared.items[1].item_id

    receipt = UploadReceipt(
        item_id=item.item_id,
        uri="ar://" + "A" * 43,
        ciphertext_sha256=hashlib.sha256(item.ciphertext).digest(),
        bytes=len(item.ciphertext),
    )
    resolved = _validate_receipts(prepared, [receipt])
    assert set(resolved.keys()) == {0}


# ---------------------------------------------------------------------------
# from_json accepts only the canonical serialization
# ---------------------------------------------------------------------------


def test_from_json_accepts_only_the_canonical_serialization() -> None:
    """The canonical form is the only accepted form: the byte-equality backstop
    rejects every lexical variant that re-serializes to the same content, so all
    SDKs reach the same verdict by construction. Whitespace and an explicit null
    on an absent optional member are the representative cases."""
    prepared = _deterministic_prepared([b"canonical only"], 2)
    canonical = prepared.to_json()
    # The canonical form round-trips into the identical artifact.
    assert PreparedSeal.from_json(canonical) == prepared

    document = json.loads(canonical)

    # Insignificant whitespace: same content, not the byte-exact canonical form.
    spaced = json.dumps(document, sort_keys=True, indent=2)
    with pytest.raises(PreparedSealJsonError) as exc:
        PreparedSeal.from_json(spaced)
    assert exc.value.code == PreparedSealJsonError.INVALID

    # An explicit null on an absent optional slot member re-serializes away, so
    # the fingerprint still matches — only the canonical backstop catches it.
    with_null = json.loads(canonical)
    with_null["items"][0]["envelope"]["slots"][0]["kem_ct"] = None
    compact_with_null = json.dumps(
        with_null, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )
    with pytest.raises(PreparedSealJsonError) as exc:
        PreparedSeal.from_json(compact_with_null)
    assert exc.value.code == PreparedSealJsonError.INVALID


def test_from_json_rejects_a_duplicate_member_as_a_parse_error() -> None:
    """A repeated member makes the fingerprint ambiguous; the parser rejects a
    duplicate at any level (here, inside an item's ``hashes`` object)."""
    canonical = _deterministic_prepared([b"dup member"], 1).to_json()
    needle = '"hashes":{'
    start = canonical.index(needle) + len(needle)
    end = canonical.index("}", start)
    inner = canonical[start:end]  # e.g. "sha2-256":"<base64url>"
    with_duplicate = canonical[:end] + "," + inner + canonical[end:]
    with pytest.raises(PreparedSealJsonError) as exc:
        PreparedSeal.from_json(with_duplicate)
    assert exc.value.code == PreparedSealJsonError.PARSE


def test_from_json_reports_a_lone_surrogate_as_prepared_seal_error() -> None:
    """A JSON string escape can decode to a lone surrogate, which has no UTF-8
    encoding. It must surface as a typed PreparedSealJsonError, never a raw
    UnicodeEncodeError leaking out of the canonicalization."""
    document = json.loads(_deterministic_prepared([b"surrogate"], 1).to_json())
    # A surrogate in a hashes key reaches the canonical-form fingerprint before
    # any structural decode; ensure_ascii emits it as a \ud800 escape.
    document["items"][0]["hashes"]["\ud800"] = "A" * 43
    text = json.dumps(document)
    with pytest.raises(PreparedSealJsonError) as exc:
        PreparedSeal.from_json(text)
    assert exc.value.code == PreparedSealJsonError.INVALID


# ---------------------------------------------------------------------------
# Package surface
# ---------------------------------------------------------------------------


def test_sealed_helpers_are_importable_from_the_client_package() -> None:
    """The two-phase surface documented in the README imports from
    ``cardanowall.client``: the quote/submit/one-shot helpers, not only
    ``seal_prepare``."""
    from cardanowall.client import (
        publish_sealed,
        quote_prepared_seal,
        submit_sealed,
    )

    assert callable(quote_prepared_seal)
    assert callable(submit_sealed)
    assert callable(publish_sealed)


# ---------------------------------------------------------------------------
# Passphrase two-phase publishing (the shared-secret key path)
# ---------------------------------------------------------------------------

_PASSPHRASE = "correct horse battery staple"


def _deterministic_passphrase_prepared(plaintexts: list[bytes]) -> PreparedPassphraseSeal:
    """A reproducible passphrase prepared seal (counter rng from 0, registry
    floor params) — the fastest Argon2 profile still passes the floor."""
    return passphrase_seal_prepare_with_rng(
        items=plaintexts,
        passphrase=_PASSPHRASE,
        params=PassphraseKdfParams(m=65536, t=3, p=1),
        rng=_counter_rng(0),
    )


def test_submit_passphrase_sealed_exact_quote_equals_published_record_bytes() -> None:
    """The passphrase quote is exact build-and-measure: the ``record_bytes`` it
    prices must equal the length of the record actually published against a real
    fixed-width Arweave receipt. A mis-charge would surface as a size mismatch
    here (the finding the strict receipt-URI validation closed)."""

    async def run() -> None:
        prepared = _deterministic_passphrase_prepared([b"passphrase submit"])
        ar_uri = "ar://" + "P" * 43
        handler = _ScriptedHandler(
            [
                (200, _quote_body()),
                (200, _uploads_body(ar_uri)),
                (202, PUBLISH_BODY),
            ]
        )
        async with _client(handler) as client:
            out = await client.poe.submit_passphrase_sealed(prepared=prepared)

        assert handler.call_count == 3
        quote_body = handler.captured[0].json()
        publish_body = handler.captured[2].json()
        published = bytes.fromhex(publish_body["record"])
        # The exact-measure quote priced precisely the bytes that were published.
        assert quote_body["record_bytes"] == len(published)
        assert out.record_bytes == published
        assert out.uris == (ar_uri,)
        # The upload rode the deterministic per-item passphrase idempotency key.
        assert handler.captured[1].headers.get("idempotency-key") == (
            prepared.upload_idempotency_key(0)
        )
        assert prepared.upload_idempotency_key(0).startswith("pwseal1-")
        # The published bytes equal the directly-assembled record for the URI,
        # and that record validates structurally.
        direct = await encode_passphrase_sealed_record(prepared, [ar_uri])
        assert direct == published
        assert isinstance(validate(published), ValidateOk)

    asyncio.run(run())


def test_submit_passphrase_sealed_resumes_from_a_validated_receipt() -> None:
    """A receipt from a prior attempt skips the ciphertext upload: the submit
    quotes and publishes without a /poe/uploads call."""

    async def run() -> None:
        prepared = _deterministic_passphrase_prepared([b"resume me"])
        ar_uri = "ar://" + "Q" * 43
        receipt = UploadReceipt(
            item_id=prepared.items[0].item_id,
            uri=ar_uri,
            ciphertext_sha256=hashlib.sha256(prepared.items[0].ciphertext).digest(),
            bytes=len(prepared.items[0].ciphertext),
        )
        handler = _ScriptedHandler([(200, _quote_body()), (202, PUBLISH_BODY)])
        async with _client(handler) as client:
            out = await client.poe.submit_passphrase_sealed(prepared=prepared, uploaded=[receipt])
        # No /poe/uploads request: quote then publish only.
        assert [c.path for c in handler.captured] == ["/api/v1/poe/quote", "/api/v1/poe/publish"]
        assert out.uris == (ar_uri,)
        assert out.uploads[0].uri == ar_uri

    asyncio.run(run())


def test_submit_passphrase_sealed_rejects_a_non_arweave_receipt_uri() -> None:
    """A sealed ciphertext always lives on Arweave, so a resume receipt whose
    URI is not a strict ``ar://<43-char txid>`` is rejected pre-network."""

    async def run() -> None:
        prepared = _deterministic_passphrase_prepared([b"bad receipt"])
        receipt = UploadReceipt(
            item_id=prepared.items[0].item_id,
            uri="ipfs://QmbFMke1KXqnYyBBWxB74N4c5SBnJMVAiMNRcGu6x1AwQH",
            ciphertext_sha256=hashlib.sha256(prepared.items[0].ciphertext).digest(),
            bytes=len(prepared.items[0].ciphertext),
        )
        handler = _refusing_handler()
        async with _client(handler) as client:
            with pytest.raises(SubmitSealedError) as exc:
                await client.poe.submit_passphrase_sealed(prepared=prepared, uploaded=[receipt])
        assert isinstance(exc.value.cause, InvalidUploadReceiptError)
        # The rejection is pre-network: no quote was spent.
        assert handler.call_count == 0


def test_passphrase_sealed_record_rejects_a_non_fetch_set_uri() -> None:
    """The pure assembly seam refuses any URI outside the canonical fetch set,
    so a producer never emits a record local validation would reject."""
    prepared = _deterministic_passphrase_prepared([b"assembly seam"])
    with pytest.raises(SealPrepareError) as exc:
        passphrase_sealed_record(prepared, ["ar://tooshort"])
    assert exc.value.code == SealPrepareError.INVALID_URI
