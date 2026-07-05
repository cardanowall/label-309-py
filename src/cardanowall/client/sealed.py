"""Two-phase sealed-PoE publishing.

Sealing is randomized by design (a fresh content key, nonce, and per-slot KEM
material on every wrap), so any helper that couples encryption to the network
round-trips makes a failed publish expensive to retry: the retry re-encrypts,
pays for a second ciphertext upload, and produces different record bytes that
can never deduplicate gateway-side. This module splits the flow at that seam:

- :func:`seal_prepare` — phase 1, pure and offline: hash and encrypt every
  item to a shared recipient set under one KEM, returning a
  :class:`PreparedSeal`. The artifact serializes to the versioned portable
  ``prepared_seal_json_v1`` format (:meth:`PreparedSeal.to_json` /
  :meth:`PreparedSeal.from_json`), so a caller can persist it and retry a
  publish without ever re-encrypting.
- :func:`quote_prepared_seal` — a price preview for a prepared seal. Nothing
  is uploaded; UIs surface the price before committing to storage.
- :func:`sealed_record` / :func:`encode_sealed_record` — pure assembly seams:
  prepared material + one uploaded URI per item → the Label 309 record
  (object form or canonical bytes). Air-gapped flows sign and archive these
  bytes without a network connection.
- :func:`submit_sealed` — phase 2, the online orchestrator: exact-size quote
  (Arweave transaction ids are fixed-width, so the record size is known
  before any upload) → price-cap check → per-item ciphertext upload under a
  deterministic idempotency key → quote refresh when a slow upload outlived
  the price lock → encode (optionally sign) → publish. Every error raised
  after a completed upload carries the finished :class:`UploadReceipt` s
  (:attr:`SubmitSealedError.uploads`), so a retry resumes from persisted
  receipts instead of re-paying storage.
- :func:`publish_sealed` — the one-shot convenience wrapper:
  :func:`seal_prepare` followed by :func:`submit_sealed` in a single call.

The portable artifact: ``prepared_seal_json_v1``
------------------------------------------------

The serialized form is deliberately rigid so every SDK produces identical
bytes for identical prepared material:

- snake_case keys; byte fields are base64url **without padding**; integers
  are JSON numbers; no floats, no timestamps.
- The canonical form is compact UTF-8 JSON (no insignificant whitespace)
  with object keys sorted lexicographically by byte order at every nesting
  level.
- ``prepared_sha256`` is the lowercase-hex SHA-256 of the canonical form
  with the ``prepared_sha256`` member itself omitted.
  :meth:`PreparedSeal.from_json` recomputes and verifies it, rejecting a
  corrupted artifact.
- Each ``item_id`` is the lowercase-hex SHA-256 of that item's ciphertext.
- The deterministic per-item upload idempotency key is
  ``"seal1-" + prepared_sha256[:32] + "-" + <item index>``, so a
  crash-and-retry can never double-pay for the same ciphertext upload.

Parity twin: the ``client/sealed`` module of the Rust SDK (crate
``cardanowall``) and the sealed helpers of ``@cardanowall/sdk-ts``.
"""

from __future__ import annotations

import base64
import binascii
import builtins
import json
import re
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import TypedDict, cast

from cardanowall._crypto.hash import sha256
from cardanowall._crypto.sealed_poe import (
    AEAD_CHACHA20_POLY1305_STREAM64K,
    KEM_MLKEM768X25519,
    KEM_X25519,
    EciesSealedPoeError,
    SealedEnvelope,
    SealedPoeOutput,
    SealedSlot,
    ecies_sealed_poe_wrap,
)
from cardanowall.estimate import ItemShape, RecordShape, estimate_record_bytes
from cardanowall.poe_standard import Item, PoeRecord

from .invalid_upload_receipt_error import InvalidUploadReceiptError
from .publish import (
    Signer,
    SupportedHashAlg,
    SupportedKem,
    _arweave_uri_placeholder,
    _assert_signer,
    _encode_record,
    _enforce_max_usd_micros,
    _envelope_to_wire,
    _hash_content,
    _post_publish,
    _post_quote,
    _quote_is_fresh,
    _QuoteRequest,
    _refresh_quote_if_stale,
    _ResolvedPublishConfig,
    _to_bytes,
    _upload_blob,
)
from .types import PublishResponse, QuoteResponse

#: The version literal of the portable prepared-seal serialization.
PREPARED_SEAL_JSON_VERSION = "prepared_seal_json_v1"

# The prefix of the deterministic per-item upload idempotency key.
_SEAL_UPLOAD_KEY_PREFIX = "seal1-"
# How many leading hex characters of `prepared_sha256` the upload key carries.
_UPLOAD_KEY_FINGERPRINT_CHARS = 32

_X25519_PUBLIC_KEY_LENGTH = 32
_MLKEM768X25519_PUBLIC_KEY_LENGTH = 1216
_X25519_EPHEMERAL_SECRET_LENGTH = 32
_MLKEM768X25519_ESEED_LENGTH = 64
_CEK_LENGTH = 32
_ENVELOPE_NONCE_LENGTH = 24
_SLOTS_MAC_LENGTH = 32
_SLOT_WRAP_LENGTH = 48
_SLOT_EPK_LENGTH = 32
_SLOT_KEM_CT_LENGTH = 1120
_DIGEST_LENGTH = 32
_SUPERSEDES_HEX_LENGTH = 64

#: A caller-supplied byte source for :func:`seal_prepare_with_rng`: called
#: with a byte count, returns exactly that many bytes.
RngFill = Callable[[int], bytes]


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class SealPrepareError(Exception):
    """A failure of the pure sealed phases: :func:`seal_prepare` or the
    :func:`sealed_record` assembly seam.

    ``code`` discriminator values:

    - ``"NO_ITEMS"`` — the input carried no items.
    - ``"INVALID_ITEMS"`` — ``items`` was a single ``str`` or ``bytes`` value
      rather than a sequence of items. A lone ``str`` is a sequence of its
      characters and a lone ``bytes`` a sequence of its byte values, so
      iterating one would silently seal one item per element; the misuse is
      rejected instead. A ``str`` *element* of the sequence stays valid (it is
      sealed as its UTF-8 bytes).
    - ``"INVALID_RECIPIENT"`` — the recipient set was empty or a recipient
      public key was the wrong length for the chosen KEM (32 bytes for
      x25519, 1216 bytes for the X-Wing hybrid).
    - ``"URI_COUNT_MISMATCH"`` — the URI list does not carry exactly one
      storage URI per prepared item.
    - ``"INVALID_SUPERSEDES"`` — ``supersedes`` was not the 64-hex hash of
      the superseded transaction.
    - ``"CRYPTO_FAILURE"`` — the sealed-PoE wrap or another cryptographic
      step failed.
    """

    NO_ITEMS = "NO_ITEMS"
    INVALID_ITEMS = "INVALID_ITEMS"
    INVALID_RECIPIENT = "INVALID_RECIPIENT"
    URI_COUNT_MISMATCH = "URI_COUNT_MISMATCH"
    INVALID_SUPERSEDES = "INVALID_SUPERSEDES"
    CRYPTO_FAILURE = "CRYPTO_FAILURE"

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code: str = code


class PreparedSealJsonError(Exception):
    """A failure to parse or verify a ``prepared_seal_json_v1`` document.

    ``code`` discriminator values:

    - ``"PARSE"`` — the document is not valid JSON for the schema
      (including unknown or duplicate members).
    - ``"UNSUPPORTED_VERSION"`` — the document declares a version this SDK
      does not implement.
    - ``"INVALID"`` — a field violates the format's structural rules (bad
      base64url, a wrong-length component, an ``item_id`` that does not hash
      its ciphertext, an inconsistent KEM, ...).
    - ``"FINGERPRINT_MISMATCH"`` — the stored ``prepared_sha256`` does not
      match the recomputed fingerprint of the canonical form; the artifact
      was corrupted in transit.
    """

    PARSE = "PARSE"
    UNSUPPORTED_VERSION = "UNSUPPORTED_VERSION"
    INVALID = "INVALID"
    FINGERPRINT_MISMATCH = "FINGERPRINT_MISMATCH"

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code: str = code


class SubmitSealedError(Exception):
    """The terminal error of :func:`submit_sealed` / :func:`publish_sealed`.

    Storage uploads are paid work, so an error raised after any upload
    completed carries the finished :class:`UploadReceipt` s: persist
    :attr:`uploads` and pass them back via the ``uploaded`` argument on the
    retry, and the already-uploaded ciphertexts are never paid for again.

    :attr:`cause` is the underlying failure (also chained as
    ``__cause__``).
    """

    def __init__(self, uploads: Sequence[UploadReceipt], cause: BaseException) -> None:
        super().__init__(
            f"sealed submit failed with {len(uploads)} completed upload receipt(s): {cause}"
        )
        self.uploads: tuple[UploadReceipt, ...] = tuple(uploads)
        self.cause: BaseException = cause


# ---------------------------------------------------------------------------
# Receipts and results
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class UploadReceipt:
    """A validated resume token for one completed ciphertext upload — never a
    bare URI.

    Plainly constructible: a caller persists the fields (e.g. as JSON of its
    own shape) and rebuilds the receipt on retry. :func:`submit_sealed`
    validates every field against the prepared material before honouring it.
    """

    #: The prepared item this receipt covers (:attr:`PreparedSealItem.item_id`).
    item_id: str
    #: The storage URI the upload committed (e.g. ``ar://<tx>``).
    uri: str
    #: The SHA-256 of the uploaded ciphertext (32 bytes).
    ciphertext_sha256: builtins.bytes
    #: The uploaded byte count.
    bytes: int


@dataclass(frozen=True)
class SealedSubmission:
    """The result of a successful :func:`submit_sealed` / :func:`publish_sealed`."""

    #: The gateway's publish response.
    response: PublishResponse
    #: The exact canonical-CBOR record bytes that were published — archive
    #: them (e.g. as ``record_hex`` in a receipt).
    record_bytes: bytes
    #: The storage URI of each item's ciphertext, in item order.
    uris: tuple[str, ...]
    #: The upload receipts, in item order. Persist them: a retry after a
    #: later failure resumes from them via the ``uploaded`` argument.
    uploads: tuple[UploadReceipt, ...]
    #: The price lock the publish consumed.
    quote: QuoteResponse


# ---------------------------------------------------------------------------
# The prepared artifact
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PreparedSealItem:
    """One prepared item: the sealed form of one plaintext."""

    #: Lowercase-hex SHA-256 of the ciphertext — the item's stable identity
    #: across persistence and resume.
    item_id: str
    #: The segmented-STREAM ciphertext destined for off-chain storage.
    ciphertext: bytes
    #: The item's content-hash claims as ``(algorithm id, digest)`` pairs,
    #: sorted by algorithm id (byte order). Bound into the envelope's slots
    #: MAC.
    hashes: tuple[tuple[str, bytes], ...]
    #: The sealed envelope (the on-chain header material).
    envelope: SealedEnvelope


@dataclass(frozen=True)
class PreparedSeal:
    """The phase-1 artifact: every item sealed, nothing uploaded.

    Serializable via the versioned portable ``prepared_seal_json_v1`` format
    (:meth:`to_json` / :meth:`from_json`); see the module docs for the
    format's rules. The dataclass is frozen and every field is an immutable
    type, and construction re-verifies ``prepared_sha256`` against the
    content, so an in-memory artifact can never drift from its fingerprint.
    """

    #: The KEM every item is sealed under.
    kem: SupportedKem
    #: The prepared items, in input order.
    items: tuple[PreparedSealItem, ...]
    #: Lowercase-hex SHA-256 fingerprint of the canonical serialized form
    #: (with the fingerprint member itself omitted).
    prepared_sha256: str

    def __post_init__(self) -> None:
        computed = _fingerprint(_document_of(self.kem, self.items))
        if computed != self.prepared_sha256:
            raise ValueError(
                "prepared_sha256 does not match the artifact content; construct a "
                "PreparedSeal via seal_prepare() or PreparedSeal.from_json()"
            )

    def upload_idempotency_key(self, item_index: int) -> str:
        """The deterministic idempotency key for the item's ciphertext upload:
        ``"seal1-" + prepared_sha256[:32] + "-" + item_index``.

        Deriving the key from the artifact (not from randomness at upload
        time) closes the crash-before-persist window: a retry of the same
        prepared item always presents the same key, so the gateway's
        idempotency layer replays the original upload instead of charging for
        a second one.

        Raises :class:`IndexError` if ``item_index`` is out of range.
        """
        if not 0 <= item_index < len(self.items):
            raise IndexError(
                f"item_index {item_index} out of range for {len(self.items)} prepared item(s)"
            )
        fingerprint_prefix = self.prepared_sha256[:_UPLOAD_KEY_FINGERPRINT_CHARS]
        return f"{_SEAL_UPLOAD_KEY_PREFIX}{fingerprint_prefix}-{item_index}"

    def to_json(self) -> str:
        """Serialize to the portable ``prepared_seal_json_v1`` form (canonical:
        compact, byte-order-sorted keys, ``prepared_sha256`` included).
        """
        document = _document_of(self.kem, self.items)
        document["prepared_sha256"] = self.prepared_sha256
        return _canonical_json(document)

    @classmethod
    def from_json(cls, text: str) -> PreparedSeal:
        """Parse and verify a portable ``prepared_seal_json_v1`` document.

        The stored ``prepared_sha256`` is recomputed over the canonical form
        and must match; every structural rule of the format (component
        lengths, ``item_id`` = SHA-256 of the ciphertext, one consistent KEM)
        is re-validated. A final gate then requires the input to be the
        **exact** canonical serialization (``to_json`` of the reconstructed
        artifact): the canonical form is the only accepted form, so every
        lexical variant that re-serializes to the same content (an explicit
        ``null`` on an absent member, insignificant whitespace, unsorted keys,
        a non-minimal number) is rejected and every SDK reaches the same
        accept/reject verdict.

        Raises :class:`PreparedSealJsonError` on malformed JSON, an
        unsupported version, a structural violation, a fingerprint mismatch,
        or a non-canonical serialization.
        """
        try:
            root = json.loads(text, object_pairs_hook=_reject_duplicate_members)
        except _DuplicateMemberError as e:
            raise PreparedSealJsonError(
                PreparedSealJsonError.PARSE, f"duplicate member {e.member!r}"
            ) from e
        except (json.JSONDecodeError, ValueError) as e:
            raise PreparedSealJsonError(PreparedSealJsonError.PARSE, str(e)) from e

        document = _parse_document_shape(root)
        version = cast("str", document["version"])
        if version != PREPARED_SEAL_JSON_VERSION:
            raise PreparedSealJsonError(
                PreparedSealJsonError.UNSUPPORTED_VERSION,
                f"{version!r} (expected {PREPARED_SEAL_JSON_VERSION!r})",
            )
        stored = cast("str | None", document.pop("prepared_sha256", None))
        if stored is None:
            raise PreparedSealJsonError(
                PreparedSealJsonError.INVALID, "prepared_sha256 is required"
            )
        if not _is_lowercase_hex(stored, 64):
            raise PreparedSealJsonError(
                PreparedSealJsonError.INVALID,
                "prepared_sha256 must be 64 lowercase-hex characters",
            )
        # A JSON string escape can decode to a lone surrogate, which has no
        # UTF-8 encoding; the canonical form (and the fingerprint over it) must
        # be valid UTF-8, so surface that as a structural rejection rather than
        # letting an undeclared UnicodeEncodeError escape.
        try:
            computed = _fingerprint(document)
            if computed != stored:
                raise PreparedSealJsonError(
                    PreparedSealJsonError.FINGERPRINT_MISMATCH,
                    f"stored {stored} != computed {computed}",
                )

            kem_wire = cast("str", document["kem"])
            if kem_wire == KEM_X25519:
                kem: SupportedKem = "x25519"
            elif kem_wire == KEM_MLKEM768X25519:
                kem = "mlkem768x25519"
            else:
                raise PreparedSealJsonError(
                    PreparedSealJsonError.INVALID, f"unknown kem {kem_wire!r}"
                )
            item_documents = cast("list[dict[str, object]]", document["items"])
            if not item_documents:
                raise PreparedSealJsonError(
                    PreparedSealJsonError.INVALID, "items must be non-empty"
                )
            items = tuple(
                _decode_item_document(index, item, kem_wire)
                for index, item in enumerate(item_documents)
            )
            prepared = cls(kem=kem, items=items, prepared_sha256=stored)
            # Canonical-form backstop: only the exact canonical serialization is
            # accepted. The structural checks and the fingerprint above pin the
            # semantic content; this gate additionally rejects every accepted-
            # but-non-canonical lexical variant, keeping the verdict identical
            # across SDKs by construction.
            if prepared.to_json() != text:
                raise PreparedSealJsonError(
                    PreparedSealJsonError.INVALID,
                    "not the canonical prepared_seal_json_v1 serialization",
                )
        except UnicodeEncodeError as e:
            raise PreparedSealJsonError(
                PreparedSealJsonError.INVALID,
                "a string is not valid UTF-8 (a lone surrogate escape)",
            ) from e
        return prepared


# ---------------------------------------------------------------------------
# prepared_seal_json_v1 serialization
# ---------------------------------------------------------------------------


class _DuplicateMemberError(ValueError):
    """A JSON object carried the same member twice; the fingerprint would be
    ambiguous, so the document is rejected at parse time."""

    def __init__(self, member: str) -> None:
        super().__init__(f"duplicate member {member!r}")
        self.member = member


def _reject_duplicate_members(pairs: list[tuple[str, object]]) -> dict[str, object]:
    obj: dict[str, object] = {}
    for key, value in pairs:
        if key in obj:
            raise _DuplicateMemberError(key)
        obj[key] = value
    return obj


def _document_of(kem: str, items: Sequence[PreparedSealItem]) -> dict[str, object]:
    """Lower the in-memory artifact to its serialization document, without
    the fingerprint member (the form the fingerprint is computed over)."""
    return {
        "version": PREPARED_SEAL_JSON_VERSION,
        "kem": kem,
        "items": [_encode_item_document(item) for item in items],
    }


def _encode_item_document(item: PreparedSealItem) -> dict[str, object]:
    envelope = item.envelope
    slots: list[dict[str, str]] = []
    for slot in envelope.slots:
        if envelope.kem == KEM_X25519:
            slots.append(
                {
                    "epk": _base64url_encode(slot.epk if slot.epk is not None else b""),
                    "wrap": _base64url_encode(slot.wrap),
                }
            )
        else:
            slots.append(
                {
                    "kem_ct": _base64url_encode(slot.kem_ct if slot.kem_ct is not None else b""),
                    "wrap": _base64url_encode(slot.wrap),
                }
            )
    return {
        "item_id": item.item_id,
        "ciphertext": _base64url_encode(item.ciphertext),
        "hashes": {alg: _base64url_encode(digest) for alg, digest in item.hashes},
        "envelope": {
            "scheme": envelope.scheme,
            "aead": envelope.aead,
            "kem": envelope.kem,
            "nonce": _base64url_encode(envelope.nonce),
            "slots": slots,
            "slots_mac": _base64url_encode(envelope.slots_mac),
        },
    }


def _canonical_json(document: dict[str, object]) -> str:
    """The canonical serialization: compact JSON with keys sorted by byte
    order at every nesting level.

    Every key of the format is ASCII, so Python's code-point sort equals the
    byte-order sort the format pins.
    """
    return json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _fingerprint(document: dict[str, object]) -> str:
    """Lowercase-hex SHA-256 of the canonical form without the fingerprint
    member. The caller must pass a document with no ``prepared_sha256``."""
    return sha256(_canonical_json(document).encode("utf-8")).hex()


def _parse_error(detail: str) -> PreparedSealJsonError:
    return PreparedSealJsonError(PreparedSealJsonError.PARSE, detail)


def _require_object(
    value: object, context: str, allowed: frozenset[str], required: frozenset[str]
) -> dict[str, object]:
    """Strict-schema gate for one JSON object level: the member set must sit
    between ``required`` and ``allowed`` — unknown members are rejected so an
    unauthenticated field can never ride under a valid fingerprint."""
    if not isinstance(value, dict):
        raise _parse_error(f"{context} must be a JSON object")
    for key in value:
        if key not in allowed:
            raise _parse_error(f"{context} carries an unknown member {key!r}")
    for key in required:
        if key not in value:
            raise _parse_error(f"{context} is missing the member {key!r}")
    return cast("dict[str, object]", value)


def _require_str(value: object, context: str) -> str:
    if not isinstance(value, str):
        raise _parse_error(f"{context} must be a string")
    return value


def _parse_document_shape(root: object) -> dict[str, object]:
    """Validate the raw parsed JSON against the strict document schema and
    normalize it (explicit ``null`` on an optional member reads as absent),
    returning the document the fingerprint is computed over."""
    document = _require_object(
        root,
        "document",
        allowed=frozenset({"version", "kem", "items", "prepared_sha256"}),
        required=frozenset({"version", "kem", "items"}),
    )
    _require_str(document["version"], "version")
    _require_str(document["kem"], "kem")
    if "prepared_sha256" in document:
        if document["prepared_sha256"] is None:
            del document["prepared_sha256"]
        else:
            _require_str(document["prepared_sha256"], "prepared_sha256")
    items = document["items"]
    if not isinstance(items, list):
        raise _parse_error("items must be an array")
    for index, item in enumerate(items):
        _parse_item_shape(item, f"items[{index}]")
    return document


def _parse_item_shape(value: object, context: str) -> None:
    item = _require_object(
        value,
        context,
        allowed=frozenset({"item_id", "ciphertext", "hashes", "envelope"}),
        required=frozenset({"item_id", "ciphertext", "hashes", "envelope"}),
    )
    _require_str(item["item_id"], f"{context}.item_id")
    _require_str(item["ciphertext"], f"{context}.ciphertext")
    hashes = item["hashes"]
    if not isinstance(hashes, dict):
        raise _parse_error(f"{context}.hashes must be a JSON object")
    for alg, digest in hashes.items():
        _require_str(digest, f"{context}.hashes[{alg!r}]")
    envelope = _require_object(
        item["envelope"],
        f"{context}.envelope",
        allowed=frozenset({"scheme", "aead", "kem", "nonce", "slots", "slots_mac"}),
        required=frozenset({"scheme", "aead", "kem", "nonce", "slots", "slots_mac"}),
    )
    scheme = envelope["scheme"]
    if isinstance(scheme, bool) or not isinstance(scheme, int) or scheme < 0:
        raise _parse_error(f"{context}.envelope.scheme must be an unsigned integer")
    _require_str(envelope["aead"], f"{context}.envelope.aead")
    _require_str(envelope["kem"], f"{context}.envelope.kem")
    _require_str(envelope["nonce"], f"{context}.envelope.nonce")
    _require_str(envelope["slots_mac"], f"{context}.envelope.slots_mac")
    slots = envelope["slots"]
    if not isinstance(slots, list):
        raise _parse_error(f"{context}.envelope.slots must be an array")
    for slot_index, slot_value in enumerate(slots):
        slot_context = f"{context}.envelope.slots[{slot_index}]"
        slot = _require_object(
            slot_value,
            slot_context,
            allowed=frozenset({"epk", "kem_ct", "wrap"}),
            required=frozenset({"wrap"}),
        )
        _require_str(slot["wrap"], f"{slot_context}.wrap")
        for optional in ("epk", "kem_ct"):
            if optional in slot:
                if slot[optional] is None:
                    del slot[optional]
                else:
                    _require_str(slot[optional], f"{slot_context}.{optional}")


def _decode_item_document(index: int, item: dict[str, object], kem_wire: str) -> PreparedSealItem:
    """Decode and structurally validate one serialized item."""

    def invalid(detail: str) -> PreparedSealJsonError:
        return PreparedSealJsonError(PreparedSealJsonError.INVALID, f"items[{index}]: {detail}")

    ciphertext = _base64url_decode(cast("str", item["ciphertext"]))
    if ciphertext is None:
        raise invalid("ciphertext is not unpadded base64url")
    item_id = cast("str", item["item_id"])
    if not _is_lowercase_hex(item_id, 64):
        raise invalid("item_id must be 64 lowercase-hex characters")
    if item_id != sha256(ciphertext).hex():
        raise invalid("item_id is not the SHA-256 of the ciphertext")

    hash_documents = cast("dict[str, str]", item["hashes"])
    if not hash_documents:
        raise invalid("hashes must be non-empty")
    hashes: list[tuple[str, bytes]] = []
    for alg, digest_text in hash_documents.items():
        digest = _base64url_decode(digest_text)
        if digest is None:
            raise invalid(f"hashes[{alg!r}] is not unpadded base64url")
        if len(digest) != _DIGEST_LENGTH:
            raise invalid(f"hashes[{alg!r}] must be {_DIGEST_LENGTH} bytes")
        hashes.append((alg, digest))
    hashes.sort(key=lambda pair: pair[0].encode("utf-8"))

    envelope = cast("dict[str, object]", item["envelope"])
    scheme = cast("int", envelope["scheme"])
    if scheme != 1:
        raise invalid(f"envelope.scheme must be 1, got {scheme}")
    aead = cast("str", envelope["aead"])
    if aead != AEAD_CHACHA20_POLY1305_STREAM64K:
        raise invalid(f"envelope.aead must be {AEAD_CHACHA20_POLY1305_STREAM64K!r}")
    envelope_kem = cast("str", envelope["kem"])
    if envelope_kem != kem_wire:
        raise invalid("envelope.kem must match the document's kem")
    nonce = _base64url_decode(cast("str", envelope["nonce"]))
    if nonce is None or len(nonce) != _ENVELOPE_NONCE_LENGTH:
        raise invalid(
            f"envelope.nonce must be {_ENVELOPE_NONCE_LENGTH} bytes of unpadded base64url"
        )
    slots_mac = _base64url_decode(cast("str", envelope["slots_mac"]))
    if slots_mac is None or len(slots_mac) != _SLOTS_MAC_LENGTH:
        raise invalid(f"envelope.slots_mac must be {_SLOTS_MAC_LENGTH} bytes of unpadded base64url")
    slot_documents = cast("list[dict[str, str]]", envelope["slots"])
    if not slot_documents:
        raise invalid("envelope.slots must be non-empty")
    slots = _decode_slot_documents(slot_documents, kem_wire, invalid)

    return PreparedSealItem(
        item_id=item_id,
        ciphertext=ciphertext,
        hashes=tuple(hashes),
        envelope=SealedEnvelope(
            scheme=1,
            aead=aead,
            kem=envelope_kem,
            nonce=nonce,
            slots=slots,
            slots_mac=slots_mac,
        ),
    )


def _decode_slot_documents(
    slots: list[dict[str, str]],
    kem_wire: str,
    invalid: Callable[[str], PreparedSealJsonError],
) -> tuple[SealedSlot, ...]:
    """Decode the per-KEM slot array, enforcing the KEM-relevant field per
    slot: an x25519 slot carries ``epk``, a hybrid slot carries ``kem_ct``,
    and the other member must be absent."""
    out: list[SealedSlot] = []
    for slot_index, slot in enumerate(slots):
        wrap = _base64url_decode(slot["wrap"])
        if wrap is None or len(wrap) != _SLOT_WRAP_LENGTH:
            raise invalid(
                f"envelope.slots[{slot_index}].wrap must be {_SLOT_WRAP_LENGTH} bytes "
                "of unpadded base64url"
            )
        if kem_wire == KEM_X25519:
            if "kem_ct" in slot:
                raise invalid(f"envelope.slots[{slot_index}] carries kem_ct on an x25519 envelope")
            epk = _base64url_decode(slot["epk"]) if "epk" in slot else None
            if epk is None or len(epk) != _SLOT_EPK_LENGTH:
                raise invalid(
                    f"envelope.slots[{slot_index}].epk must be {_SLOT_EPK_LENGTH} bytes "
                    "of unpadded base64url"
                )
            out.append(SealedSlot(epk=epk, wrap=wrap))
        else:
            if "epk" in slot:
                raise invalid(
                    f"envelope.slots[{slot_index}] carries epk on an mlkem768x25519 envelope"
                )
            kem_ct = _base64url_decode(slot["kem_ct"]) if "kem_ct" in slot else None
            if kem_ct is None or len(kem_ct) != _SLOT_KEM_CT_LENGTH:
                raise invalid(
                    f"envelope.slots[{slot_index}].kem_ct must be {_SLOT_KEM_CT_LENGTH} "
                    "bytes of unpadded base64url"
                )
            out.append(SealedSlot(kem_ct=kem_ct, wrap=wrap))
    return tuple(out)


# ---------------------------------------------------------------------------
# Phase 1 — seal_prepare
# ---------------------------------------------------------------------------


def seal_prepare(
    *,
    items: Sequence[bytes | str],
    recipients: Sequence[bytes],
    kem: SupportedKem = "mlkem768x25519",
    hash_alg: SupportedHashAlg = "sha2-256",
) -> PreparedSeal:
    """Seal every item to the shared recipient set, drawing every secret from
    the operating-system CSPRNG. Pure and offline: no I/O, no network.

    One KEM covers the whole prepared set (mixing KEMs across slots is
    forbidden by the standard, and mixing them across the items of one record
    would silently weaken the strongest envelope to the weakest). ``items``
    must be a sequence of items; a ``str`` *element* is sealed as its UTF-8
    bytes, but a bare ``str`` or ``bytes`` passed as ``items`` is rejected
    (it would otherwise seal one item per character/byte) — wrap a lone value
    in a list, e.g. ``items=[value]``.

    Raises :class:`SealPrepareError` when ``items`` is a bare ``str``/``bytes``
    value, the input carries no items, the recipient set is empty or a key is
    the wrong length for the chosen KEM, or the cryptographic wrap fails.
    """
    return _prepare(items=items, recipients=recipients, kem=kem, hash_alg=hash_alg, rng=None)


def seal_prepare_with_rng(
    *,
    items: Sequence[bytes | str],
    recipients: Sequence[bytes],
    kem: SupportedKem = "mlkem768x25519",
    hash_alg: SupportedHashAlg = "sha2-256",
    rng: RngFill,
) -> PreparedSeal:
    """Deterministic twin of :func:`seal_prepare` for known-answer tests and
    reproducible vectors: every secret (content keys, nonces, per-slot KEM
    material, shuffle draws) is drawn from the caller-supplied ``rng``, in
    item order.

    ``rng(count)`` must return exactly ``count`` bytes. **Not secure for
    production use**: ``rng`` carries the entire confidentiality guarantee —
    a weak source yields predictable content keys with no error. Production
    code calls :func:`seal_prepare`, which pins the OS CSPRNG.

    Raises the same :class:`SealPrepareError` cases as :func:`seal_prepare`.
    """
    return _prepare(items=items, recipients=recipients, kem=kem, hash_alg=hash_alg, rng=rng)


def _prepare(
    *,
    items: Sequence[bytes | str],
    recipients: Sequence[bytes],
    kem: SupportedKem,
    hash_alg: SupportedHashAlg,
    rng: RngFill | None,
) -> PreparedSeal:
    """The shared prepare path: ``rng is None`` sources secrets from the OS
    CSPRNG inside the sealed-PoE wrap."""
    if isinstance(items, (str, bytes, bytearray)):
        # A lone str/bytes value IS a Sequence, so iterating it would seal one
        # item per character/byte instead of one item for the whole value.
        # Require an actual sequence of items; a str element inside it is fine.
        raise SealPrepareError(
            SealPrepareError.INVALID_ITEMS,
            "items must be a sequence of items (each bytes or str), not a single "
            "str or bytes value; wrap a lone value in a list, e.g. items=[value]",
        )
    if len(items) == 0:
        raise SealPrepareError(SealPrepareError.NO_ITEMS, "at least one item is required")
    if len(recipients) == 0:
        raise SealPrepareError(
            SealPrepareError.INVALID_RECIPIENT,
            "at least one recipient public key is required",
        )
    if kem not in (KEM_X25519, KEM_MLKEM768X25519):
        raise SealPrepareError(
            SealPrepareError.CRYPTO_FAILURE,
            f"kem={kem!r} unsupported (expected 'x25519' or 'mlkem768x25519')",
        )
    expected_length = (
        _X25519_PUBLIC_KEY_LENGTH if kem == KEM_X25519 else _MLKEM768X25519_PUBLIC_KEY_LENGTH
    )
    recipient_keys = [bytes(recipient) for recipient in recipients]
    if any(len(recipient) != expected_length for recipient in recipient_keys):
        raise SealPrepareError(
            SealPrepareError.INVALID_RECIPIENT,
            f"a recipient public key is not {expected_length} bytes for kem={kem!r}",
        )

    prepared_items: list[PreparedSealItem] = []
    for item in items:
        content = bytes(_to_bytes(item))
        digest = _hash_content(content, hash_alg)
        hashes: dict[str, bytes] = {hash_alg: digest}
        try:
            if rng is None:
                sealed = ecies_sealed_poe_wrap(
                    plaintext=content,
                    recipient_public_keys=recipient_keys,
                    hashes=hashes,
                    kem=kem,
                )
            else:
                sealed = _deterministic_wrap(content, recipient_keys, hashes, kem, rng)
        except EciesSealedPoeError as e:
            raise SealPrepareError(SealPrepareError.CRYPTO_FAILURE, str(e)) from e
        prepared_items.append(
            PreparedSealItem(
                item_id=sha256(sealed.ciphertext).hex(),
                ciphertext=sealed.ciphertext,
                hashes=((hash_alg, digest),),
                envelope=sealed.envelope,
            )
        )

    fingerprint = _fingerprint(_document_of(kem, prepared_items))
    return PreparedSeal(kem=kem, items=tuple(prepared_items), prepared_sha256=fingerprint)


def _deterministic_wrap(
    plaintext: bytes,
    recipient_keys: list[bytes],
    hashes: dict[str, bytes],
    kem: SupportedKem,
    rng: RngFill,
) -> SealedPoeOutput:
    """One deterministic wrap over the pinned cross-SDK draw order: content
    key (32) → envelope nonce (24) → per-slot KEM secret in recipient order
    (a 32-byte x25519 ephemeral scalar or a 64-byte X-Wing encapsulation
    seed) → the anonymity-shuffle index draws (4 bytes each, little-endian,
    rejection-sampled to an unbiased index).

    The shuffle normally runs *after* the per-recipient wrap, and the slots
    MAC binds the post-shuffle order. Each slot is a pure function of its own
    ``(recipient, secret, cek, nonce)`` tuple, so permuting the recipient and
    secret lists with the same permutation *before* the wrap (with the wrap's
    own shuffle disabled) produces the identical slot array, MAC, and
    ciphertext — while keeping the rng draw order identical across SDKs.
    """
    cek = _draw(rng, _CEK_LENGTH)
    nonce = _draw(rng, _ENVELOPE_NONCE_LENGTH)
    secret_length = (
        _X25519_EPHEMERAL_SECRET_LENGTH if kem == KEM_X25519 else _MLKEM768X25519_ESEED_LENGTH
    )
    slot_secrets = [_draw(rng, secret_length) for _ in recipient_keys]
    order = _shuffled_order(len(recipient_keys), rng)
    shuffled_recipients = [recipient_keys[i] for i in order]
    shuffled_secrets = [slot_secrets[i] for i in order]
    if kem == KEM_X25519:
        return ecies_sealed_poe_wrap(
            plaintext=plaintext,
            recipient_public_keys=shuffled_recipients,
            hashes=hashes,
            kem=kem,
            cek=cek,
            nonce=nonce,
            ephemeral_secrets=shuffled_secrets,
            skip_shuffle=True,
        )
    return ecies_sealed_poe_wrap(
        plaintext=plaintext,
        recipient_public_keys=shuffled_recipients,
        hashes=hashes,
        kem=kem,
        cek=cek,
        nonce=nonce,
        eseeds=shuffled_secrets,
        skip_shuffle=True,
    )


def _draw(rng: RngFill, count: int) -> bytes:
    out = bytes(rng(count))
    if len(out) != count:
        raise SealPrepareError(
            SealPrepareError.CRYPTO_FAILURE,
            f"rng returned {len(out)} byte(s), expected {count}",
        )
    return out


def _uniform_index_below(rng: RngFill, modulus: int) -> int:
    """An unbiased index in ``[0, modulus)`` via rejection sampling.

    A plain ``draw % modulus`` skews toward low residues whenever the modulus
    does not divide 2^32; the shuffle's whole purpose is a uniform
    permutation, so any 4-byte little-endian draw at or above the rejection
    ceiling is discarded and redrawn.
    """
    ceiling = (1 << 32) - ((1 << 32) % modulus)
    while True:
        draw = int.from_bytes(_draw(rng, 4), "little")
        if draw < ceiling:
            return draw % modulus


def _shuffled_order(count: int, rng: RngFill) -> list[int]:
    """The Fisher-Yates permutation the wrap's anonymity shuffle would apply,
    keyed by unbiased index draws from ``rng``. Fewer than two slots draw
    nothing."""
    order = list(range(count))
    for i in range(count - 1, 0, -1):
        j = _uniform_index_below(rng, i + 1)
        order[i], order[j] = order[j], order[i]
    return order


# ---------------------------------------------------------------------------
# Pure assembly seams
# ---------------------------------------------------------------------------


def sealed_record(
    prepared: PreparedSeal,
    uris: Sequence[str],
    supersedes: str | None = None,
) -> PoeRecord:
    """Assemble the Label 309 record from prepared material and the uploaded
    storage URIs — the pure seam air-gapped flows build on.

    ``uris`` must carry exactly one storage URI per prepared item, in item
    order. ``supersedes`` is the 64-hex hash of the transaction this record
    replaces, when any.

    Raises :class:`SealPrepareError` with code ``URI_COUNT_MISMATCH`` on a
    wrong URI count and ``INVALID_SUPERSEDES`` on a malformed supersedes
    hash.
    """
    if len(uris) != len(prepared.items):
        raise SealPrepareError(
            SealPrepareError.URI_COUNT_MISMATCH,
            f"expected {len(prepared.items)} storage uri(s), one per item, got {len(uris)}",
        )
    supersedes_bytes = _parse_supersedes_hex(supersedes) if supersedes is not None else None
    items: list[Item] = []
    for prepared_item, uri in zip(prepared.items, uris, strict=True):
        items.append(
            {
                # The artifact's hash map keys by algorithm id verbatim; the
                # wire type's Literal key set is a subset pin, so cast at the
                # boundary rather than re-narrowing every entry.
                "hashes": cast("dict[SupportedHashAlg, bytes]", dict(prepared_item.hashes)),
                "uris": [uri],
                "enc": _envelope_to_wire(prepared_item.envelope),
            }
        )
    record: PoeRecord = {"v": 1, "items": items}
    if supersedes_bytes is not None:
        record["supersedes"] = supersedes_bytes
    return record


async def encode_sealed_record(
    prepared: PreparedSeal,
    uris: Sequence[str],
    supersedes: str | None = None,
    signer: Signer | None = None,
) -> bytes:
    """Canonical-bytes twin of :func:`sealed_record`: assemble the record and
    encode it, attaching a path-1 COSE_Sign1 first when a signer is supplied.
    Air-gapped flows archive these exact bytes.

    Raises :class:`SealPrepareError`, :class:`~.publish.PublishError`, or an
    encoding error on an assembly, signer, or encoding failure.
    """
    if signer is not None:
        _assert_signer(signer)
    record = sealed_record(prepared, uris, supersedes)
    return await _encode_record(record, signer)


def _parse_supersedes_hex(value: str) -> bytes:
    """Parse a supersedes value into the 32-byte transaction hash the record
    carries."""
    if len(value) != _SUPERSEDES_HEX_LENGTH:
        raise SealPrepareError(
            SealPrepareError.INVALID_SUPERSEDES,
            "supersedes must be the 64-hex transaction hash",
        )
    try:
        return bytes.fromhex(value)
    except ValueError as e:
        raise SealPrepareError(
            SealPrepareError.INVALID_SUPERSEDES,
            "supersedes must be the 64-hex transaction hash",
        ) from e


# ---------------------------------------------------------------------------
# Quoting
# ---------------------------------------------------------------------------


def _prepared_quote_request(
    prepared: PreparedSeal, *, signed: bool, supersedes: bool
) -> _QuoteRequest:
    """The byte counts a prepared seal is priced against.

    The record side is the exact-width upper-bound estimate over the prepared
    shape with a fixed-width Arweave URI placeholder per item (a real
    ``ar://`` URI is always 5 + 43 characters, so the estimate is exact
    before any upload); the storage side is the exact ciphertext total.
    """
    shape = RecordShape(
        items=tuple(
            ItemShape(
                hash_algs=tuple(alg for alg, _ in item.hashes),
                uris=(_arweave_uri_placeholder(),),
                recipient_count=len(item.envelope.slots),
                kem=prepared.kem,
            )
            for item in prepared.items
        ),
        signed=signed,
        supersedes=supersedes,
        merkle=None,
    )
    return _QuoteRequest(
        record_bytes=estimate_record_bytes(shape),
        recipient_count=sum(len(item.envelope.slots) for item in prepared.items),
        file_bytes_total=sum(len(item.ciphertext) for item in prepared.items),
    )


async def quote_prepared_seal(
    config: _ResolvedPublishConfig,
    *,
    prepared: PreparedSeal,
    signer: Signer | None = None,
    supersedes: str | None = None,
) -> QuoteResponse:
    """Price a prepared seal without uploading anything — the preview UIs
    show before the user commits to storage. The returned quote may later be
    passed to :func:`submit_sealed` via its ``quote`` argument.

    ``signer`` and ``supersedes`` only affect the price through their
    presence (a signed or superseding record is larger); the signer is not
    invoked.

    Raises a signer-shape or HTTP error.
    """
    if signer is not None:
        _assert_signer(signer)
    request = _prepared_quote_request(
        prepared, signed=signer is not None, supersedes=supersedes is not None
    )
    return await _post_quote(config, request)


# ---------------------------------------------------------------------------
# Phase 2 — submit_sealed
# ---------------------------------------------------------------------------


async def submit_sealed(
    config: _ResolvedPublishConfig,
    *,
    prepared: PreparedSeal,
    signer: Signer | None = None,
    max_usd_micros: int | None = None,
    quote: QuoteResponse | None = None,
    supersedes: str | None = None,
    idempotency_key: str | None = None,
    chunk_bytes: int | None = None,
    uploaded: Sequence[UploadReceipt] = (),
) -> SealedSubmission:
    """Submit a prepared seal: quote → price-cap check → per-item ciphertext
    upload (skipping items covered by validated receipts) → quote refresh if
    an upload outlived the price lock → encode (optionally sign) → publish.

    Uploads carry the deterministic per-item idempotency key
    (:meth:`PreparedSeal.upload_idempotency_key`), so a crash-and-retry of
    the same prepared item can never pay for its storage twice.

    Raises :class:`SubmitSealedError`; when the failure happened after any
    upload completed, :attr:`SubmitSealedError.uploads` carries the finished
    receipts — persist them and resume via ``uploaded``.
    """
    # Everything that can be validated without the network fails before the
    # quote is spent: the signer shape, the supersedes format, the receipts.
    try:
        if signer is not None:
            _assert_signer(signer)
        if supersedes is not None:
            _parse_supersedes_hex(supersedes)
        resumed = _validate_receipts(prepared, uploaded)
    except Exception as cause:
        raise SubmitSealedError((), cause) from cause

    def resumed_receipts() -> list[UploadReceipt]:
        return [receipt for _, receipt in sorted(resumed.items())]

    request = _prepared_quote_request(
        prepared, signed=signer is not None, supersedes=supersedes is not None
    )
    # A caller-passed preview is consumed only while it is still comfortably
    # inside its TTL; anything else re-quotes so the publish never races the
    # gateway's expiry check.
    if quote is not None and _quote_is_fresh(quote):
        active_quote = cast("QuoteResponse", dict(quote))
    else:
        try:
            active_quote = await _post_quote(config, request)
        except Exception as cause:
            raise SubmitSealedError(resumed_receipts(), cause) from cause
    try:
        _enforce_max_usd_micros(max_usd_micros, active_quote)
    except Exception as cause:
        raise SubmitSealedError(resumed_receipts(), cause) from cause

    uploads: list[UploadReceipt] = []
    for index, item in enumerate(prepared.items):
        receipt = resumed.pop(index, None)
        if receipt is not None:
            uploads.append(receipt)
            continue
        key = prepared.upload_idempotency_key(index)
        try:
            uri = await _upload_blob(config, item.ciphertext, key, chunk_bytes)
        except Exception as cause:
            # Receipts for later items were validated but not yet folded into
            # the ordered list; return every completed upload.
            uploads.extend(receipt for _, receipt in sorted(resumed.items()))
            raise SubmitSealedError(uploads, cause) from cause
        uploads.append(
            UploadReceipt(
                item_id=item.item_id,
                uri=uri,
                ciphertext_sha256=sha256(item.ciphertext),
                bytes=len(item.ciphertext),
            )
        )

    try:
        # A large upload can outlive the price lock; publish only against a
        # live one, re-enforcing the cap against the refreshed price.
        active_quote = await _refresh_quote_if_stale(config, active_quote, request, max_usd_micros)
        uris = tuple(receipt.uri for receipt in uploads)
        record_bytes = await encode_sealed_record(
            prepared, uris, supersedes=supersedes, signer=signer
        )
        response = await _post_publish(
            config, record_bytes.hex(), active_quote["quote_id"], idempotency_key
        )
    except Exception as cause:
        raise SubmitSealedError(uploads, cause) from cause

    return SealedSubmission(
        response=response,
        record_bytes=record_bytes,
        uris=uris,
        uploads=tuple(uploads),
        quote=active_quote,
    )


def _validate_receipts(
    prepared: PreparedSeal, uploaded: Sequence[UploadReceipt]
) -> dict[int, UploadReceipt]:
    """Validate resume receipts against the prepared material, keyed by item
    index. Every field must match — an unknown ``item_id``, a digest or byte
    count that differs from the prepared ciphertext, an empty URI, or a
    duplicate receipt is rejected outright rather than skipped."""
    by_index: dict[int, UploadReceipt] = {}
    # First match wins when two prepared items share an item_id (identical
    # ciphertext): a receipt resolves to the earliest such item, matching the
    # reference SDK's position-based lookup.
    item_index_by_id: dict[str, int] = {}
    for i, item in enumerate(prepared.items):
        item_index_by_id.setdefault(item.item_id, i)
    for receipt in uploaded:
        index = item_index_by_id.get(receipt.item_id)
        if index is None:
            raise InvalidUploadReceiptError(
                f"item_id {receipt.item_id} does not belong to the prepared seal"
            )
        item = prepared.items[index]
        if bytes(receipt.ciphertext_sha256) != sha256(item.ciphertext):
            raise InvalidUploadReceiptError(
                f"receipt for {receipt.item_id} has a ciphertext_sha256 that does not "
                "match the prepared ciphertext"
            )
        if receipt.bytes != len(item.ciphertext):
            raise InvalidUploadReceiptError(
                f"receipt for {receipt.item_id} declares {receipt.bytes} byte(s), "
                f"prepared ciphertext is {len(item.ciphertext)}"
            )
        if not receipt.uri:
            raise InvalidUploadReceiptError(f"receipt for {receipt.item_id} carries an empty uri")
        if index in by_index:
            raise InvalidUploadReceiptError(f"duplicate receipt for {receipt.item_id}")
        # Rebuilt rather than stored as passed: a caller-held bytearray digest
        # must not remain mutable inside the receipts the flow carries onward.
        by_index[index] = UploadReceipt(
            item_id=receipt.item_id,
            uri=receipt.uri,
            ciphertext_sha256=bytes(receipt.ciphertext_sha256),
            bytes=receipt.bytes,
        )
    return by_index


# ---------------------------------------------------------------------------
# One-shot wrapper
# ---------------------------------------------------------------------------


class PublishSealedInput(TypedDict, total=False):
    """Keyword arguments of :py:meth:`PoeNamespace.publish_sealed`.

    The helper quotes internally from the exact-width record-size estimate;
    there is no caller-supplied quote id. Flows that must survive a crash
    (persist the prepared artifact, resume uploads from receipts) use the
    two-phase :func:`seal_prepare` / :func:`submit_sealed` surface instead.
    """

    items: Sequence[bytes | str]  # required
    recipients: Sequence[bytes]  # required
    hash_alg: SupportedHashAlg
    kem: SupportedKem
    signer: Signer
    # Refuse to publish when the quoted price exceeds this many USD
    # micro-cents (1 USD = 1,000,000).
    max_usd_micros: int
    # The 64-hex transaction hash of the record this one supersedes.
    supersedes: str
    idempotency_key: str
    chunk_bytes: int


async def publish_sealed(
    config: _ResolvedPublishConfig,
    *,
    items: Sequence[bytes | str],
    recipients: Sequence[bytes],
    hash_alg: SupportedHashAlg = "sha2-256",
    kem: SupportedKem = "mlkem768x25519",
    signer: Signer | None = None,
    max_usd_micros: int | None = None,
    supersedes: str | None = None,
    idempotency_key: str | None = None,
    chunk_bytes: int | None = None,
) -> SealedSubmission:
    """One-shot sealed publish: :func:`seal_prepare` followed by
    :func:`submit_sealed`.

    Convenient when nothing needs to survive a process crash; a flow that
    must resume (CI jobs, large ciphertexts) runs the two phases itself and
    persists the :class:`PreparedSeal` and the :class:`UploadReceipt` s.

    Raises :class:`SubmitSealedError`; see :func:`submit_sealed`.
    """
    try:
        prepared = seal_prepare(items=items, recipients=recipients, kem=kem, hash_alg=hash_alg)
    except Exception as cause:
        raise SubmitSealedError((), cause) from cause
    return await submit_sealed(
        config,
        prepared=prepared,
        signer=signer,
        max_usd_micros=max_usd_micros,
        supersedes=supersedes,
        idempotency_key=idempotency_key,
        chunk_bytes=chunk_bytes,
    )


# ---------------------------------------------------------------------------
# base64url (RFC 4648 §5, unpadded)
# ---------------------------------------------------------------------------

_BASE64URL_ALPHABET_RE = re.compile(r"[A-Za-z0-9_-]*")


def _base64url_encode(data: bytes) -> str:
    """Unpadded base64url of a byte string."""
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _base64url_decode(text: str) -> bytes | None:
    """Strict unpadded-base64url decode: rejects padding, characters outside
    the alphabet, an impossible remainder length, and non-canonical trailing
    bits (so every byte string has exactly one accepted encoding).

    The trailing-bit rule is enforced by round-trip: a decode whose canonical
    re-encoding differs from the input carried non-zero trailing bits.
    """
    if _BASE64URL_ALPHABET_RE.fullmatch(text) is None or len(text) % 4 == 1:
        return None
    padded = text + "=" * (-len(text) % 4)
    try:
        raw = base64.urlsafe_b64decode(padded.encode("ascii"))
    except (binascii.Error, ValueError):
        return None
    if _base64url_encode(raw) != text:
        return None
    return raw


def _is_lowercase_hex(text: str, length: int) -> bool:
    """Whether ``text`` is exactly ``length`` lowercase-hex characters."""
    return len(text) == length and all("0" <= ch <= "9" or "a" <= ch <= "f" for ch in text)


__all__ = [
    "PREPARED_SEAL_JSON_VERSION",
    "InvalidUploadReceiptError",
    "PreparedSeal",
    "PreparedSealItem",
    "PreparedSealJsonError",
    "PublishSealedInput",
    "RngFill",
    "SealPrepareError",
    "SealedSubmission",
    "SubmitSealedError",
    "UploadReceipt",
    "encode_sealed_record",
    "publish_sealed",
    "quote_prepared_seal",
    "seal_prepare",
    "seal_prepare_with_rng",
    "sealed_record",
    "submit_sealed",
]
