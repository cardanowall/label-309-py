"""Label 309 v1 structural validator (the Part A structural-validation role).

Pure function over the reassembled CBOR record body — performs no I/O, opens
no socket, verifies no signature cryptographically, decodes no ciphertext.
Chain resolution, URI fetching, decryption, and confirmation-depth checks are
the verifier's concern (the Part B role). The transport chunk array is
reassembled BEFORE this function runs; the carriage codes (``CHUNK_TOO_LARGE``,
the transport ``MALFORMED_CBOR`` reuse) are emitted by that step, not here.

Pipeline:

- **Step 1** Canonical CBOR decode — every malformed / non-canonical /
  duplicate-key / indefinite-length input surfaces as the single
  ``MALFORMED_CBOR`` code.
- **Step 2** Schema parse — the closed per-field shape gate; each violation
  lifts to its canonical structural code. A failed parse forecloses the
  domain pass (there is no typed record to walk).
- **Step 3** Domain checks — cross-field rules, registry membership, URI
  shape (the offline CID profile), the encryption-envelope union (typed
  scheme-1 vs the degrade-to-opaque reading), ``sigs[i]`` COSE_Sign1
  structural decode, ``crit[]`` shape, exact-integer range enforcement.
- **Step 4** Result emission — every collected issue is sorted (path
  segment-wise, registry-order tie-break) and the record is valid iff no
  error-severity issue is present.

The validator NEVER raises — failure paths route through the discriminated
``ValidateResult`` union so callers handle errors as data, and its output is
deterministic for any given ``(bytes, options)`` pair.
"""

from __future__ import annotations

import re
from collections.abc import Set as AbstractSet
from dataclasses import dataclass
from typing import Final, Literal, cast

from cardanowall._crypto.cbor import (
    CanonicalCborValue,
    decode_canonical_cbor,
    encode_canonical_cbor,
)
from cardanowall._crypto.cose_sign1 import CoseVerifyError, decode_cose_sign1

# The verifier resource bounds the sealed-PoE unwrap layer enforces. Importing
# the same constants, rather than re-declaring them, makes the structural
# validator and the unwrap layer default to identical thresholds. Both are
# deployment-pinned reference values, not wire fields — the validate() options
# override them per deployment.
from cardanowall._crypto.sealed_poe import MAX_DECODED_ENVELOPE_BYTES, MAX_SLOTS

from .cid_profile import is_valid_cid
from .error_codes import SEVERITY, ErrorCode, Severity, error_code_registry_index
from .schema import (
    TOP_LEVEL_BASE_KEYS,
    Argon2Params,
    PoeRecord,
    is_extension_key,
)

# =============================================================================
# Registries (closed catalogue of this implementation)
# =============================================================================

# Content-hash algorithm registry. Map value = digest length.
HASH_ALG_LENGTHS: Final[dict[str, int]] = {
    "sha2-256": 32,
    "blake2b-256": 32,
}

# Merkle list-commitment algorithm registry. Map value = root length.
MERKLE_COMMIT_ALG_LENGTHS: Final[dict[str, int]] = {"rfc9162-sha256": 32}

# Content-format (AEAD) registry. Value = the registered `enc.nonce` length.
AEAD_NONCE_LENGTHS: Final[dict[str, int]] = {"chacha20-poly1305-stream64k": 24}

# Unauthenticated-cipher family. An `enc.aead` naming any of these is rejected
# with `UNAUTHENTICATED_CIPHER_FORBIDDEN` in EVERY role — a forbidden
# primitive is a recognised hazard, not an unknown identifier, so it never
# takes the degrade-to-opaque reading. Two arms:
#   - block-cipher modes with no integrity (`cbc`, `ctr`, `ecb`, `cfb`,
#     `ofb`) appearing as a delimited token, matching every key-size spelling
#     (`aes-cbc`, `aes-256-cbc`, `des-ede3-cbc`, …);
#   - legacy stream/block ciphers as a leading token (`rc4`, `des`, `3des`).
# The token delimiters keep authenticated AEADs (`aes-256-gcm`,
# `chacha20-poly1305-stream64k`) from matching.
UNAUTHENTICATED_CIPHER_RE: Final[re.Pattern[str]] = re.compile(
    r"(?:^|[-_])(?:cbc|ctr|ecb|cfb|ofb)(?:[-_]|$)|^(?:rc4|des|3des)(?:[-_]|$)",
    re.IGNORECASE,
)

# KEM registry, expressed as a per-KEM slot DESCRIPTOR. Each registered KEM
# pins the exact recipient-slot shape:
#
#   - x25519:         `{ epk: bstr(32), wrap: bstr(48) }` — classical
#     ephemeral-static X25519.
#   - mlkem768x25519: `{ kem_ct: bstr(1120), wrap: bstr(48) }` — the X-Wing
#     hybrid; the encapsulation is a SINGLE 1120-byte byte string and there
#     is NO per-slot `epk` (the X25519 ephemeral is the trailing 32 bytes of
#     `kem_ct`).
#
# A descriptor declares the slot's ciphertext-bearing field and its exact
# byte length; `wrap` is 48 bytes for every KEM (32-byte CEK + 16-byte AEAD
# tag). The validator branches on the descriptor so adding a future KEM is a
# registry edit, not a new code path.

KemSlotField = Literal["epk", "kem_ct"]


@dataclass(frozen=True)
class KemSlotDescriptor:
    """The recipient-slot shape pinned by one registered KEM."""

    field: KemSlotField
    field_length: int
    wrap_length: int


KEM_SLOT_DESCRIPTORS: Final[dict[str, KemSlotDescriptor]] = {
    "x25519": KemSlotDescriptor(field="epk", field_length=32, wrap_length=48),
    "mlkem768x25519": KemSlotDescriptor(field="kem_ct", field_length=1120, wrap_length=48),
}

KEM_FIELD_LENGTH_CODE: Final[dict[KemSlotField, ErrorCode]] = {
    "epk": "KEM_EPK_LENGTH_MISMATCH",
    "kem_ct": "KEM_CT_LENGTH_MISMATCH",
}

# A slot is a closed 2-key map; the universe of keys a slot may ever carry.
SLOT_KEY_UNIVERSE: Final[frozenset[str]] = frozenset({"epk", "kem_ct", "wrap"})

# Passphrase KDF registry.
PASSPHRASE_KDF_ALGS: Final[frozenset[str]] = frozenset({"argon2id"})

# Signature-algorithm registry: COSE `alg` labels. `-8` (EdDSA, pinned to
# Ed25519) is the mandatory baseline; `-19` (Ed25519 fully-specified) is
# verified identically when accepted. Anything else is tagged
# `SIGNATURE_UNSUPPORTED` (info-severity) — signatures are optional, so an
# unrecognised algorithm never fails the record by itself.
KNOWN_SIG_ALG_IDS: Final[frozenset[int]] = frozenset({-8, -19})

# Every numeric wire field is a CBOR unsigned integer pinned to this range
# and handled as an EXACT integer (Python integers are arbitrary precision,
# so no value is ever rounded through a float before the range check).
_UINT32_MAX: Final[int] = 0xFFFF_FFFF

# The closed typed-envelope key set and the closed argon2id params key set.
_ENC_SCHEME1_KEYS: Final[frozenset[str]] = frozenset(
    {"scheme", "aead", "kem", "nonce", "slots", "slots_mac", "passphrase"}
)
_PASSPHRASE_KEYS: Final[frozenset[str]] = frozenset({"alg", "salt", "params"})
_ARGON2_PARAM_NAMES: Final[tuple[Literal["m", "t", "p"], ...]] = ("m", "t", "p")
_ARGON2_FLOORS: Final[dict[str, int]] = {"m": 65_536, "t": 3, "p": 1}

# =============================================================================
# Options
# =============================================================================

ValidatorRole = Literal["public", "recipient_or_strict"]

# The reference deployment ceiling on Argon2id work factors — a verifier-side
# denial-of-service backstop (a 64 GiB `m` must not be able to stall a
# decrypt-on-paste consumer), enforced by default and distinct from the
# normative floors. Ceilings are deployment policy, not a wire rule: override
# per deployment, or pass `passphrase_params_ceiling=None` to disable.
DEFAULT_PASSPHRASE_PARAMS_CEILING: Final[Argon2Params] = {
    "m": 2_097_152,  # KiB = 2 GiB
    "t": 16,
    "p": 8,
}

_EMPTY_EXTENSION_SET: Final[frozenset[str]] = frozenset()


@dataclass(frozen=True)
class _ResolvedOptions:
    supported_critical_extensions: frozenset[str]
    role: ValidatorRole
    max_slots: int
    max_enc_envelope_bytes: int
    passphrase_params_ceiling: Argon2Params | None


# =============================================================================
# Result types
# =============================================================================

_PathSeg = str | int
_Path = tuple[_PathSeg, ...]


@dataclass(frozen=True)
class ValidationIssue:
    """One entry in the validator's result.

    ``path`` holds segments from the record root: text map keys and integer
    array indices (e.g. ``("items", 0, "hashes", "sha2-256")``). A dotted
    string is a display rendering only — the segment tuple is the API form,
    so map keys containing ``.`` need no escaping.
    """

    code: ErrorCode
    path: _Path
    message: str
    severity: Severity = "error"


@dataclass(frozen=True)
class ValidateOk:
    """Returned when zero error-severity issues fired. ``warnings`` and
    ``info`` may still be non-empty (e.g. ``SIGNATURE_UNSUPPORTED``)."""

    ok: Literal[True]
    record: PoeRecord
    info: tuple[ValidationIssue, ...] = ()
    warnings: tuple[ValidationIssue, ...] = ()


@dataclass(frozen=True)
class ValidateFail:
    """Returned when at least one error-severity issue fired."""

    ok: Literal[False]
    issues: tuple[ValidationIssue, ...]


ValidateResult = ValidateOk | ValidateFail


# =============================================================================
# Public entry point
# =============================================================================


def validate(
    cbor_bytes: bytes,
    *,
    supported_critical_extensions: AbstractSet[str] | None = None,
    role: ValidatorRole = "public",
    max_slots: int = MAX_SLOTS,
    max_enc_envelope_bytes: int = MAX_DECODED_ENVELOPE_BYTES,
    passphrase_params_ceiling: Argon2Params | None = DEFAULT_PASSPHRASE_PARAMS_CEILING,
) -> ValidateResult:
    """Structurally validate one Label 309 record body.

    Options:

    - ``supported_critical_extensions`` — names of the critical extensions
      this validator implements. Default: the empty set, so a
      default-configured validator fails every ``crit``-bearing record with
      ``EXTENSION_UNSUPPORTED_CRITICAL`` — by design.
    - ``role`` — the validation reading for dual-severity envelope
      dispositions. ``"public"`` (default): an envelope under an unsupported
      ``scheme`` / ``kem`` / ``aead`` degrades to opaque and
      ``ENC_UNSUPPORTED`` is informational. ``"recipient_or_strict"`` (the
      recipient verifier and strict sealed-crypto mode): the same condition
      is a hard reject — ``ENC_UNSUPPORTED`` escalates to error and co-fires
      with the identifier-specific ``UNSUPPORTED_*`` code.
    - ``max_slots`` — slot-count resource bound (reference bound 1024).
    - ``max_enc_envelope_bytes`` — decoded-envelope byte resource bound
      (reference bound 65536), measured by canonically re-encoding the
      decoded ``enc`` subtree.
    - ``passphrase_params_ceiling`` — upper policy ceiling on Argon2id
      parameters (``ENC_PASSPHRASE_PARAMS_EXCEED_POLICY``). Defaults to
      :data:`DEFAULT_PASSPHRASE_PARAMS_CEILING`; ``None`` disables it.
    """
    opts = _ResolvedOptions(
        supported_critical_extensions=(
            frozenset(supported_critical_extensions)
            if supported_critical_extensions is not None
            else _EMPTY_EXTENSION_SET
        ),
        role=role,
        max_slots=max_slots,
        max_enc_envelope_bytes=max_enc_envelope_bytes,
        passphrase_params_ceiling=passphrase_params_ceiling,
    )

    # Step 1 — canonical CBOR decode. Every decode failure surfaces as the
    # single MALFORMED_CBOR code: malformed/truncated bytes, indefinite-length
    # (streaming) encodings, non-canonical map-key ordering, duplicate map
    # keys, floats/simple values, and invalid UTF-8. There is no separate
    # duplicate-key code — canonical-decode rejection covers it.
    try:
        decoded = decode_canonical_cbor(cbor_bytes)
    except Exception as cause:
        return ValidateFail(
            ok=False,
            issues=(_issue("MALFORMED_CBOR", (), f"cbor decode failed: {cause}"),),
        )

    # Step 2 pre-guard — non-text map keys. Every map at a typed grammar
    # position is text-keyed; a map carrying any non-text key cannot be read
    # by the field schema at all, so the violation is detected here and
    # attributed at the containing map as SCHEMA_TYPE_MISMATCH, foreclosing
    # the parse the same way any other unparseable shape does.
    non_text_key_issues = _collect_non_text_key_map_issues(decoded)
    if non_text_key_issues:
        return ValidateFail(ok=False, issues=tuple(_sort_issues(non_text_key_issues)))

    # Step 2 — schema parse. A failed parse forecloses the domain pass (there
    # is no typed record to walk); its issues are emitted sorted.
    schema_issues = _schema_parse(decoded)
    if schema_issues:
        return ValidateFail(ok=False, issues=tuple(_sort_issues(schema_issues)))

    # Step 3 — domain checks. Issues of every severity are collected together;
    # no error-severity issue stops the walk.
    record_map = cast("dict[str, object]", decoded)
    issues: list[ValidationIssue] = []

    _check_content_commitment_presence(record_map, issues)

    # `crit[]` shape rules run before the per-entry support check.
    _check_crit(record_map, opts.supported_critical_extensions, issues)

    # Unknown top-level fields: keys outside the base set that match neither
    # extension-key namespace (typos, control-character keys).
    for key in record_map:
        if key in TOP_LEVEL_BASE_KEYS or is_extension_key(key):
            continue
        issues.append(_issue("SCHEMA_UNKNOWN_FIELD", (key,), f"unknown top-level field: {key}"))

    items = record_map.get("items")
    if isinstance(items, list):
        for i, item in enumerate(items):
            item_map = cast("dict[str, object]", item)
            _check_item_hashes(item_map, i, issues)
            uris = item_map.get("uris")
            if uris is not None:
                _check_uris(cast("list[object]", uris), ("items", i, "uris"), issues)
            if "enc" in item_map:
                _check_item_enc(item_map, i, opts, issues)

    merkle = record_map.get("merkle")
    if isinstance(merkle, list):
        for i, commit in enumerate(merkle):
            _check_merkle_commit(cast("dict[str, object]", commit), i, issues)

    sigs = record_map.get("sigs")
    if isinstance(sigs, list):
        if len(sigs) == 0:
            issues.append(
                _issue("SCHEMA_TYPE_MISMATCH", ("sigs",), "sigs[] must be non-empty when present")
            )
        for i, entry in enumerate(sigs):
            _check_sig_entry(cast("dict[str, object]", entry), i, issues)

    # Step 4 — result emission. The full issue list is sorted once (path
    # segment-wise, registry-order tie-break); the record is valid iff no
    # error-severity issue is present, and warnings / info never fail it.
    sorted_issues = _sort_issues(issues)
    if any(issue.severity == "error" for issue in sorted_issues):
        return ValidateFail(ok=False, issues=tuple(sorted_issues))
    warnings = tuple(issue for issue in sorted_issues if issue.severity == "warning")
    info = tuple(issue for issue in sorted_issues if issue.severity == "info")
    return ValidateOk(
        ok=True,
        record=cast("PoeRecord", record_map),
        info=info,
        warnings=warnings,
    )


# =============================================================================
# Issue construction and deterministic ordering
# =============================================================================


def _issue(
    code: ErrorCode,
    path: _Path,
    message: str,
    severity: Severity | None = None,
) -> ValidationIssue:
    return ValidationIssue(
        code=code,
        path=path,
        message=message,
        severity=severity if severity is not None else SEVERITY[code],
    )


def _segment_sort_key(seg: _PathSeg) -> tuple[int, int, bytes]:
    # Integer segments order before text segments where the kinds differ;
    # integers compare numerically; text compares by UTF-8 bytes — the only
    # collation that is byte-stable across runs and across language
    # implementations (no locale tables, no UTF-16 code-unit artefacts).
    if isinstance(seg, int):
        return (0, seg, b"")
    return (1, 0, seg.encode("utf-8"))


def _issue_sort_key(
    issue: ValidationIssue,
) -> tuple[tuple[tuple[int, int, bytes], ...], int]:
    # Segment-wise path order with a strict prefix ordering before its
    # extensions (tuple comparison gives prefix-first for free), then the
    # registry-position tie-break for issues on an identical path.
    return (
        tuple(_segment_sort_key(seg) for seg in issue.path),
        error_code_registry_index(issue.code),
    )


def _sort_issues(issues: list[ValidationIssue]) -> list[ValidationIssue]:
    return sorted(issues, key=_issue_sort_key)


# =============================================================================
# Step 2 pre-guard — non-text map keys at the typed grammar positions
# =============================================================================
#
# Walks the positions reachable from the record root: the root map, each
# `items[i]` / `merkle[i]` / `sigs[i]` entry, and the `hashes` / `enc` maps
# inside an item. Positions inside extension values are deliberately NOT
# walked — extension values admit any CBOR value the canonical profile
# allows, integer-keyed maps included. The interior of a supported `enc`
# envelope is scanned by the envelope dispatch itself (the opaque reading
# likewise admits arbitrary extension values).

_NON_TEXT_KEY_MESSAGE: Final[str] = (
    "CBOR map carries a non-text key where a text-keyed map is required"
)


def _has_non_text_key(value: object) -> bool:
    return isinstance(value, dict) and any(
        not isinstance(k, str) for k in cast("dict[object, object]", value)
    )


def _collect_non_text_key_map_issues(decoded: object) -> list[ValidationIssue]:
    issues: list[ValidationIssue] = []

    def flag(path: _Path) -> None:
        issues.append(_issue("SCHEMA_TYPE_MISMATCH", path, _NON_TEXT_KEY_MESSAGE))

    if _has_non_text_key(decoded):
        flag(())
        return issues
    if not isinstance(decoded, dict):
        return issues
    record = cast("dict[str, object]", decoded)
    for field in ("items", "merkle", "sigs"):
        entries = record.get(field)
        if not isinstance(entries, list):
            continue
        for i, entry in enumerate(entries):
            if _has_non_text_key(entry):
                flag((field, i))
                continue
            if field != "items" or not isinstance(entry, dict):
                continue
            item = cast("dict[str, object]", entry)
            if _has_non_text_key(item.get("hashes")):
                flag((field, i, "hashes"))
            if _has_non_text_key(item.get("enc")):
                flag((field, i, "enc"))
    return issues


# =============================================================================
# Step 2 — schema parse (the closed per-field shape gate)
# =============================================================================
#
# Enforces per-field CBOR types, the fixed byte lengths a field can assert in
# isolation (32-byte `supersedes`, 32-byte `slots_mac`, the 16..64-byte
# passphrase salt), closed-map invariants (`items[i]`, `merkle[i]`,
# `sigs[i]`), and the `v == 1` literal. Cross-field rules (content-hash
# binding under `enc`, slots/passphrase exclusivity, `crit[]` shape, registry
# membership of algorithm identifiers, COSE_Sign1 structural decode, URI
# shape, non-empty-array rules, integer ranges) fire in the domain pass so
# each violation emits its precise canonical code rather than a generic
# schema mismatch. `enc` is NOT parsed here — the envelope is a union whose
# disposition (typed scheme-1 vs opaque) depends on identifier support, so
# the domain pass dispatches it.


def _is_uint(value: object) -> bool:
    # A CBOR unsigned integer as the canonical decoder surfaces it. A `bool`
    # is a distinct CBOR major type and is never a uint; a negative value is
    # a different major type as well.
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _schema_parse(decoded: object) -> list[ValidationIssue]:
    issues: list[ValidationIssue] = []
    if not isinstance(decoded, dict):
        issues.append(_issue("SCHEMA_TYPE_MISMATCH", (), "top-level value must be a CBOR map"))
        return issues
    record = cast("dict[str, object]", decoded)

    if "v" not in record:
        issues.append(_issue("SCHEMA_MISSING_REQUIRED", ("v",), "missing required field 'v'"))
    else:
        v = record["v"]
        if not (isinstance(v, int) and not isinstance(v, bool) and v == 1):
            issues.append(
                _issue("SCHEMA_INVALID_LITERAL", ("v",), "v must be the unsigned integer 1")
            )

    items = record.get("items")
    if items is not None:
        if not isinstance(items, list):
            issues.append(_issue("SCHEMA_TYPE_MISMATCH", ("items",), "items must be an array"))
        else:
            for i, item in enumerate(items):
                _schema_parse_item(item, ("items", i), issues)

    merkle = record.get("merkle")
    if merkle is not None:
        if not isinstance(merkle, list):
            issues.append(_issue("SCHEMA_TYPE_MISMATCH", ("merkle",), "merkle must be an array"))
        else:
            for i, commit in enumerate(merkle):
                _schema_parse_merkle_commit(commit, ("merkle", i), issues)

    supersedes = record.get("supersedes")
    if supersedes is not None:
        if not isinstance(supersedes, bytes):
            issues.append(
                _issue(
                    "SCHEMA_TYPE_MISMATCH",
                    ("supersedes",),
                    "supersedes must be a CBOR byte string (32-byte transaction hash)",
                )
            )
        elif len(supersedes) != 32:
            issues.append(
                _issue(
                    "SUPERSEDES_TX_INVALID_LENGTH",
                    ("supersedes",),
                    f"supersedes length {len(supersedes)} != 32",
                )
            )

    sigs = record.get("sigs")
    if sigs is not None:
        if not isinstance(sigs, list):
            issues.append(_issue("SCHEMA_TYPE_MISMATCH", ("sigs",), "sigs must be an array"))
        else:
            for i, entry in enumerate(sigs):
                _schema_parse_sig_entry(entry, ("sigs", i), issues)

    crit = record.get("crit")
    if crit is not None:
        if not isinstance(crit, list):
            issues.append(_issue("SCHEMA_TYPE_MISMATCH", ("crit",), "crit must be an array"))
        else:
            for i, name in enumerate(crit):
                if not isinstance(name, str):
                    issues.append(
                        _issue(
                            "SCHEMA_TYPE_MISMATCH",
                            ("crit", i),
                            "crit[] entries must be text strings",
                        )
                    )

    return issues


def _schema_parse_item(item: object, path: _Path, issues: list[ValidationIssue]) -> None:
    if not isinstance(item, dict):
        issues.append(_issue("SCHEMA_TYPE_MISMATCH", path, "item entry must be a CBOR map"))
        return
    item_map = cast("dict[str, object]", item)

    # items[i] is a CLOSED map {hashes, ? uris, ? enc}.
    for key in item_map:
        if key not in ("hashes", "uris", "enc"):
            issues.append(
                _issue(
                    "SCHEMA_UNKNOWN_FIELD",
                    (*path, key),
                    f"unrecognized key '{key}' in a closed map",
                )
            )

    if "hashes" not in item_map:
        issues.append(
            _issue("SCHEMA_MISSING_REQUIRED", (*path, "hashes"), "item.hashes is required")
        )
    else:
        hashes = item_map["hashes"]
        if not isinstance(hashes, dict):
            issues.append(
                _issue("SCHEMA_TYPE_MISMATCH", (*path, "hashes"), "hashes must be a CBOR map")
            )
        else:
            for alg, digest in cast("dict[str, object]", hashes).items():
                if not isinstance(digest, bytes):
                    issues.append(
                        _issue(
                            "SCHEMA_TYPE_MISMATCH",
                            (*path, "hashes", alg),
                            f"hashes['{alg}'] must be a CBOR byte string",
                        )
                    )

    uris = item_map.get("uris")
    if uris is not None:
        _schema_parse_uris(uris, (*path, "uris"), issues)

    # `enc` is captured untyped: the envelope union is dispatched by the
    # domain pass on identifier support, never by shape success here.


def _schema_parse_uris(uris: object, path: _Path, issues: list[ValidationIssue]) -> None:
    if not isinstance(uris, list):
        issues.append(_issue("SCHEMA_TYPE_MISMATCH", path, "uris must be an array"))
        return
    for i, uri in enumerate(uris):
        if not isinstance(uri, str):
            issues.append(
                _issue(
                    "SCHEMA_TYPE_MISMATCH",
                    (*path, i),
                    "each URI is one absolute URI in a single text string",
                )
            )


def _schema_parse_merkle_commit(commit: object, path: _Path, issues: list[ValidationIssue]) -> None:
    if not isinstance(commit, dict):
        issues.append(_issue("SCHEMA_TYPE_MISMATCH", path, "merkle entry must be a CBOR map"))
        return
    commit_map = cast("dict[str, object]", commit)

    for key in commit_map:
        if key not in ("alg", "root", "leaf_count", "uris"):
            issues.append(
                _issue(
                    "SCHEMA_UNKNOWN_FIELD",
                    (*path, key),
                    f"unrecognized key '{key}' in a closed map",
                )
            )

    if "alg" not in commit_map:
        issues.append(
            _issue("SCHEMA_MISSING_REQUIRED", (*path, "alg"), "merkle entry `alg` is required")
        )
    elif not isinstance(commit_map["alg"], str):
        issues.append(
            _issue(
                "SCHEMA_TYPE_MISMATCH",
                (*path, "alg"),
                "merkle entry `alg` must be a text string",
            )
        )

    if "root" not in commit_map:
        issues.append(
            _issue("SCHEMA_MISSING_REQUIRED", (*path, "root"), "merkle entry `root` is required")
        )
    elif not isinstance(commit_map["root"], bytes):
        issues.append(
            _issue(
                "SCHEMA_TYPE_MISMATCH",
                (*path, "root"),
                "merkle entry `root` must be a CBOR byte string",
            )
        )

    if "leaf_count" not in commit_map:
        issues.append(
            _issue(
                "SCHEMA_MISSING_REQUIRED",
                (*path, "leaf_count"),
                "merkle entry `leaf_count` is required",
            )
        )
    elif isinstance(commit_map["leaf_count"], bool) or not isinstance(
        commit_map["leaf_count"], int
    ):
        issues.append(
            _issue(
                "SCHEMA_TYPE_MISMATCH",
                (*path, "leaf_count"),
                "merkle entry `leaf_count` must be a CBOR integer",
            )
        )

    uris = commit_map.get("uris")
    if uris is not None:
        _schema_parse_uris(uris, (*path, "uris"), issues)


def _schema_parse_sig_entry(entry: object, path: _Path, issues: list[ValidationIssue]) -> None:
    # The sig-entry closed-map rule owns every shape violation inside a
    # `sigs[i]` entry: a non-map entry, a missing/`non-bstr` `cose_sign1`, a
    # non-bstr `cose_key`, and any stray key all carry SIG_ENTRY_INVALID_SHAPE.
    if not isinstance(entry, dict):
        issues.append(
            _issue(
                "SIG_ENTRY_INVALID_SHAPE",
                path,
                "each sigs entry must be a CBOR map { cose_sign1, ? cose_key }",
            )
        )
        return
    entry_map = cast("dict[str, object]", entry)

    for key in entry_map:
        if key not in ("cose_sign1", "cose_key"):
            issues.append(
                _issue(
                    "SIG_ENTRY_INVALID_SHAPE",
                    (*path, key),
                    f"unrecognized key '{key}' in a closed map",
                )
            )

    if "cose_sign1" not in entry_map:
        issues.append(
            _issue(
                "SIG_ENTRY_INVALID_SHAPE",
                (*path, "cose_sign1"),
                "sigs entry is missing required 'cose_sign1'",
            )
        )
    elif not isinstance(entry_map["cose_sign1"], bytes):
        issues.append(
            _issue(
                "SIG_ENTRY_INVALID_SHAPE",
                (*path, "cose_sign1"),
                "sigs[i].cose_sign1 must be a single CBOR byte string",
            )
        )

    cose_key = entry_map.get("cose_key")
    if cose_key is not None and not isinstance(cose_key, bytes):
        issues.append(
            _issue(
                "SIG_ENTRY_INVALID_SHAPE",
                (*path, "cose_key"),
                "sigs[i].cose_key must be a single CBOR byte string",
            )
        )


# =============================================================================
# Step 3 helpers — domain checks
# =============================================================================


def _check_content_commitment_presence(
    record: dict[str, object], issues: list[ValidationIssue]
) -> None:
    # Content-commitment rule: a record MUST carry at least one of `items[]`
    # or `merkle[]` non-empty (SCHEMA_EMPTY_RECORD when both are empty or
    # absent). When exactly one of them is present-but-empty beside a
    # non-empty sibling, the empty array itself violates its `1*` cardinality.
    items = record.get("items")
    merkle = record.get("merkle")
    items_len = len(items) if isinstance(items, list) else 0
    merkle_len = len(merkle) if isinstance(merkle, list) else 0
    if items_len == 0 and merkle_len == 0:
        issues.append(
            _issue(
                "SCHEMA_EMPTY_RECORD",
                (),
                "record must carry at least one of items[] or merkle[] non-empty",
            )
        )
        return
    if isinstance(items, list) and items_len == 0:
        issues.append(
            _issue("SCHEMA_TYPE_MISMATCH", ("items",), "items[] must be non-empty when present")
        )
    if isinstance(merkle, list) and merkle_len == 0:
        issues.append(
            _issue("SCHEMA_TYPE_MISMATCH", ("merkle",), "merkle[] must be non-empty when present")
        )


def _check_item_hashes(item: dict[str, object], idx: int, issues: list[ValidationIssue]) -> None:
    # Hash-map: non-empty, registry membership, per-algorithm digest length.
    hashes = cast("dict[str, bytes]", item["hashes"])
    if len(hashes) == 0:
        issues.append(
            _issue(
                "SCHEMA_TYPE_MISMATCH",
                ("items", idx, "hashes"),
                "hashes must be a non-empty CBOR map of <alg-id> -> <digest>",
            )
        )
        return
    for alg, digest in hashes.items():
        if alg not in HASH_ALG_LENGTHS:
            issues.append(
                _issue(
                    "UNSUPPORTED_HASH_ALG",
                    ("items", idx, "hashes", alg),
                    f"unknown hash alg: {alg}",
                )
            )
            continue
        expected = HASH_ALG_LENGTHS[alg]
        if len(digest) != expected:
            issues.append(
                _issue(
                    "HASH_DIGEST_LENGTH_MISMATCH",
                    ("items", idx, "hashes", alg),
                    f"hashes['{alg}'] digest length {len(digest)} != {expected}",
                )
            )


def _check_uris(uris: list[object], base_path: _Path, issues: list[ValidationIssue]) -> None:
    # URI shape: each entry is one absolute URI in a single text string.
    if len(uris) == 0:
        issues.append(
            _issue("SCHEMA_TYPE_MISMATCH", base_path, "uris[] must be non-empty when present")
        )
        return
    for i, uri in enumerate(uris):
        _check_one_uri(cast("str", uri), (*base_path, i), issues)


_URI_SCHEME_RE: Final[re.Pattern[str]] = re.compile(r"\A[a-z][a-z0-9+.\-]*\Z", re.IGNORECASE)
_ARWEAVE_TXID_BODY_RE: Final[re.Pattern[str]] = re.compile(r"\A[A-Za-z0-9_-]{43}\Z")


def _is_arweave_txid(body: str) -> bool:
    """Whether ``body`` is a valid Arweave transaction id: exactly 43 unpadded
    base64url characters (``[A-Za-z0-9_-]``)."""
    return _ARWEAVE_TXID_BODY_RE.match(body) is not None


def fetch_set_uri_rejection(uri: str) -> str | None:
    """The specific reason ``uri`` is not a well-formed member of a record's
    fetch set, or ``None`` when it is. This is the single source of truth for
    the fetch-set URI grammar: an absolute URI with no fragment, a scheme in
    ``{ar://, ipfs://}``, an ``ar://`` body of exactly 43 base64url characters
    (an Arweave txid), or an ``ipfs://`` body whose first path segment is a CID
    valid under the Label 309 profile. RFC 3986 §3.1: the scheme is
    case-insensitive, so the SCHEME alone is case-folded; the body is matched
    verbatim — a base64url Arweave txid and a base58btc CID are both
    case-significant.

    The canonical record validator and every producer-side pre-check delegate
    here, so a producer can never emit a URI a downstream verifier would reject.
    """
    if "#" in uri:
        return "URI contains a fragment identifier ('#'), which is forbidden"
    sep_idx = uri.find("://")
    if sep_idx <= 0 or _URI_SCHEME_RE.match(uri[:sep_idx]) is None:
        return "URI is not absolute (missing scheme://hierarchical-part)"
    scheme = uri[:sep_idx].lower()
    rest = uri[sep_idx + len("://") :]
    if scheme == "ar":
        if _is_arweave_txid(rest):
            return None
        return (
            "ar:// URI does not match `^ar://[A-Za-z0-9_-]{43}$` "
            "(43-char base64url txid, no path/query/fragment)"
        )
    if scheme == "ipfs":
        # Full offline CID parse (not a prefix heuristic).
        cid = rest.split("/", 1)[0]
        if is_valid_cid(cid):
            return None
        return "ipfs:// URI is not a valid CID under the Label 309 profile"
    return "unsupported URI scheme; v1 PoE URI set is {ar://, ipfs://}"


def is_fetch_set_uri(uri: str) -> bool:
    """Whether ``uri`` is a well-formed member of a record's fetch set under the
    strict Label 309 grammar (see :func:`fetch_set_uri_rejection`). Producer
    helpers call this to reject a malformed content or mirror URI early, using
    the exact grammar the canonical record validator enforces — the early check
    and the canonical check can never diverge because they are the same
    function."""
    return fetch_set_uri_rejection(uri) is None


def is_arweave_tx_uri(uri: str) -> bool:
    """Whether ``uri`` is an absolute Arweave transaction URI: ``ar://`` followed
    by a valid 43-character base64url txid, with no fragment, path, or query.

    This is the exact form a sealed-ciphertext upload receipt carries — the
    gateway is the only Arweave writer and every sealed ciphertext is stored on
    Arweave — so the sealed submit path constrains resume-receipt URIs to it. A
    URI accepted here is always a valid fetch-set member (so the assembled
    record still passes canonical validation), and its encoded width is fixed at
    ``5 + 43`` bytes, which is what keeps the pre-upload exact-size quote exact.
    """
    if not uri.startswith("ar://"):
        return False
    return _is_arweave_txid(uri[len("ar://") :])


def _check_one_uri(uri: str, path: _Path, issues: list[ValidationIssue]) -> None:
    # Absolute URI, no fragment, scheme in `{ar://, ipfs://}`. Delegated to the
    # single-source grammar so the canonical check can never diverge from the
    # producer-side pre-checks that share it.
    reason = fetch_set_uri_rejection(uri)
    if reason is not None:
        issues.append(_issue("INVALID_URI", path, reason))


# =============================================================================
# Encryption envelope — the typed-vs-opaque union
# =============================================================================
#
# `enc = enc-scheme-1 / enc-opaque`. The disposition is decided by identifier
# support, never by shape success:
#
#   - When `scheme`, `kem`, and `aead` are ALL supported identifiers, the
#     envelope is held to the full scheme-1 shape and key-path rules; an
#     envelope that fails them is rejected with its typed code, never
#     reclassified as opaque.
#   - When any of the three names an identifier this implementation does not
#     support, the envelope becomes OPAQUE: no shape, length, or key-path
#     rule is applied against an unknown identifier; the item is tagged
#     ENC_UNSUPPORTED (info in the public reading; error co-firing with the
#     identifier-specific UNSUPPORTED_* code in the recipient role / strict
#     sealed-crypto mode).
#   - Carve-out: an `aead` naming a forbidden unauthenticated cipher family
#     is rejected UNAUTHENTICATED_CIPHER_FORBIDDEN in every role — a
#     recognised hazard, not an unknown identifier.
#
# The content-hash binding (ENC_REQUIRES_CONTENT_HASH) inspects the item's
# `hashes` map, not the envelope, so it applies even under an opaque
# envelope.


def _check_item_enc(
    item: dict[str, object],
    idx: int,
    opts: _ResolvedOptions,
    issues: list[ValidationIssue],
) -> None:
    enc_path: _Path = ("items", idx, "enc")

    # Content-hash binding: an `enc`-bearing item MUST commit to at least one
    # REGISTERED content hash — the ciphertext is otherwise bound to no
    # plaintext digest. A presence check, not a non-empty check: `{md5: …}`
    # fails it (and MAY co-fire with UNSUPPORTED_HASH_ALG on the same item).
    hashes = cast("dict[str, object]", item["hashes"])
    if not any(alg in HASH_ALG_LENGTHS for alg in hashes):
        issues.append(
            _issue(
                "ENC_REQUIRES_CONTENT_HASH",
                enc_path,
                "item carries `enc` but `hashes` has no registered content-hash entry "
                "(sha2-256 or blake2b-256)",
            )
        )

    # The pre-guard has already rejected an `enc` map carrying non-text keys,
    # so a well-typed envelope arrives here as a text-keyed map.
    raw_enc = item["enc"]
    if not isinstance(raw_enc, dict):
        issues.append(_issue("SCHEMA_TYPE_MISMATCH", enc_path, "enc must be a CBOR map"))
        return
    enc = cast("dict[str, object]", raw_enc)

    # Decoded-envelope byte resource bound — a generic decode limit that
    # applies in every reading, opaque included. Canonical decode → canonical
    # encode is byte-identical, so re-encoding the decoded envelope measures
    # exactly the wire bytes of the `enc` subtree.
    envelope_bytes = len(encode_canonical_cbor(cast("CanonicalCborValue", raw_enc)))
    if envelope_bytes > opts.max_enc_envelope_bytes:
        issues.append(
            _issue(
                "ENC_ENVELOPE_TOO_LARGE",
                enc_path,
                f"decoded envelope is {envelope_bytes} bytes; "
                f"the resource bound is {opts.max_enc_envelope_bytes}",
            )
        )

    # `scheme` is structurally required in BOTH readings, as a CBOR unsigned
    # integer (the opaque grammar admits any uint; the typed grammar pins 1).
    if "scheme" not in enc:
        issues.append(
            _issue("SCHEMA_MISSING_REQUIRED", (*enc_path, "scheme"), "enc.scheme is required")
        )
        return
    scheme = enc["scheme"]
    if not _is_uint(scheme):
        issues.append(
            _issue(
                "SCHEMA_TYPE_MISMATCH",
                (*enc_path, "scheme"),
                "enc.scheme must be a CBOR unsigned integer",
            )
        )
        return

    # Forbidden-cipher carve-out: rejected in every role, never opaque.
    aead = enc.get("aead")
    if isinstance(aead, str) and UNAUTHENTICATED_CIPHER_RE.search(aead) is not None:
        issues.append(
            _issue(
                "UNAUTHENTICATED_CIPHER_FORBIDDEN",
                (*enc_path, "aead"),
                f"'{aead}' is an unauthenticated cipher; "
                "Label 309 mandates an authenticated (AEAD) cipher",
            )
        )
        return

    # Unknown-envelope rule: collect every identifier outside the implemented
    # set. A non-text `kem` / `aead` is not an identifier at all — it is a
    # type violation of whichever reading applies, handled by the typed pass
    # below.
    kem = enc.get("kem")
    unsupported: list[tuple[str, ErrorCode, str]] = []
    if scheme != 1:
        unsupported.append(("scheme", "UNSUPPORTED_ENVELOPE_SCHEME", str(scheme)))
    if isinstance(kem, str) and kem not in KEM_SLOT_DESCRIPTORS:
        unsupported.append(("kem", "UNSUPPORTED_KEM_ALG", kem))
    if isinstance(aead, str) and aead not in AEAD_NONCE_LENGTHS:
        unsupported.append(("aead", "UNSUPPORTED_AEAD_ALG", aead))
    if unsupported:
        # Degrade to opaque: the envelope is bounded metadata only. No shape,
        # length, nonce, slot, or key-path rule may be applied against an
        # unknown identifier.
        named = ", ".join(f"{field}={identifier}" for field, _, identifier in unsupported)
        message = (
            f"envelope uses identifiers this implementation does not support ({named}); "
            "the envelope is opaque and only the content-hash claim is validated"
        )
        if opts.role == "recipient_or_strict":
            issues.append(_issue("ENC_UNSUPPORTED", enc_path, message, severity="error"))
            for field, code, identifier in unsupported:
                issues.append(
                    _issue(
                        code,
                        (*enc_path, field),
                        f"enc.{field} '{identifier}' is not supported",
                    )
                )
        else:
            issues.append(_issue("ENC_UNSUPPORTED", enc_path, message, severity="info"))
        return

    # Fully supported identifiers → the typed scheme-1 pass is mandatory.
    # Non-text-key maps inside the typed envelope (a slot, the passphrase
    # block, its params) are rejected first, at the containing map — the same
    # pre-guard rule the record level applies, scoped here because only the
    # typed reading constrains the envelope interior.
    internal_map_issues = _enc_internal_non_text_key_issues(enc, enc_path)
    if internal_map_issues:
        issues.extend(internal_map_issues)
        return
    typed_issues = _enc_scheme1_schema_issues(enc, enc_path)
    if typed_issues:
        issues.extend(typed_issues)
        return
    _check_scheme1_envelope(enc, enc_path, opts, issues)


def _enc_internal_non_text_key_issues(
    enc: dict[str, object], enc_path: _Path
) -> list[ValidationIssue]:
    # Non-text-key maps at the typed envelope's interior positions: each
    # slot, the passphrase block, and its `params` map.
    issues: list[ValidationIssue] = []

    def flag(path: _Path) -> None:
        issues.append(_issue("SCHEMA_TYPE_MISMATCH", path, _NON_TEXT_KEY_MESSAGE))

    slots = enc.get("slots")
    if isinstance(slots, list):
        for i, slot in enumerate(slots):
            if _has_non_text_key(slot):
                flag((*enc_path, "slots", i))
    passphrase = enc.get("passphrase")
    if _has_non_text_key(passphrase):
        flag((*enc_path, "passphrase"))
    elif isinstance(passphrase, dict):
        params = cast("dict[str, object]", passphrase).get("params")
        if _has_non_text_key(params):
            flag((*enc_path, "passphrase", "params"))
    return issues


def _enc_scheme1_schema_issues(enc: dict[str, object], enc_path: _Path) -> list[ValidationIssue]:
    # The typed scheme-1 shape gate. Applied only when `scheme` / `kem` /
    # `aead` are all supported identifiers; the map is CLOSED — an unknown
    # key in a supported envelope is SCHEMA_UNKNOWN_FIELD, never a reason to
    # fall back to the opaque reading. Field lengths a value can assert in
    # isolation (`slots_mac` 32 bytes, the 16..64-byte salt) fire here with
    # their dedicated codes; if ANY issue fires, the cross-field and per-slot
    # domain rules below are foreclosed (there is no typed envelope to walk).
    issues: list[ValidationIssue] = []

    for key in enc:
        if key not in _ENC_SCHEME1_KEYS:
            issues.append(
                _issue(
                    "SCHEMA_UNKNOWN_FIELD",
                    (*enc_path, key),
                    f"unrecognized key '{key}' in a closed map",
                )
            )

    # `aead` reaches this gate unsupported-checked only when it IS a
    # registered string; a missing or non-text `aead` falls through the
    # identifier dispatch and is a shape violation of the typed reading.
    if "aead" not in enc:
        issues.append(
            _issue("SCHEMA_MISSING_REQUIRED", (*enc_path, "aead"), "enc.aead is required")
        )
    elif not isinstance(enc["aead"], str):
        issues.append(
            _issue("SCHEMA_TYPE_MISMATCH", (*enc_path, "aead"), "enc.aead must be a text string")
        )

    if "nonce" not in enc:
        issues.append(
            _issue("SCHEMA_MISSING_REQUIRED", (*enc_path, "nonce"), "enc.nonce is required")
        )
    elif not isinstance(enc["nonce"], bytes):
        issues.append(
            _issue(
                "SCHEMA_TYPE_MISMATCH",
                (*enc_path, "nonce"),
                "enc.nonce must be a CBOR byte string",
            )
        )

    kem = enc.get("kem")
    if kem is not None and not isinstance(kem, str):
        issues.append(
            _issue("SCHEMA_TYPE_MISMATCH", (*enc_path, "kem"), "enc.kem must be a text string")
        )

    slots = enc.get("slots")
    if slots is not None:
        if not isinstance(slots, list):
            issues.append(
                _issue("SCHEMA_TYPE_MISMATCH", (*enc_path, "slots"), "enc.slots must be an array")
            )
        else:
            for i, slot in enumerate(slots):
                slot_path: _Path = (*enc_path, "slots", i)
                if not isinstance(slot, dict):
                    issues.append(
                        _issue("ENC_SLOT_INVALID_SHAPE", slot_path, "a slot must be a CBOR map")
                    )
                    continue
                for field in ("epk", "kem_ct", "wrap"):
                    value = cast("dict[str, object]", slot).get(field)
                    if value is not None and not isinstance(value, bytes):
                        issues.append(
                            _issue(
                                "ENC_SLOT_INVALID_SHAPE",
                                (*slot_path, field),
                                f"slot.{field} must be a single CBOR byte string",
                            )
                        )

    slots_mac = enc.get("slots_mac")
    if slots_mac is not None:
        if not isinstance(slots_mac, bytes):
            issues.append(
                _issue(
                    "SCHEMA_TYPE_MISMATCH",
                    (*enc_path, "slots_mac"),
                    "enc.slots_mac must be a CBOR byte string",
                )
            )
        elif len(slots_mac) != 32:
            issues.append(
                _issue(
                    "ENC_SLOTS_MAC_INVALID_LENGTH",
                    (*enc_path, "slots_mac"),
                    f"slots_mac length {len(slots_mac)} != 32",
                )
            )

    passphrase = enc.get("passphrase")
    if passphrase is not None:
        pp_path: _Path = (*enc_path, "passphrase")
        if not isinstance(passphrase, dict):
            issues.append(
                _issue("SCHEMA_TYPE_MISMATCH", pp_path, "enc.passphrase must be a CBOR map")
            )
        else:
            pp = cast("dict[str, object]", passphrase)
            for key in pp:
                if key not in _PASSPHRASE_KEYS:
                    issues.append(
                        _issue(
                            "SCHEMA_UNKNOWN_FIELD",
                            (*pp_path, key),
                            f"unrecognized key '{key}' in a closed map",
                        )
                    )
            if "alg" not in pp:
                issues.append(
                    _issue(
                        "SCHEMA_MISSING_REQUIRED", (*pp_path, "alg"), "passphrase.alg is required"
                    )
                )
            elif not isinstance(pp["alg"], str):
                issues.append(
                    _issue(
                        "SCHEMA_TYPE_MISMATCH",
                        (*pp_path, "alg"),
                        "passphrase.alg must be a text string",
                    )
                )
            if "salt" not in pp:
                # An absent salt maps to the same code as a wrong-typed one —
                # the reference schema layer expresses the salt as a byte
                # string carrying its own length refinements, so its absence
                # surfaces as the type violation of that shape.
                issues.append(
                    _issue(
                        "SCHEMA_TYPE_MISMATCH",
                        (*pp_path, "salt"),
                        "passphrase.salt must be a CBOR byte string of 16..64 bytes",
                    )
                )
            elif not isinstance(pp["salt"], bytes):
                issues.append(
                    _issue(
                        "SCHEMA_TYPE_MISMATCH",
                        (*pp_path, "salt"),
                        "passphrase.salt must be a CBOR byte string",
                    )
                )
            elif len(pp["salt"]) < 16:
                issues.append(
                    _issue(
                        "ENC_PASSPHRASE_SALT_TOO_SHORT",
                        (*pp_path, "salt"),
                        f"passphrase.salt length {len(pp['salt'])} < 16",
                    )
                )
            elif len(pp["salt"]) > 64:
                issues.append(
                    _issue(
                        "ENC_PASSPHRASE_SALT_TOO_LONG",
                        (*pp_path, "salt"),
                        f"passphrase.salt length {len(pp['salt'])} > 64",
                    )
                )
            if "params" not in pp:
                issues.append(
                    _issue(
                        "SCHEMA_MISSING_REQUIRED",
                        (*pp_path, "params"),
                        "passphrase.params is required",
                    )
                )
            elif not isinstance(pp["params"], dict):
                issues.append(
                    _issue(
                        "SCHEMA_TYPE_MISMATCH",
                        (*pp_path, "params"),
                        "passphrase.params must be a CBOR map",
                    )
                )

    return issues


def _check_scheme1_envelope(
    enc: dict[str, object],
    enc_path: _Path,
    opts: _ResolvedOptions,
    issues: list[ValidationIssue],
) -> None:
    # Nonce length is registered per content format (24 bytes for
    # chacha20-poly1305-stream64k). Checked only under a supported `aead` —
    # which is guaranteed on this path.
    aead = cast("str", enc["aead"])
    nonce = cast("bytes", enc["nonce"])
    expected_nonce_len = AEAD_NONCE_LENGTHS[aead]
    if len(nonce) != expected_nonce_len:
        issues.append(
            _issue(
                "NONCE_LENGTH_MISMATCH",
                (*enc_path, "nonce"),
                f"nonce length {len(nonce)} != {expected_nonce_len} for {aead}",
            )
        )

    # Key-path cross-field rules. Exactly one of `slots` / `passphrase` is
    # present; `passphrase` forbids `kem`, `slots`, and `slots_mac`; `slots`
    # requires both `kem` and `slots_mac`; `slots_mac` binds nothing without
    # `slots`. Each independent rule emits its own code — they co-fire where
    # several apply.
    has_slots = "slots" in enc
    has_slots_mac = "slots_mac" in enc
    has_passphrase = "passphrase" in enc
    has_kem = "kem" in enc

    if has_passphrase and (has_slots or has_slots_mac or has_kem):
        issues.append(
            _issue(
                "ENC_EXCLUSIVITY_VIOLATION",
                enc_path,
                "enc.passphrase is mutually exclusive with kem / slots / slots_mac; "
                "exactly one key path is allowed",
            )
        )
    if has_slots and not has_slots_mac:
        issues.append(
            _issue("ENC_SLOTS_MAC_REQUIRED", enc_path, "enc.slots present but enc.slots_mac absent")
        )
    if has_slots_mac and not has_slots:
        issues.append(
            _issue("ENC_SLOTS_REQUIRED", enc_path, "enc.slots_mac present but enc.slots absent")
        )
    if has_slots and not has_kem:
        issues.append(_issue("ENC_KEM_REQUIRED", enc_path, "enc.slots present but enc.kem absent"))
    if not has_slots and not has_passphrase:
        issues.append(
            _issue(
                "ENC_NO_KEY_PATH",
                enc_path,
                "enc requires either slots or passphrase — no on-chain key path otherwise",
            )
        )

    if has_slots:
        slots = cast("list[dict[str, object]]", enc["slots"])
        if len(slots) < 1:
            issues.append(
                _issue(
                    "ENC_SLOTS_EMPTY",
                    (*enc_path, "slots"),
                    "slots[] must carry at least one slot",
                )
            )
        elif len(slots) > opts.max_slots:
            # Slot-count resource bound: reject before walking any slot, so a
            # hostile record cannot drive unbounded per-slot work.
            issues.append(
                _issue(
                    "ENC_SLOTS_TOO_MANY",
                    (*enc_path, "slots"),
                    f"slots length {len(slots)} exceeds the slot-count bound {opts.max_slots}",
                )
            )
        elif has_kem:
            # The descriptor exists — `kem` is registered on this path.
            descriptor = KEM_SLOT_DESCRIPTORS[cast("str", enc["kem"])]
            # Per-slot KEK uniqueness: the zero-nonce per-slot wrap is safe
            # only because each slot draws fresh KEM randomness; two slots
            # sharing the same encapsulation material would derive the same
            # KEK. Reject the repeat before any cryptographic layer would.
            seen_kem_material: set[bytes] = set()
            for i, slot in enumerate(slots):
                slot_path: _Path = (*enc_path, "slots", i)
                _check_slot_shape(slot, descriptor, cast("str", enc["kem"]), slot_path, issues)
                material = slot.get(descriptor.field)
                if isinstance(material, bytes):
                    if material in seen_kem_material:
                        issues.append(
                            _issue(
                                "ENC_SLOTS_DUPLICATE_KEM_MATERIAL",
                                (*slot_path, descriptor.field),
                                f"slot {i} {descriptor.field} duplicates an earlier slot — "
                                "per-slot KEK uniqueness is violated",
                            )
                        )
                    else:
                        seen_kem_material.add(material)

    if has_passphrase:
        _check_passphrase_block(
            cast("dict[str, object]", enc["passphrase"]),
            (*enc_path, "passphrase"),
            opts,
            issues,
        )


def _check_slot_shape(
    slot: dict[str, object],
    descriptor: KemSlotDescriptor,
    kem: str,
    slot_path: _Path,
    issues: list[ValidationIssue],
) -> None:
    # KEM-driven per-slot shape gate. The descriptor for the declared
    # envelope `kem` pins which ciphertext-bearing field MUST be present at
    # what exact length, and forbids everything else: the other KEM's field,
    # any stray key (a slot is a CLOSED 2-key map), and a missing required
    # field all surface as ENC_SLOT_INVALID_SHAPE.
    foreign_field: KemSlotField = "kem_ct" if descriptor.field == "epk" else "epk"
    if foreign_field in slot:
        issues.append(
            _issue(
                "ENC_SLOT_INVALID_SHAPE",
                (*slot_path, foreign_field),
                f"slot carries '{foreign_field}' but kem='{kem}' expects '{descriptor.field}'",
            )
        )
    for key in slot:
        if key not in SLOT_KEY_UNIVERSE:
            issues.append(
                _issue(
                    "ENC_SLOT_INVALID_SHAPE",
                    (*slot_path, key),
                    f"slot carries unexpected key '{key}'; "
                    f"a slot is a 2-key map {{{descriptor.field}, wrap}}",
                )
            )

    ct_field = slot.get(descriptor.field)
    if ct_field is None:
        issues.append(
            _issue(
                "ENC_SLOT_INVALID_SHAPE",
                (*slot_path, descriptor.field),
                f"slot for kem='{kem}' is missing required '{descriptor.field}'",
            )
        )
    elif len(cast("bytes", ct_field)) != descriptor.field_length:
        issues.append(
            _issue(
                KEM_FIELD_LENGTH_CODE[descriptor.field],
                (*slot_path, descriptor.field),
                f"slot.{descriptor.field} length {len(cast('bytes', ct_field))} "
                f"!= {descriptor.field_length} for {kem}",
            )
        )

    wrap = slot.get("wrap")
    if wrap is None:
        issues.append(
            _issue(
                "ENC_SLOT_INVALID_SHAPE",
                (*slot_path, "wrap"),
                f"slot for kem='{kem}' is missing required 'wrap'",
            )
        )
    elif len(cast("bytes", wrap)) != descriptor.wrap_length:
        issues.append(
            _issue(
                "WRAP_LENGTH_MISMATCH",
                (*slot_path, "wrap"),
                f"slot.wrap length {len(cast('bytes', wrap))} != {descriptor.wrap_length}",
            )
        )


def _check_passphrase_block(
    pp: dict[str, object],
    pp_path: _Path,
    opts: _ResolvedOptions,
    issues: list[ValidationIssue],
) -> None:
    # Passphrase block: KDF registry membership, then the registered
    # algorithm's CLOSED parameter map with exact-integer range, floors, and
    # the deployment ceiling. Salt bounds fired in the shape gate already.
    alg = cast("str", pp["alg"])
    if alg not in PASSPHRASE_KDF_ALGS:
        issues.append(
            _issue(
                "ENC_PASSPHRASE_ALG_UNSUPPORTED",
                (*pp_path, "alg"),
                f"unknown passphrase kdf alg: {alg}",
            )
        )
        return  # no algorithm-specific params rule can apply

    # argon2id: `params` is the CLOSED map of exactly {m, t, p}.
    params_path: _Path = (*pp_path, "params")
    params = cast("dict[str, object]", pp["params"])
    for key in params:
        if key not in ("m", "t", "p"):
            issues.append(
                _issue(
                    "SCHEMA_UNKNOWN_FIELD",
                    (*params_path, key),
                    f"unknown argon2id params field: {key}",
                )
            )

    ceiling = opts.passphrase_params_ceiling
    for name in _ARGON2_PARAM_NAMES:
        if name not in params:
            issues.append(
                _issue(
                    "SCHEMA_MISSING_REQUIRED",
                    (*params_path, name),
                    f"argon2id params.{name} is required",
                )
            )
            continue
        value = params[name]
        # Exact-integer discipline: Python integers are arbitrary precision,
        # so an out-of-range value is rejected without precision loss.
        if not _is_uint(value):
            issues.append(
                _issue(
                    "SCHEMA_TYPE_MISMATCH",
                    (*params_path, name),
                    f"argon2id params.{name} must be a CBOR unsigned integer",
                )
            )
            continue
        num = cast("int", value)
        if num > _UINT32_MAX:
            issues.append(
                _issue(
                    "SCHEMA_TYPE_MISMATCH",
                    (*params_path, name),
                    f"argon2id params.{name} exceeds the pinned wire range 0 .. 2^32 - 1",
                )
            )
            continue
        if num < _ARGON2_FLOORS[name]:
            issues.append(
                _issue(
                    "ENC_PASSPHRASE_ARGON2_PARAMS_TOO_LOW",
                    (*params_path, name),
                    f"argon2id requires {name} >= {_ARGON2_FLOORS[name]}",
                )
            )
            continue
        if ceiling is not None and num > ceiling[name]:
            issues.append(
                _issue(
                    "ENC_PASSPHRASE_PARAMS_EXCEED_POLICY",
                    (*params_path, name),
                    f"argon2id params.{name} = {num} exceeds "
                    f"the deployment ceiling {ceiling[name]}",
                )
            )


# =============================================================================
# Merkle commitments
# =============================================================================


def _check_merkle_commit(
    commit: dict[str, object], idx: int, issues: list[ValidationIssue]
) -> None:
    base_path: _Path = ("merkle", idx)
    alg = cast("str", commit["alg"])
    if alg not in MERKLE_COMMIT_ALG_LENGTHS:
        issues.append(
            _issue(
                "UNSUPPORTED_MERKLE_COMMIT_ALG",
                (*base_path, "alg"),
                f"unknown merkle commitment alg: {alg}",
            )
        )
    else:
        expected = MERKLE_COMMIT_ALG_LENGTHS[alg]
        root = cast("bytes", commit["root"])
        if len(root) != expected:
            issues.append(
                _issue(
                    "HASH_DIGEST_LENGTH_MISMATCH",
                    (*base_path, "root"),
                    f"merkle entry root length {len(root)} != {expected} for {alg}",
                )
            )

    # `leaf_count` is REQUIRED and pinned to `1 .. 2^32 - 1`, compared as an
    # exact integer. A negative value is a CBOR type violation (nint where
    # uint is required), distinct from an out-of-range unsigned value.
    leaf_count = commit["leaf_count"]
    if not _is_uint(leaf_count):
        issues.append(
            _issue(
                "SCHEMA_TYPE_MISMATCH",
                (*base_path, "leaf_count"),
                "leaf_count must be a CBOR unsigned integer",
            )
        )
    elif not 1 <= cast("int", leaf_count) <= _UINT32_MAX:
        issues.append(
            _issue(
                "SCHEMA_MERKLE_LEAF_COUNT_INVALID",
                (*base_path, "leaf_count"),
                f"leaf_count {leaf_count} is outside the pinned range 1 .. 2^32 - 1",
            )
        )

    uris = commit.get("uris")
    if uris is not None:
        _check_uris(cast("list[object]", uris), (*base_path, "uris"), issues)


# =============================================================================
# Record-level signature entries
# =============================================================================

# IANA-registered COSE_Key private-key-material labels (RFC 9052 §7.1). `-4`
# is the private scalar `d` for OKP / EC2 keys; a private key on the public
# permanent ledger is forbidden, so its presence is a hard structural error.
COSE_KEY_PRIVATE_MATERIAL_LABELS: Final[frozenset[int]] = frozenset({-4})


def _check_sig_entry(entry: dict[str, object], idx: int, issues: list[ValidationIssue]) -> None:
    # Path-2 `cose_key` private-material guard runs FIRST: a leaked private
    # scalar must be named even when the COSE_Sign1 is also malformed.
    cose_key = entry.get("cose_key")
    if cose_key is not None:
        key_issue = _inspect_cose_key(cast("bytes", cose_key), idx)
        if key_issue is not None:
            issues.append(key_issue)
            return

    try:
        cose = decode_cose_sign1(cast("bytes", entry["cose_sign1"]))
    except CoseVerifyError as cause:
        issues.append(_issue("MALFORMED_SIG_COSE_SIGN1", ("sigs", idx), str(cause)))
        return
    except Exception as cause:  # pragma: no cover — the validator never raises
        issues.append(_issue("MALFORMED_SIG_COSE_SIGN1", ("sigs", idx), str(cause)))
        return

    # Detached-only: the COSE_Sign1 payload MUST be CBOR null. An attached
    # payload — even zero-length — is rejected; a producer chaining a CIP-30
    # signData result must null the payload before embedding.
    if cose["payload"] is not None:
        issues.append(
            _issue(
                "MALFORMED_SIG_COSE_SIGN1",
                ("sigs", idx),
                "COSE_Sign1 payload must be null (detached); attached form forbidden",
            )
        )
        return

    # Signature-algorithm registry check (info severity — signatures are
    # optional, so an unrecognised algorithm never fails the record alone).
    protected_header = cose["protected_header"]
    alg = protected_header.get(1) if isinstance(protected_header, dict) else None
    if isinstance(alg, bool) or not isinstance(alg, int) or alg not in KNOWN_SIG_ALG_IDS:
        issues.append(
            _issue(
                "SIGNATURE_UNSUPPORTED",
                ("sigs", idx),
                f"COSE_Sign1 protected alg {alg!r} not in {{-8, -19}}",
                severity="info",
            )
        )

    # Path-1 (32-byte protected-header `kid`) and path-2 (`cose_key` sidecar)
    # are mutually exclusive.
    protected_kid = protected_header.get(4) if isinstance(protected_header, dict) else None
    if isinstance(protected_kid, bytes) and len(protected_kid) == 32 and cose_key is not None:
        issues.append(
            _issue(
                "SIG_ENTRY_KID_COSE_KEY_CONFLICT",
                ("sigs", idx),
                "sigs[i] carries both a 32-byte protected `kid` (path 1) and an inline "
                "`cose_key` (path 2); paths are mutually exclusive",
            )
        )


def _inspect_cose_key(key_bytes: bytes, i: int) -> ValidationIssue | None:
    # COSE_Key inspector (path-2 `sigs[i].cose_key` blob). Two structural
    # checks:
    #   1. Private-material guard (FIRST). COSE_Key label `-4` (the private
    #      scalar `d` for OKP / EC2 per RFC 9052 §7.1) → SIG_PRIVATE_KEY_LEAKED.
    #      Publishing a private key on the permanent ledger is catastrophic
    #      and irreversible, so this is a load-bearing producer-side preflight.
    #   2. Positive-shape guard: `kty = 1` (OKP), `crv = 6` (Ed25519), and a
    #      32-byte `-2` (x). Any failure → MALFORMED_SIG_COSE_SIGN1.
    path: _Path = ("sigs", i, "cose_key")
    try:
        decoded = decode_canonical_cbor(key_bytes)
    except Exception as cause:
        return _issue(
            "MALFORMED_SIG_COSE_SIGN1",
            path,
            f"sigs[{i}].cose_key failed to decode as cbor<COSE_Key>: {cause}",
        )

    key_map = cast("dict[object, object]", decoded) if isinstance(decoded, dict) else {}

    if any(
        isinstance(label, int)
        and not isinstance(label, bool)
        and label in COSE_KEY_PRIVATE_MATERIAL_LABELS
        for label in key_map
    ):
        return _issue(
            "SIG_PRIVATE_KEY_LEAKED",
            path,
            "cose_key carries COSE_Key private-key material (label -4, the OKP/EC2 private "
            "scalar d); publishing a private key on the permanent ledger is forbidden",
        )

    kty = key_map.get(1)
    if kty != 1 or isinstance(kty, bool):
        return _issue(
            "MALFORMED_SIG_COSE_SIGN1",
            path,
            f"sigs[{i}].cose_key COSE_Key kty (label 1) must be 1 (OKP); got {kty!r}",
        )
    crv = key_map.get(-1)
    if crv != 6 or isinstance(crv, bool):
        return _issue(
            "MALFORMED_SIG_COSE_SIGN1",
            path,
            f"sigs[{i}].cose_key COSE_Key crv (label -1) must be 6 (Ed25519); got {crv!r}",
        )
    x = key_map.get(-2)
    if not isinstance(x, bytes) or len(x) != 32:
        got = f"{len(x)}-byte bstr" if isinstance(x, bytes) else type(x).__name__
        return _issue(
            "MALFORMED_SIG_COSE_SIGN1",
            path,
            f"sigs[{i}].cose_key COSE_Key label -2 must be a 32-byte byte string "
            f"(Ed25519 public key); got {got}",
        )
    return None


# =============================================================================
# `crit[]` shape + critical-extension support
# =============================================================================


def _check_crit(
    record: dict[str, object],
    supported_critical_extensions: frozenset[str],
    issues: list[ValidationIssue],
) -> None:
    crit = record.get("crit")
    if not isinstance(crit, list):
        return
    # `crit` has `1*` cardinality: an empty array is a malformed shape.
    if len(crit) == 0:
        issues.append(
            _issue(
                "SCHEMA_TYPE_MISMATCH",
                ("crit",),
                "crit[] must carry at least one entry when present",
            )
        )
        return
    seen: set[str] = set()
    for i, crit_name in enumerate(cast("list[str]", crit)):
        reason: str | None = None
        if crit_name in TOP_LEVEL_BASE_KEYS:
            reason = f"'{crit_name}' is a base key and MUST NOT appear in crit[]"
        elif not is_extension_key(crit_name):
            reason = (
                f"'{crit_name}' does not match the extension-key form "
                "(^x-.+ or ^[a-z]+-.+, no control characters)"
            )
        elif crit_name not in record:
            reason = f"'{crit_name}' is named in crit but absent from the record map"
        elif crit_name in seen:
            reason = f"'{crit_name}' appears more than once in crit[]"
        seen.add(crit_name)
        if reason is not None:
            issues.append(_issue("CRIT_SHAPE_INVALID", ("crit", i), reason))
            continue
        # Shape-valid entry: accepted iff this validator implements the named
        # extension. The default supported set is empty, so a
        # default-configured validator fails every `crit`-bearing record — by
        # design.
        if crit_name not in supported_critical_extensions:
            issues.append(
                _issue(
                    "EXTENSION_UNSUPPORTED_CRITICAL",
                    ("crit", i),
                    f"crit lists extension '{crit_name}' that this validator does not implement",
                )
            )


__all__ = [
    "AEAD_NONCE_LENGTHS",
    "COSE_KEY_PRIVATE_MATERIAL_LABELS",
    "DEFAULT_PASSPHRASE_PARAMS_CEILING",
    "HASH_ALG_LENGTHS",
    "KEM_FIELD_LENGTH_CODE",
    "KEM_SLOT_DESCRIPTORS",
    "KNOWN_SIG_ALG_IDS",
    "MERKLE_COMMIT_ALG_LENGTHS",
    "PASSPHRASE_KDF_ALGS",
    "SLOT_KEY_UNIVERSE",
    "UNAUTHENTICATED_CIPHER_RE",
    "KemSlotDescriptor",
    "KemSlotField",
    "ValidateFail",
    "ValidateOk",
    "ValidateResult",
    "ValidationIssue",
    "ValidatorRole",
    "validate",
]
