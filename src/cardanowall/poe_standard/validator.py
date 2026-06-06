from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Final, Literal, cast

import cbor2

from cardanowall._crypto.cbor import (
    CanonicalCborError,
    decode_canonical_cbor,
)
from cardanowall._crypto.cose_sign1 import CoseVerifyError, decode_cose_sign1

# The verifier resource bounds the sealed-PoE unwrap layer enforces. Importing
# the same constants here, rather than re-declaring them, makes the structural
# validator and the unwrap layer trip the identical thresholds: a divergence is
# impossible because there is one definition. Both are deployment-pinned
# reference values, not wire fields.
from cardanowall._crypto.sealed_poe import (
    MAX_DECODED_ENVELOPE_BYTES,
    MAX_SLOTS,
)

from .chunked import bytes_chunk_array_concat, reconstruct_chunked_uri
from .cid_profile import is_valid_cid
from .error_codes import SEVERITY, ErrorCode, Severity
from .schema import PoeRecord

# Algorithm registries — single source of truth for the closed-catalogue
# constants enforced by the structural validator.

# Signature-algorithm baseline. `-8` (EdDSA, curve-agnostic; pinned to Ed25519
# by the record signature construction) is the mandatory baseline; `-19`
# (Ed25519, fully-specified per RFC 9864) is optional and verified identically
# under the Ed25519 primitive when accepted. The reference validator accepts
# both; anything else surfaces as `SIGNATURE_UNSUPPORTED` (info-severity).
KNOWN_SIG_ALG_IDS: Final[frozenset[int]] = frozenset({-8, -19})

# Content-hash registry. Both v1 algorithms are 32-byte digests.
HASH_ALGS: Final[dict[str, int]] = {
    "sha2-256": 32,
    "blake2b-256": 32,
}
CONTENT_HASH_ALGS: Final[frozenset[str]] = frozenset(HASH_ALGS)

# List-commitment registry; disjoint from the content-hash registry.
MERKLE_COMMIT_ALGS: Final[dict[str, int]] = {"rfc9162-sha256": 32}

# AEAD registry; the closed nonce-length map IS the registry-membership check
# (membership ↔ key presence).
AEAD_NONCE_LENGTHS: Final[dict[str, int]] = {"xchacha20-poly1305": 24}

# KEM registry, expressed as a per-KEM slot DESCRIPTOR.
#
# Each registered KEM pins the exact recipient-slot shape:
#
#   - x25519:         `{ epk: bstr(32), wrap: bstr(48) }` — classical
#     ephemeral-static X25519. The per-slot `epk` is the 32-byte ephemeral
#     public key.
#   - mlkem768x25519: `{ kem_ct: <1120-byte X-Wing enc>, wrap: bstr(48) }` —
#     the X-Wing hybrid (ML-KEM-768 + X25519). The ciphertext is carried as a
#     chunked byte-string array (`kem_ct`) that MUST reassemble to exactly
#     1120 bytes; there is NO per-slot `epk` on the hybrid path.
#
# A descriptor declares the slot's ciphertext-bearing field (`epk` for a
# classical KEM, `kem_ct` for a hybrid), its expected reassembled byte length,
# and the `wrap` length (48 bytes for every KEM — 32-byte CEK + 16-byte AEAD
# tag). The validator branches on the descriptor's `field` to know which field
# MUST be present and which MUST be absent, so adding a future KEM is a
# one-line registry edit, not a new code path.

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

# The length-mismatch code emitted when a slot's ciphertext-bearing field has
# the wrong (reassembled) length, keyed by the descriptor's `field`.
KEM_FIELD_LENGTH_CODE: Final[dict[KemSlotField, ErrorCode]] = {
    "epk": "KEM_EPK_LENGTH_MISMATCH",
    "kem_ct": "KEM_CT_LENGTH_MISMATCH",
}

# Fixed envelope-field lengths used by the decoded-envelope byte backstop. The
# nonce is the XChaCha20-Poly1305 nonce (also the AEAD registry value) and
# `slots_mac` is a SHA-256 MAC; both are pinned by the construction, so the
# backstop measures the same aggregate the unwrap layer does.
_NONCE_LENGTH: Final[int] = 24
_SLOTS_MAC_LENGTH: Final[int] = 32

# Passphrase-KDF registry; pbkdf2-sha-256 is NOT registered (argon2id only).
PASSPHRASE_ALGS: Final[frozenset[str]] = frozenset({"argon2id"})

# IANA-registered COSE_Key private-key-material labels (RFC 9052 §7.1). Listed
# as a set so future labels can be added without touching call sites. `-4` is
# the private scalar `d` for OKP / EC2 keys; a private key on the public ledger
# is forbidden, so its presence is a hard structural error.
COSE_KEY_PRIVATE_MATERIAL_LABELS: Final[frozenset[int]] = frozenset({-4})

# Closed v1 base key sets — the exact set of keys each map may carry.
REGISTERED_RECORD_KEYS: Final[frozenset[str]] = frozenset(
    {"v", "items", "merkle", "supersedes", "sigs", "crit"}
)
REGISTERED_ITEM_KEYS: Final[frozenset[str]] = frozenset({"hashes", "uris", "enc"})
REGISTERED_ENC_KEYS: Final[frozenset[str]] = frozenset(
    {"scheme", "aead", "kem", "nonce", "slots", "slots_mac", "passphrase"}
)
REGISTERED_PASSPHRASE_KEYS: Final[frozenset[str]] = frozenset({"alg", "salt", "params"})
REGISTERED_SLOT_KEYS: Final[frozenset[str]] = frozenset({"epk", "kem_ct", "wrap"})
REGISTERED_SIG_ENTRY_KEYS: Final[frozenset[str]] = frozenset({"cose_sign1", "cose_key"})
REGISTERED_MERKLE_COMMIT_KEYS: Final[frozenset[str]] = frozenset(
    {"alg", "root", "leaf_count", "uris"}
)

# Extension-key namespace — vendor (`x-…`) and companion-CIP
# (`<cip>-…`) namespaces are tolerated on the top-level record; the base
# verifier ships an empty implemented-extensions set so any `crit[]` entry
# in a well-formed extension namespace surfaces as
# EXTENSION_UNSUPPORTED_CRITICAL.
EXTENSION_KEY_REGEX: Final[re.Pattern[str]] = re.compile(r"^(x-.+|[a-z]+-.+)$")
IMPLEMENTED_EXTENSIONS: Final[frozenset[str]] = frozenset()

# Unauthenticated-cipher family. An `enc.aead` naming any of these is rejected
# with UNAUTHENTICATED_CIPHER_FORBIDDEN (not the generic UNSUPPORTED_AEAD_ALG)
# so the failure names the integrity hazard. Two arms: block-cipher modes with
# no integrity (`cbc`, `ctr`, `ecb`, `cfb`, `ofb`) as a delimited token —
# matching every key-size spelling (`aes-cbc`, `aes-256-cbc`, `des-ede3-cbc`, …)
# — plus the legacy stream/block ciphers as a leading token (`rc4`, `des`,
# `3des`). The delimiters keep authenticated AEADs (`aes-256-gcm`,
# `chacha20-poly1305`, `xchacha20-poly1305`) from matching.
_UNAUTHENTICATED_CIPHER_REGEX: Final[re.Pattern[str]] = re.compile(
    r"(^|[-_])(cbc|ctr|ecb|cfb|ofb)([-_]|$)|^(rc4|des|3des)([-_]|$)", re.IGNORECASE
)

# Closed fetch set — only `ar://` and `ipfs://` are retrievable schemes.
_ABSOLUTE_URI_REGEX: Final[re.Pattern[str]] = re.compile(r"^[a-z][a-z0-9+.\-]*://", re.IGNORECASE)
_PERMITTED_SCHEME_REGEX: Final[re.Pattern[str]] = re.compile(r"^(ar|ipfs)://", re.IGNORECASE)
_ARWEAVE_TXID_REGEX: Final[re.Pattern[str]] = re.compile(r"^ar://[A-Za-z0-9_-]{43}$")


_PathSeg = str | int
_Path = tuple[_PathSeg, ...]


@dataclass(frozen=True)
class ValidationIssue:
    """One entry in the validator's result. `severity` defaults to 'error';
    warnings and info entries appear under the corresponding sequences of
    `ValidateOk`."""

    code: ErrorCode
    path: _Path
    message: str
    severity: Severity = "error"


@dataclass(frozen=True)
class ValidateOk:
    """Returned when zero error-severity issues fired. `warnings` and
    `info` may still be non-empty (e.g. `SIGNATURE_UNSUPPORTED`)."""

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


def validate(cbor_bytes: bytes) -> ValidateResult:
    """Structural validator. Pure function; performs no I/O.

    The validator MUST NOT raise — every failure mode is mapped to an error
    code in the issue list.
    """
    # Step 2 — canonical CBOR decode. Every decode failure — malformed bytes,
    # indefinite-length encodings, non-canonical (unsorted) map-key ordering,
    # duplicate map keys, non-minimal ints, invalid UTF-8 — surfaces as the
    # single MALFORMED_CBOR code per the Label 309 taxonomy (no separate code).
    try:
        decoded = decode_canonical_cbor(cbor_bytes)
    except CanonicalCborError as cause:
        return ValidateFail(
            ok=False,
            issues=(_issue((), "MALFORMED_CBOR", f"cbor decode failed: {cause}"),),
        )
    except Exception as cause:  # pragma: no cover — defensive
        return ValidateFail(
            ok=False,
            issues=(_issue((), "MALFORMED_CBOR", f"cbor decode failed: {cause}"),),
        )

    issues: list[ValidationIssue] = []
    warnings: list[ValidationIssue] = []
    info: list[ValidationIssue] = []

    if not isinstance(decoded, dict):
        return ValidateFail(
            ok=False,
            issues=(_issue((), "SCHEMA_TYPE_MISMATCH", "top-level value must be a CBOR map"),),
        )

    record_map = cast(dict[object, object], decoded)

    # Step 3 — top-level key gate (closed base + extension-key tolerance).
    extensions = _check_record_top_level_keys(record_map, issues, info)
    del extensions  # currently informational only

    # Step 3 / 4 — required `v` literal.
    if "v" not in record_map:
        issues.append(_issue(("v",), "SCHEMA_MISSING_REQUIRED", "missing required field 'v'"))
    else:
        v_val = record_map["v"]
        # `v` MUST be the unsigned integer 1. Reject CBOR floats explicitly:
        # Python's `1.0 == 1` would otherwise silently accept a malformed
        # major-type-7 float record.
        if not isinstance(v_val, int) or isinstance(v_val, bool) or v_val != 1:
            issues.append(
                _issue(
                    ("v",),
                    "SCHEMA_INVALID_LITERAL",
                    "v must be the unsigned integer 1",
                )
            )

    has_items_key = "items" in record_map
    has_merkle_key = "merkle" in record_map
    items_non_empty = False
    merkle_non_empty = False

    if has_items_key:
        items_raw = record_map["items"]
        if not isinstance(items_raw, list):
            issues.append(_issue(("items",), "SCHEMA_TYPE_MISMATCH", "items must be an array"))
        elif len(items_raw) == 0:
            # An empty `items` field without a non-empty `merkle` violates the
            # content-commitment rule; surface as SCHEMA_EMPTY_RECORD when
            # there is also no merkle, otherwise SCHEMA_TYPE_MISMATCH (the
            # array is present but unusable). Combined with the post-loop
            # check below, the net effect matches the spec: a record with
            # zero content commitments fails with SCHEMA_EMPTY_RECORD.
            pass
        else:
            items_non_empty = True
            for i, item in enumerate(items_raw):
                _validate_item_entry(item, ("items", i), issues)

    if has_merkle_key:
        merkle_raw = record_map["merkle"]
        if not isinstance(merkle_raw, list):
            issues.append(_issue(("merkle",), "SCHEMA_TYPE_MISMATCH", "merkle must be an array"))
        elif len(merkle_raw) == 0:
            pass
        else:
            merkle_non_empty = True
            for i, commit in enumerate(merkle_raw):
                _validate_merkle_commit(commit, ("merkle", i), issues)

    # Content-commitment rule: a record MUST commit to content via at least one
    # non-empty `items[]` or `merkle[]` — an empty record proves nothing.
    if not items_non_empty and not merkle_non_empty:
        issues.append(
            _issue(
                (),
                "SCHEMA_EMPTY_RECORD",
                "record carries neither `items` (>=1 entry) nor `merkle` (>=1 entry); "
                "at least one MUST be present",
            )
        )

    # Step 4h — supersedes length.
    if "supersedes" in record_map:
        _validate_supersedes(record_map["supersedes"], ("supersedes",), issues)

    # Step 4j — crit[] shape rules.
    if "crit" in record_map:
        _validate_crit(record_map, issues)

    # Step 4f / 4g — sig-entry shape + COSE_Sign1 structural decode.
    if "sigs" in record_map:
        _validate_sigs(record_map["sigs"], issues, info)

    # Step 5 — result emission.
    if issues:
        issues.sort(key=_path_key)
        return ValidateFail(ok=False, issues=tuple(issues))

    record = cast(PoeRecord, record_map)
    info.sort(key=_path_key)
    warnings.sort(key=_path_key)
    return ValidateOk(
        ok=True,
        record=record,
        info=tuple(info),
        warnings=tuple(warnings),
    )


# --- Internal helpers ------------------------------------------------------


def _issue(
    path: _Path,
    code: ErrorCode,
    message: str,
    severity: Severity | None = None,
) -> ValidationIssue:
    return ValidationIssue(
        code=code,
        path=path,
        message=message,
        severity=severity if severity is not None else SEVERITY[code],
    )


def _path_key(issue: ValidationIssue) -> str:
    return ".".join(str(s) for s in issue.path)


def _check_unknown_keys(
    obj: dict[object, object],
    allowed: frozenset[str],
    path: _Path,
    issues: list[ValidationIssue],
    label: str,
) -> None:
    for k in obj:
        if not isinstance(k, str) or k not in allowed:
            issues.append(
                _issue(
                    (*path, str(k)),
                    "SCHEMA_UNKNOWN_FIELD",
                    f"unknown {label} field: {k!r}",
                )
            )


def _check_record_top_level_keys(
    record: dict[object, object],
    issues: list[ValidationIssue],
    info: list[ValidationIssue],
) -> list[str]:
    """Validate the top-level keys: a closed base set plus tolerated extension
    namespaces. Returns the list of recognised extension-key names so the caller
    can drive crit enforcement.
    """
    extensions: list[str] = []
    for k in record:
        if not isinstance(k, str):
            issues.append(
                _issue(
                    (str(k),),
                    "SCHEMA_TYPE_MISMATCH",
                    f"top-level key {k!r} must be a text string",
                )
            )
            continue
        if k in REGISTERED_RECORD_KEYS:
            continue
        if EXTENSION_KEY_REGEX.match(k):
            extensions.append(k)
            info.append(
                _issue(
                    (k,),
                    "OUT_OF_PROFILE_SKIPPED",
                    f"top-level extension key {k!r} preserved but not interpreted by base verifier",
                    severity="info",
                )
            )
        else:
            issues.append(
                _issue(
                    (k,),
                    "SCHEMA_UNKNOWN_FIELD",
                    f"unknown record field: {k!r}",
                )
            )
    return extensions


def _validate_item_entry(
    item: object,
    path: _Path,
    issues: list[ValidationIssue],
) -> None:
    if not isinstance(item, dict):
        issues.append(_issue(path, "SCHEMA_TYPE_MISMATCH", "item entry must be a map"))
        return
    item_map = cast(dict[object, object], item)
    _check_unknown_keys(item_map, REGISTERED_ITEM_KEYS, path, issues, "item")

    hashes_raw = item_map.get("hashes")
    if not isinstance(hashes_raw, dict) or len(hashes_raw) == 0:
        issues.append(
            _issue(
                (*path, "hashes"),
                "SCHEMA_TYPE_MISMATCH",
                "hashes must be a non-empty CBOR map of <alg-id> -> <digest>",
            )
        )
    else:
        hashes_map = cast(dict[object, object], hashes_raw)
        for alg_key, digest in hashes_map.items():
            _validate_hash_map_entry(alg_key, digest, (*path, "hashes", str(alg_key)), issues)

    has_enc = "enc" in item_map

    if "uris" in item_map:
        _validate_item_uris(item_map["uris"], (*path, "uris"), issues)

    if has_enc:
        # Content-hash pre-check: every `enc`-bearing item's hashes map MUST
        # carry at least one content-hash entry, otherwise a decrypted plaintext
        # could not be bound to any claimed digest. Fires BEFORE inner enc-shape
        # validation so the more fundamental defect is reported first.
        if isinstance(hashes_raw, dict) and not any(
            isinstance(k, str) and k in CONTENT_HASH_ALGS for k in hashes_raw
        ):
            issues.append(
                _issue(
                    (*path, "enc"),
                    "ENC_REQUIRES_CONTENT_HASH",
                    "item carries `enc` but `hashes` has no content-hash entry "
                    "(sha2-256 or blake2b-256)",
                )
            )
        else:
            _validate_encryption(item_map["enc"], (*path, "enc"), issues)


def _validate_hash_map_entry(
    alg: object,
    digest: object,
    path: _Path,
    issues: list[ValidationIssue],
) -> None:
    """Validate one (alg → digest) entry of the `hashes` CBOR map.

    Duplicate algorithms are impossible by CBOR map-key uniqueness (RFC 8949
    §3.1); canonical decode rejects duplicates as MALFORMED_CBOR upstream.
    """
    if not isinstance(alg, str) or alg not in HASH_ALGS:
        issues.append(_issue(path, "UNSUPPORTED_HASH_ALG", f"unknown hash alg: {alg!r}"))
        return
    if not isinstance(digest, (bytes, bytearray)):
        issues.append(
            _issue(
                path,
                "SCHEMA_TYPE_MISMATCH",
                f"hashes[{alg!r}] value must be CBOR bytes",
            )
        )
        return
    expected = HASH_ALGS[alg]
    if len(digest) != expected:
        issues.append(
            _issue(
                path,
                "HASH_DIGEST_LENGTH_MISMATCH",
                f"hashes[{alg!r}] digest length {len(digest)} != {expected}",
            )
        )


def _validate_item_uris(raw: object, path: _Path, issues: list[ValidationIssue]) -> None:
    if not isinstance(raw, list) or len(raw) == 0:
        issues.append(
            _issue(
                path,
                "SCHEMA_TYPE_MISMATCH",
                "uris must be a non-empty array of chunked-tstr-arrays",
            )
        )
        return
    for ui, chunks in enumerate(raw):
        _validate_one_uri(chunks, (*path, ui), issues)


def _validate_one_uri(chunks: object, path: _Path, issues: list[ValidationIssue]) -> None:
    if not isinstance(chunks, list) or len(chunks) == 0:
        issues.append(
            _issue(
                path,
                "SCHEMA_TYPE_MISMATCH",
                "each URI must be a non-empty array of tstr chunks (<=64B each)",
            )
        )
        return
    typed_chunks: list[str] = []
    type_ok = True
    for ci, chunk in enumerate(chunks):
        if not isinstance(chunk, str):
            issues.append(
                _issue(
                    (*path, ci),
                    "SCHEMA_TYPE_MISMATCH",
                    "chunked-tstr element must be a text string",
                )
            )
            type_ok = False
            continue
        chunk_byte_len = len(chunk.encode("utf-8"))
        if chunk_byte_len < 1 or chunk_byte_len > 64:
            issues.append(
                _issue(
                    (*path, ci),
                    "CHUNK_TOO_LARGE",
                    f"chunk length {chunk_byte_len} not in [1, 64]",
                )
            )
            type_ok = False
            continue
        typed_chunks.append(chunk)
    if not type_ok:
        return
    ok, reconstructed, err_code = reconstruct_chunked_uri(typed_chunks)
    if not ok or reconstructed is None:
        issues.append(
            _issue(
                path,
                cast(ErrorCode, err_code if err_code is not None else "INVALID_URI"),
                "URI chunk reconstruction failed",
            )
        )
        return
    if "#" in reconstructed:
        issues.append(
            _issue(
                path,
                "INVALID_URI",
                "URI contains a fragment identifier ('#'), which is forbidden",
            )
        )
        return
    if not _ABSOLUTE_URI_REGEX.match(reconstructed):
        issues.append(
            _issue(
                path,
                "INVALID_URI",
                "URI is not absolute (missing scheme://hierarchical-part)",
            )
        )
        return
    scheme_match = _PERMITTED_SCHEME_REGEX.match(reconstructed)
    if not scheme_match:
        issues.append(
            _issue(
                path,
                "INVALID_URI",
                "unsupported URI scheme; v1 PoE URI set is {ar://, ipfs://}",
            )
        )
        return
    # RFC 3986 §3.1: the scheme is case-insensitive, the rest of the URI is not.
    # Fold ONLY the scheme to lowercase so the body (txid / CID / host) is
    # always shape-checked — never lowercase the txid or CID itself.
    scheme = reconstructed[: scheme_match.end()].lower()
    body = reconstructed[scheme_match.end() :]
    if scheme == "ar://":
        if not _ARWEAVE_TXID_REGEX.match(scheme + body):
            issues.append(
                _issue(
                    path,
                    "INVALID_URI",
                    "ar:// URI does not match `^ar://[A-Za-z0-9_-]{43}$` "
                    "(43-char base64url txid, no path/query/fragment)",
                )
            )
    elif scheme == "ipfs://":
        cid = body.split("/", 1)[0]
        if not is_valid_cid(cid):
            issues.append(
                _issue(
                    path,
                    "INVALID_URI",
                    "ipfs:// URI is not a valid CID under the Label 309 profile",
                )
            )


def _validate_encryption(enc: object, path: _Path, issues: list[ValidationIssue]) -> None:
    if not isinstance(enc, dict):
        issues.append(_issue(path, "SCHEMA_TYPE_MISMATCH", "enc must be a map"))
        return
    enc_map = cast(dict[object, object], enc)
    _check_unknown_keys(enc_map, REGISTERED_ENC_KEYS, path, issues, "enc")

    # `scheme` is the envelope-level version and MUST be exactly the integer 1.
    # Reject CBOR floats explicitly (1.0 == 1 in Python).
    scheme = enc_map.get("scheme")
    if not isinstance(scheme, int) or isinstance(scheme, bool) or scheme != 1:
        issues.append(
            _issue(
                (*path, "scheme"),
                "UNSUPPORTED_ENVELOPE_SCHEME",
                f"enc.scheme must be the unsigned integer 1; got {scheme!r}",
            )
        )

    aead = enc_map.get("aead")
    if not isinstance(aead, str):
        issues.append(
            _issue(
                (*path, "aead"),
                "UNSUPPORTED_AEAD_ALG",
                f"unknown aead alg: {aead!r}",
            )
        )
        return
    if _UNAUTHENTICATED_CIPHER_REGEX.search(aead):
        issues.append(
            _issue(
                (*path, "aead"),
                "UNAUTHENTICATED_CIPHER_FORBIDDEN",
                f"{aead!r} is an unauthenticated cipher; "
                "Label 309 mandates an authenticated (AEAD) cipher",
            )
        )
        return
    if aead not in AEAD_NONCE_LENGTHS:
        issues.append(
            _issue(
                (*path, "aead"),
                "UNSUPPORTED_AEAD_ALG",
                f"unknown aead alg: {aead!r}",
            )
        )
        return

    has_kem = "kem" in enc_map
    # `kem_resolved` is the kem string ONLY when it names a registered KEM; it
    # selects the per-slot descriptor that drives the KEM-aware slot-shape pass.
    kem_resolved: str | None = None
    if has_kem:
        kem = enc_map["kem"]
        if not isinstance(kem, str) or kem not in KEM_SLOT_DESCRIPTORS:
            issues.append(
                _issue(
                    (*path, "kem"),
                    "UNSUPPORTED_KEM_ALG",
                    f"unknown kem alg: {kem!r}",
                )
            )
        else:
            kem_resolved = kem

    nonce = enc_map.get("nonce")
    if not isinstance(nonce, (bytes, bytearray)):
        issues.append(
            _issue(
                (*path, "nonce"),
                "SCHEMA_TYPE_MISMATCH",
                "nonce must be bytes",
            )
        )
    elif len(nonce) != AEAD_NONCE_LENGTHS[aead]:
        issues.append(
            _issue(
                (*path, "nonce"),
                "NONCE_LENGTH_MISMATCH",
                f"nonce length {len(nonce)} != {AEAD_NONCE_LENGTHS[aead]} for {aead}",
            )
        )

    has_slots = "slots" in enc_map
    has_slots_mac = "slots_mac" in enc_map
    has_passphrase = "passphrase" in enc_map

    if has_slots:
        slots = enc_map["slots"]
        if not isinstance(slots, list):
            issues.append(
                _issue(
                    (*path, "slots"),
                    "SCHEMA_TYPE_MISMATCH",
                    "slots must be an array",
                )
            )
        elif len(slots) < 1:
            issues.append(
                _issue(
                    (*path, "slots"),
                    "ENC_SLOTS_EMPTY",
                    "slots must be a non-empty array",
                )
            )
        elif len(slots) > MAX_SLOTS:
            # Slot-count resource bound — reject an over-large slot array before
            # walking every slot. This is the slot-count half of the
            # partitioning-oracle resource guard; the unwrap layer trips the
            # identical threshold first, so the two layers agree. Skip the
            # per-slot, duplicate, and byte-size passes — the array is rejected
            # outright.
            issues.append(
                _issue(
                    (*path, "slots"),
                    "ENC_SLOTS_TOO_MANY",
                    f"slots length {len(slots)} exceeds MAX_SLOTS={MAX_SLOTS}",
                )
            )
        else:
            # Only validate slot shape when the KEM resolves to a known
            # descriptor; an unknown / absent KEM already emits its own code
            # above, and we cannot pick a descriptor to branch on.
            if kem_resolved is not None:
                descriptor = KEM_SLOT_DESCRIPTORS[kem_resolved]
                # Per-slot KEK uniqueness: the zero-nonce per-slot wrap is safe
                # only because each slot draws fresh KEM randomness, so two slots
                # sharing the same encapsulation material derive the same KEK and
                # repeat a (KEK, zero-nonce) pair. The material that fixes the KEK
                # is the `epk` (x25519) or the reassembled `kem_ct` (hybrid); a
                # repeat of either across slots is rejected here, before any
                # KEM/AEAD primitive — the same check the unwrap layer runs.
                seen_kem_material: set[bytes] = set()
                for i, slot in enumerate(slots):
                    _validate_slot(slot, kem_resolved, (*path, "slots", i), issues)
                    material = _slot_kem_material(slot, descriptor)
                    if material is not None:
                        if material in seen_kem_material:
                            issues.append(
                                _issue(
                                    (*path, "slots", i, descriptor.field),
                                    "ENC_SLOTS_DUPLICATE_KEM_MATERIAL",
                                    f"slot {i} {descriptor.field} duplicates an earlier slot "
                                    "— per-slot KEK uniqueness is violated",
                                )
                            )
                        else:
                            seen_kem_material.add(material)

                # Decoded-envelope byte backstop. Every per-slot field is
                # fixed-length (the descriptor pins them; a wrong length already
                # emitted its own code), so the decoded envelope's aggregate size
                # is determined by the slot count: nonce + slots_mac + count *
                # (ct-field + wrap). This is the identical measure the unwrap
                # layer computes, so the two layers trip ENC_ENVELOPE_TOO_LARGE on
                # the same envelopes. A tighter cap than MAX_SLOTS for honest
                # records.
                per_slot_bytes = descriptor.field_length + descriptor.wrap_length
                decoded_envelope_bytes = (
                    _NONCE_LENGTH + _SLOTS_MAC_LENGTH + len(slots) * per_slot_bytes
                )
                if decoded_envelope_bytes > MAX_DECODED_ENVELOPE_BYTES:
                    issues.append(
                        _issue(
                            (*path, "slots"),
                            "ENC_ENVELOPE_TOO_LARGE",
                            f"decoded envelope size {decoded_envelope_bytes} exceeds "
                            f"MAX_DECODED_ENVELOPE_BYTES={MAX_DECODED_ENVELOPE_BYTES}",
                        )
                    )

    if has_slots_mac:
        slots_mac = enc_map["slots_mac"]
        if not isinstance(slots_mac, (bytes, bytearray)):
            issues.append(
                _issue(
                    (*path, "slots_mac"),
                    "SCHEMA_TYPE_MISMATCH",
                    "slots_mac must be bytes",
                )
            )
        elif len(slots_mac) != 32:
            issues.append(
                _issue(
                    (*path, "slots_mac"),
                    "ENC_SLOTS_MAC_INVALID_LENGTH",
                    f"slots_mac length {len(slots_mac)} != 32",
                )
            )

    if has_slots and has_passphrase:
        issues.append(
            _issue(
                path,
                "ENC_EXCLUSIVITY_VIOLATION",
                "enc combines slots with passphrase; exactly one MUST be present",
            )
        )
    if has_slots and not has_slots_mac:
        issues.append(
            _issue(
                path,
                "ENC_SLOTS_MAC_REQUIRED",
                "enc.slots present but enc.slots_mac absent",
            )
        )
    if has_slots_mac and not has_slots:
        issues.append(
            _issue(
                path,
                "ENC_SLOTS_REQUIRED",
                "enc.slots_mac present but enc.slots absent",
            )
        )
    if has_slots and not has_kem:
        issues.append(
            _issue(
                path,
                "ENC_KEM_REQUIRED",
                "enc.slots present but enc.kem absent",
            )
        )
    if not has_slots and not has_passphrase:
        issues.append(
            _issue(
                path,
                "ENC_NO_KEY_PATH",
                "enc requires either slots or passphrase — no on-chain key path otherwise",
            )
        )

    if has_passphrase:
        _validate_passphrase(enc_map["passphrase"], (*path, "passphrase"), issues)


def _validate_slot(slot: object, kem: str, path: _Path, issues: list[ValidationIssue]) -> None:
    """KEM-driven per-slot shape gate (pure). `kem` is a resolved member of
    `KEM_SLOT_DESCRIPTORS`. The descriptor pins which ciphertext-bearing field
    this KEM uses (`epk` for x25519, `kem_ct` for mlkem768x25519) and its
    expected length:

      - The descriptor's ciphertext field MUST be present at the expected
        (reassembled) length.
      - The OTHER KEM's ciphertext field MUST be absent — its presence is
        cross-KEM contamination and surfaces as `ENC_SLOT_INVALID_SHAPE`.
      - `wrap` MUST be present at 48 bytes.

    `kem_ct` reassembly uses byte concatenation only (`bytes_chunk_array_concat`)
    — no crypto, no I/O — so the validator stays a pure function over CBOR bytes.
    """
    if not isinstance(slot, dict):
        issues.append(_issue(path, "ENC_SLOT_INVALID_SHAPE", "recipient slot must be a map"))
        return
    slot_map = cast(dict[object, object], slot)
    descriptor = KEM_SLOT_DESCRIPTORS[kem]

    # The ciphertext field that does NOT belong to this KEM. Its presence is a
    # shape violation regardless of length.
    foreign_field: KemSlotField = "kem_ct" if descriptor.field == "epk" else "epk"
    if foreign_field in slot_map:
        issues.append(
            _issue(
                (*path, foreign_field),
                "ENC_SLOT_INVALID_SHAPE",
                f"slot carries {foreign_field!r} but kem={kem!r} expects {descriptor.field!r}",
            )
        )

    # Any key outside {<ct field>, wrap} for this KEM is a closed-map violation.
    for k in slot_map:
        if not isinstance(k, str) or k not in REGISTERED_SLOT_KEYS:
            issues.append(
                _issue(
                    (*path, str(k)),
                    "ENC_SLOT_INVALID_SHAPE",
                    f"slot carries unexpected key {k!r}; "
                    f"a slot is a 2-key map {{{descriptor.field}, wrap}}",
                )
            )

    # The required ciphertext-bearing field MUST be present at the expected
    # (reassembled) length.
    if descriptor.field == "epk":
        epk = slot_map.get("epk")
        if epk is None:
            issues.append(
                _issue(
                    (*path, "epk"),
                    "ENC_SLOT_INVALID_SHAPE",
                    f"slot for kem={kem!r} is missing required 'epk'",
                )
            )
        elif not isinstance(epk, (bytes, bytearray)):
            issues.append(
                _issue((*path, "epk"), "ENC_SLOT_INVALID_SHAPE", "slot epk must be bytes")
            )
        elif len(epk) != descriptor.field_length:
            issues.append(
                _issue(
                    (*path, "epk"),
                    KEM_FIELD_LENGTH_CODE["epk"],
                    f"epk length {len(epk)} != {descriptor.field_length} for {kem}",
                )
            )
    else:
        reassembled = _reassemble_kem_ct(slot_map.get("kem_ct"), (*path, "kem_ct"), issues)
        if reassembled is not None and reassembled != descriptor.field_length:
            issues.append(
                _issue(
                    (*path, "kem_ct"),
                    KEM_FIELD_LENGTH_CODE["kem_ct"],
                    f"kem_ct reassembles to {reassembled} bytes "
                    f"!= {descriptor.field_length} for {kem}",
                )
            )

    # `wrap` is 48 bytes for every KEM.
    wrap = slot_map.get("wrap")
    if wrap is None:
        issues.append(
            _issue(
                (*path, "wrap"),
                "ENC_SLOT_INVALID_SHAPE",
                f"slot for kem={kem!r} is missing required 'wrap'",
            )
        )
    elif not isinstance(wrap, (bytes, bytearray)):
        issues.append(_issue((*path, "wrap"), "ENC_SLOT_INVALID_SHAPE", "slot wrap must be bytes"))
    elif len(wrap) != descriptor.wrap_length:
        issues.append(
            _issue(
                (*path, "wrap"),
                "WRAP_LENGTH_MISMATCH",
                f"wrap length {len(wrap)} != {descriptor.wrap_length}",
            )
        )


def _slot_kem_material(slot: object, descriptor: KemSlotDescriptor) -> bytes | None:
    """The encapsulation material that fixes a slot's per-slot KEK, used for the
    within-record duplicate check: the `epk` (x25519) or the reassembled
    `kem_ct` (hybrid). Returns ``None`` when the required field is absent or the
    wrong type — the shape defect already emitted `ENC_SLOT_INVALID_SHAPE`, so
    the duplicate pass simply skips that slot.
    """
    if not isinstance(slot, dict):
        return None
    slot_map = cast(dict[object, object], slot)
    if descriptor.field == "epk":
        epk = slot_map.get("epk")
        return bytes(epk) if isinstance(epk, (bytes, bytearray)) else None
    raw = slot_map.get("kem_ct")
    if not isinstance(raw, list) or len(raw) == 0:
        return None
    chunks: list[bytes] = []
    for chunk in raw:
        if not isinstance(chunk, (bytes, bytearray)):
            return None
        chunks.append(bytes(chunk))
    return bytes_chunk_array_concat(chunks)


def _reassemble_kem_ct(
    raw: object,
    path: _Path,
    issues: list[ValidationIssue],
) -> int | None:
    """Validate the chunked-bytes shape of `kem_ct` and return its reassembled
    byte length, or ``None`` when the field is missing / malformed (in which
    case the appropriate issue has already been appended).

    The chunked-bytes-array contract mirrors `sigs[i].cose_sign1`: a non-empty
    list of `bstr .size (1..64)` chunks. A missing field is ENC_SLOT_INVALID_SHAPE
    (the hybrid slot is missing its required ciphertext); a chunk outside [1,64]
    is CHUNK_TOO_LARGE (the same code the schema layer assigns on the TS twin).
    """
    if raw is None:
        issues.append(
            _issue(
                path,
                "ENC_SLOT_INVALID_SHAPE",
                "hybrid slot is missing required 'kem_ct'",
            )
        )
        return None
    if not isinstance(raw, list) or len(raw) == 0:
        issues.append(
            _issue(
                path,
                "ENC_SLOT_INVALID_SHAPE",
                "kem_ct must be a non-empty array of byte chunks (<=64B each)",
            )
        )
        return None
    typed_chunks: list[bytes] = []
    shape_ok = True
    for ci, chunk in enumerate(raw):
        if not isinstance(chunk, (bytes, bytearray)):
            issues.append(
                _issue(
                    (*path, ci),
                    "ENC_SLOT_INVALID_SHAPE",
                    "kem_ct chunk must be a byte string",
                )
            )
            shape_ok = False
            continue
        if len(chunk) < 1 or len(chunk) > 64:
            issues.append(
                _issue(
                    (*path, ci),
                    "CHUNK_TOO_LARGE",
                    f"chunk length {len(chunk)} not in [1, 64]",
                )
            )
            shape_ok = False
            continue
        typed_chunks.append(bytes(chunk))
    if not shape_ok:
        return None
    return len(bytes_chunk_array_concat(typed_chunks))


def _validate_passphrase(passphrase: object, path: _Path, issues: list[ValidationIssue]) -> None:
    if not isinstance(passphrase, dict):
        issues.append(_issue(path, "SCHEMA_TYPE_MISMATCH", "passphrase must be a map"))
        return
    pp = cast(dict[object, object], passphrase)
    _check_unknown_keys(pp, REGISTERED_PASSPHRASE_KEYS, path, issues, "passphrase")

    alg = pp.get("alg")
    if not isinstance(alg, str) or alg not in PASSPHRASE_ALGS:
        issues.append(
            _issue(
                (*path, "alg"),
                "ENC_PASSPHRASE_ALG_UNSUPPORTED",
                f"unknown passphrase alg: {alg!r}",
            )
        )

    salt = pp.get("salt")
    if not isinstance(salt, (bytes, bytearray)):
        issues.append(_issue((*path, "salt"), "SCHEMA_TYPE_MISMATCH", "salt must be bytes"))
    elif len(salt) < 16:
        issues.append(
            _issue(
                (*path, "salt"),
                "ENC_PASSPHRASE_SALT_TOO_SHORT",
                f"passphrase.salt length {len(salt)} < 16",
            )
        )
    elif len(salt) > 64:
        issues.append(
            _issue(
                (*path, "salt"),
                "ENC_PASSPHRASE_SALT_TOO_LONG",
                f"passphrase.salt length {len(salt)} > 64",
            )
        )

    params = pp.get("params")
    if not isinstance(params, dict):
        issues.append(_issue((*path, "params"), "SCHEMA_TYPE_MISMATCH", "params must be a map"))
        return

    if alg == "argon2id":
        _validate_argon2_params(cast(dict[object, object], params), (*path, "params"), issues)


def _validate_argon2_params(
    params: dict[object, object], path: _Path, issues: list[ValidationIssue]
) -> None:
    allowed = {"m", "t", "p"}
    for k in params:
        if not isinstance(k, str) or k not in allowed:
            issues.append(
                _issue(
                    (*path, str(k)),
                    "SCHEMA_UNKNOWN_FIELD",
                    f"unknown argon2id params field: {k!r}",
                )
            )

    def _int_or_none(val: object, name: str) -> int | None:
        if not isinstance(val, int) or isinstance(val, bool):
            issues.append(
                _issue(
                    (*path, name),
                    "SCHEMA_TYPE_MISMATCH",
                    f"argon2id params.{name} must be a CBOR unsigned integer",
                )
            )
            return None
        return val

    m = _int_or_none(params.get("m"), "m")
    t = _int_or_none(params.get("t"), "t")
    p = _int_or_none(params.get("p"), "p")
    if m is not None and m < 65_536:
        issues.append(
            _issue(
                (*path, "m"),
                "ENC_PASSPHRASE_ARGON2_PARAMS_TOO_LOW",
                "argon2id requires m >= 65536 KiB",
            )
        )
    if t is not None and t < 3:
        issues.append(
            _issue(
                (*path, "t"),
                "ENC_PASSPHRASE_ARGON2_PARAMS_TOO_LOW",
                "argon2id requires t >= 3",
            )
        )
    if p is not None and p < 1:
        issues.append(
            _issue(
                (*path, "p"),
                "ENC_PASSPHRASE_ARGON2_PARAMS_TOO_LOW",
                "argon2id requires p >= 1",
            )
        )


def _validate_merkle_commit(commit: object, path: _Path, issues: list[ValidationIssue]) -> None:
    if not isinstance(commit, dict):
        issues.append(_issue(path, "SCHEMA_TYPE_MISMATCH", "merkle entry must be a map"))
        return
    cm = cast(dict[object, object], commit)
    _check_unknown_keys(cm, REGISTERED_MERKLE_COMMIT_KEYS, path, issues, "merkle entry")

    alg_resolved: str | None = None
    if "alg" not in cm:
        issues.append(
            _issue(
                (*path, "alg"),
                "SCHEMA_MISSING_REQUIRED",
                "merkle entry missing required `alg`",
            )
        )
    else:
        alg = cm["alg"]
        if not isinstance(alg, str):
            issues.append(
                _issue(
                    (*path, "alg"),
                    "SCHEMA_TYPE_MISMATCH",
                    "merkle entry `alg` must be a text string",
                )
            )
        elif alg not in MERKLE_COMMIT_ALGS:
            issues.append(
                _issue(
                    (*path, "alg"),
                    "UNSUPPORTED_MERKLE_COMMIT_ALG",
                    f"unknown merkle commitment alg: {alg!r}",
                )
            )
        else:
            alg_resolved = alg

    if "root" not in cm:
        issues.append(
            _issue(
                (*path, "root"),
                "SCHEMA_MISSING_REQUIRED",
                "merkle entry missing required `root`",
            )
        )
    else:
        root = cm["root"]
        if not isinstance(root, (bytes, bytearray)):
            issues.append(
                _issue(
                    (*path, "root"),
                    "SCHEMA_TYPE_MISMATCH",
                    "merkle entry `root` must be CBOR bytes",
                )
            )
        elif alg_resolved is not None:
            expected = MERKLE_COMMIT_ALGS[alg_resolved]
            if len(root) != expected:
                issues.append(
                    _issue(
                        (*path, "root"),
                        "HASH_DIGEST_LENGTH_MISMATCH",
                        f"merkle entry `root` length {len(root)} != {expected} for {alg_resolved}",
                    )
                )

    if "leaf_count" not in cm:
        issues.append(
            _issue(
                (*path, "leaf_count"),
                "SCHEMA_MISSING_REQUIRED",
                "merkle entry missing required `leaf_count`",
            )
        )
    else:
        leaf_count = cm["leaf_count"]
        if not isinstance(leaf_count, int) or isinstance(leaf_count, bool) or leaf_count < 1:
            issues.append(
                _issue(
                    (*path, "leaf_count"),
                    "SCHEMA_TYPE_MISMATCH",
                    "merkle entry `leaf_count` must be a CBOR unsigned integer >= 1",
                )
            )

    if "uris" in cm:
        u = cm["uris"]
        if not isinstance(u, list) or len(u) == 0:
            issues.append(
                _issue(
                    (*path, "uris"),
                    "SCHEMA_TYPE_MISMATCH",
                    "merkle entry `uris` must be a non-empty array of chunked-tstr-arrays",
                )
            )
        else:
            for ui, chunks in enumerate(u):
                _validate_one_uri(chunks, (*path, "uris", ui), issues)


def _validate_supersedes(value: object, path: _Path, issues: list[ValidationIssue]) -> None:
    # A wrong-typed value is a schema defect distinct from a correctly-typed
    # byte string of the wrong length; the two carry different codes.
    if not isinstance(value, (bytes, bytearray)):
        issues.append(
            _issue(
                path,
                "SCHEMA_TYPE_MISMATCH",
                "supersedes must be a 32-byte transaction hash (CBOR bytes)",
            )
        )
    elif len(value) != 32:
        issues.append(
            _issue(
                path,
                "SUPERSEDES_TX_INVALID_LENGTH",
                "supersedes must be a 32-byte transaction hash",
            )
        )


def _validate_crit(record_map: dict[object, object], issues: list[ValidationIssue]) -> None:
    crit_arr = record_map["crit"]
    if not isinstance(crit_arr, list) or len(crit_arr) == 0:
        issues.append(
            _issue(
                ("crit",),
                "SCHEMA_TYPE_MISMATCH",
                "crit must be a non-empty array of text strings",
            )
        )
        return
    seen: set[str] = set()
    decoded_top_keys = {k for k in record_map if isinstance(k, str)}
    for ci, name in enumerate(crit_arr):
        if not isinstance(name, str):
            issues.append(
                _issue(
                    ("crit", ci),
                    "SCHEMA_TYPE_MISMATCH",
                    f"crit[{ci}] must be a text string; got {type(name).__name__}",
                )
            )
            continue
        reason: str | None = None
        if name in REGISTERED_RECORD_KEYS:
            reason = f"{name!r} is a base key and MUST NOT appear in crit[]"
        elif not EXTENSION_KEY_REGEX.match(name):
            reason = f"{name!r} does not match the extension-key regex (^x-.+ or ^[a-z]+-.+)"
        elif name not in decoded_top_keys:
            reason = f"{name!r} is named in crit but absent from the record map"
        elif name in seen:
            reason = f"{name!r} appears more than once in crit[]"
        seen.add(name)
        if reason is not None:
            issues.append(_issue(("crit", ci), "CRIT_SHAPE_INVALID", reason))
            continue
        if name not in IMPLEMENTED_EXTENSIONS:
            issues.append(
                _issue(
                    ("crit", ci),
                    "EXTENSION_UNSUPPORTED_CRITICAL",
                    f"crit entry {name!r} names an extension this verifier does not implement",
                )
            )


def _validate_sigs(
    raw: object,
    issues: list[ValidationIssue],
    info: list[ValidationIssue],
) -> None:
    if not isinstance(raw, list):
        issues.append(_issue(("sigs",), "SCHEMA_TYPE_MISMATCH", "sigs must be an array"))
        return
    if len(raw) < 1:
        issues.append(
            _issue(
                ("sigs",),
                "SCHEMA_TYPE_MISMATCH",
                "sigs must be a non-empty array when present",
            )
        )
        return
    for i, entry in enumerate(raw):
        _validate_sig_entry(entry, i, issues, info)


def _validate_sig_entry(
    entry: object,
    i: int,
    issues: list[ValidationIssue],
    info: list[ValidationIssue],
) -> None:
    if not isinstance(entry, dict):
        issues.append(
            _issue(
                ("sigs", i),
                "SIG_ENTRY_INVALID_SHAPE",
                "each sigs entry must be a CBOR map { cose_sign1, cose_key? }",
            )
        )
        return
    entry_map = cast(dict[object, object], entry)

    cose_sign1_raw = entry_map.get("cose_sign1")
    if cose_sign1_raw is None:
        issues.append(
            _issue(
                ("sigs", i),
                "SIG_ENTRY_INVALID_SHAPE",
                "sigs entry missing required 'cose_sign1' field",
            )
        )
        cose_sign1_chunks: list[bytes] | None = None
    elif not _is_chunked_bytes_shape(cose_sign1_raw):
        issues.append(
            _issue(
                ("sigs", i, "cose_sign1"),
                "SIG_ENTRY_INVALID_SHAPE",
                "sigs[i].cose_sign1 must be a non-empty list of byte chunks (<=64B each)",
            )
        )
        cose_sign1_chunks = None
    else:
        chunks_list = cast(list[bytes], cose_sign1_raw)
        _validate_bytes_chunk_lengths(chunks_list, ("sigs", i, "cose_sign1"), issues)
        cose_sign1_chunks = chunks_list

    cose_key_chunks: list[bytes] | None = None
    if "cose_key" in entry_map:
        cose_key_raw = entry_map["cose_key"]
        if not _is_chunked_bytes_shape(cose_key_raw):
            issues.append(
                _issue(
                    ("sigs", i, "cose_key"),
                    "SIG_ENTRY_INVALID_SHAPE",
                    "sigs[i].cose_key must be a non-empty list of byte chunks (<=64B each)",
                )
            )
        else:
            cose_key_chunks = cast(list[bytes], cose_key_raw)
            _validate_bytes_chunk_lengths(cose_key_chunks, ("sigs", i, "cose_key"), issues)
            _validate_cose_key_blob(cose_key_chunks, ("sigs", i, "cose_key"), issues)

    # Closed sig-entry schema — no extension-key namespace at this layer. An
    # unrecognized key is a malformed sig-entry shape, not a generic unknown
    # field, so it carries SIG_ENTRY_INVALID_SHAPE at the offending key's path.
    for k in entry_map:
        if not isinstance(k, str) or k not in REGISTERED_SIG_ENTRY_KEYS:
            issues.append(
                _issue(
                    ("sigs", i, str(k)),
                    "SIG_ENTRY_INVALID_SHAPE",
                    f"unknown sig-entry field: {k!r}",
                )
            )

    if cose_sign1_chunks is not None:
        _check_cose_sign1(cose_sign1_chunks, ("sigs", i), entry_map, issues, info)


def _is_chunked_bytes_shape(value: object) -> bool:
    if not isinstance(value, list) or len(value) == 0:
        return False
    return all(isinstance(c, (bytes, bytearray)) for c in value)


def _validate_bytes_chunk_lengths(
    chunks: list[bytes], path: _Path, issues: list[ValidationIssue]
) -> None:
    for j, c in enumerate(chunks):
        if len(c) < 1 or len(c) > 64:
            issues.append(
                _issue(
                    (*path, j),
                    "CHUNK_TOO_LARGE",
                    f"chunk length {len(c)} not in [1, 64]",
                )
            )


def _validate_cose_key_blob(
    chunks: list[bytes], path: _Path, issues: list[ValidationIssue]
) -> None:
    """Decode the chunked cose_key blob and apply the signer-key checks:
    private-material guard FIRST, then positive Ed25519 OKP shape check.
    """
    joined = b"".join(chunks)
    try:
        decoded = cbor2.loads(joined)
    except Exception as cause:
        issues.append(
            _issue(
                path,
                "MALFORMED_SIG_COSE_SIGN1",
                f"cose_key failed to decode as cbor<COSE_Key>: {cause}",
            )
        )
        return
    if not isinstance(decoded, dict):
        issues.append(
            _issue(
                path,
                "MALFORMED_SIG_COSE_SIGN1",
                f"cose_key did not decode to a CBOR map; got {type(decoded).__name__}",
            )
        )
        return
    cose_key_map = cast(dict[object, object], decoded)
    forbidden = [
        k
        for k in cose_key_map
        if isinstance(k, int) and not isinstance(k, bool) and k in COSE_KEY_PRIVATE_MATERIAL_LABELS
    ]
    if forbidden:
        issues.append(
            _issue(
                path,
                "SIG_PRIVATE_KEY_LEAKED",
                "cose_key carries COSE_Key private-key material "
                "(label -4, the OKP/EC2 private scalar d); "
                "publishing a private key on the permanent ledger is forbidden",
            )
        )
        return
    # Positive-shape check (Ed25519 OKP path-2 sidecar).
    kty = cose_key_map.get(1)
    crv = cose_key_map.get(-1)
    x_val = cose_key_map.get(-2)
    if kty != 1:
        issues.append(
            _issue(
                path,
                "MALFORMED_SIG_COSE_SIGN1",
                f"cose_key kty (label 1) must be 1 (OKP); got {kty!r}",
            )
        )
        return
    if crv != 6:
        issues.append(
            _issue(
                path,
                "MALFORMED_SIG_COSE_SIGN1",
                f"cose_key crv (label -1) must be 6 (Ed25519); got {crv!r}",
            )
        )
        return
    if -2 not in cose_key_map:
        issues.append(
            _issue(
                path,
                "MALFORMED_SIG_COSE_SIGN1",
                "cose_key missing label -2 (Ed25519 public-key bytes)",
            )
        )
        return
    if not isinstance(x_val, (bytes, bytearray)) or len(x_val) != 32:
        got = (
            f"{len(x_val)}-byte bstr"
            if isinstance(x_val, (bytes, bytearray))
            else type(x_val).__name__
        )
        issues.append(
            _issue(
                path,
                "MALFORMED_SIG_COSE_SIGN1",
                f"cose_key label -2 must be a 32-byte byte string (Ed25519 public key); got {got}",
            )
        )


def _check_cose_sign1(
    chunks: list[bytes],
    path: _Path,
    entry_map: dict[object, object],
    issues: list[ValidationIssue],
    info: list[ValidationIssue],
) -> None:
    """Step 4g — COSE_Sign1 structural decode + algorithm + path-1/path-2
    mutual-exclusion check.
    """
    merged = b"".join(chunks)
    try:
        cose = decode_cose_sign1(merged)
    except CoseVerifyError as cause:
        issues.append(
            _issue(
                path,
                "MALFORMED_SIG_COSE_SIGN1",
                cause.args[0] if cause.args else "cose decode failed",
            )
        )
        return
    if cose["payload"] is not None:
        issues.append(
            _issue(
                path,
                "MALFORMED_SIG_COSE_SIGN1",
                "COSE_Sign1 payload must be null (detached); attached form forbidden",
            )
        )
        return
    protected_header = cose["protected_header"]
    alg = protected_header.get(1) if isinstance(protected_header, dict) else None
    if not isinstance(alg, int) or isinstance(alg, bool) or alg not in KNOWN_SIG_ALG_IDS:
        info.append(
            _issue(
                path,
                "SIGNATURE_UNSUPPORTED",
                f"alg {alg!r} not in KNOWN_SIG_ALG_IDS = {set(KNOWN_SIG_ALG_IDS)}",
                severity="info",
            )
        )

    # Path-1 / path-2 mutual exclusion: a signature entry resolves its signer
    # key by exactly one path, never both.
    kid = protected_header.get(4) if isinstance(protected_header, dict) else None
    if isinstance(kid, (bytes, bytearray)) and len(kid) == 32 and "cose_key" in entry_map:
        issues.append(
            _issue(
                path,
                "SIG_ENTRY_KID_COSE_KEY_CONFLICT",
                "sigs[i] carries both a 32-byte protected `kid` (path 1) "
                "and an inline `cose_key` (path 2); paths are mutually exclusive",
            )
        )


__all__ = [
    "AEAD_NONCE_LENGTHS",
    "CONTENT_HASH_ALGS",
    "COSE_KEY_PRIVATE_MATERIAL_LABELS",
    "EXTENSION_KEY_REGEX",
    "HASH_ALGS",
    "IMPLEMENTED_EXTENSIONS",
    "KEM_FIELD_LENGTH_CODE",
    "KEM_SLOT_DESCRIPTORS",
    "KNOWN_SIG_ALG_IDS",
    "MERKLE_COMMIT_ALGS",
    "PASSPHRASE_ALGS",
    "REGISTERED_ENC_KEYS",
    "REGISTERED_ITEM_KEYS",
    "REGISTERED_MERKLE_COMMIT_KEYS",
    "REGISTERED_PASSPHRASE_KEYS",
    "REGISTERED_RECORD_KEYS",
    "REGISTERED_SIG_ENTRY_KEYS",
    "REGISTERED_SLOT_KEYS",
    "KemSlotDescriptor",
    "KemSlotField",
    "ValidateFail",
    "ValidateOk",
    "ValidateResult",
    "ValidationIssue",
    "validate",
]
