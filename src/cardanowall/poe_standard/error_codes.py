"""Label 309 v1 error-code catalogue — the Python projection of the
machine-readable registry (``error-codes.json`` in the Label 309 distribution).

Three layers emit these codes:

- **Part A** — the structural validator (:func:`~cardanowall.poe_standard.validate`):
  a pure function over the reassembled CBOR record body.
- **carriage** — the pre-validator transport step that reassembles the
  label-309 chunk array.
- **Part B** — the public / recipient verifier (chain resolution, signature
  verification, content fetch, decryption). Exported here so downstream
  verifiers dispatch on a single ``ErrorCode`` union.

Codes are SCREAMING_SNAKE_CASE and MUST match the canonical catalogue
byte-exact across the TS/PY/RS implementations — no lowercase synonyms, no
parser-internal codes, no free-form reason strings.

``ERROR_CODES`` preserves the registry's entry order. That order is
load-bearing: issues sharing an identical path tie-break by the order in
which their codes appear in the registry, so the tuple below doubles as the
cross-implementation sort key (:func:`error_code_registry_index`).
"""

from __future__ import annotations

from typing import Final, Literal

ErrorCode = Literal[
    "MALFORMED_CBOR",
    "SCHEMA_TYPE_MISMATCH",
    "SCHEMA_MISSING_REQUIRED",
    "SCHEMA_UNKNOWN_FIELD",
    "SCHEMA_INVALID_LITERAL",
    "SCHEMA_EMPTY_RECORD",
    "HASH_DIGEST_LENGTH_MISMATCH",
    "UNSUPPORTED_HASH_ALG",
    "UNSUPPORTED_MERKLE_COMMIT_ALG",
    "SCHEMA_MERKLE_LEAF_COUNT_INVALID",
    "INVALID_URI",
    "CHUNK_TOO_LARGE",
    "UNAUTHENTICATED_CIPHER_FORBIDDEN",
    "UNSUPPORTED_AEAD_ALG",
    "NONCE_LENGTH_MISMATCH",
    "UNSUPPORTED_ENVELOPE_SCHEME",
    "ENC_UNSUPPORTED",
    "ENC_SLOTS_EMPTY",
    "ENC_SLOT_INVALID_SHAPE",
    "UNSUPPORTED_KEM_ALG",
    "ENC_KEM_REQUIRED",
    "KEM_EPK_LENGTH_MISMATCH",
    "KEM_CT_LENGTH_MISMATCH",
    "WRAP_LENGTH_MISMATCH",
    "ENC_SLOTS_MAC_INVALID_LENGTH",
    "ENC_SLOTS_MAC_REQUIRED",
    "ENC_SLOTS_REQUIRED",
    "ENC_SLOTS_DUPLICATE_KEM_MATERIAL",
    "ENC_SLOTS_TOO_MANY",
    "ENC_ENVELOPE_TOO_LARGE",
    "ENC_EXCLUSIVITY_VIOLATION",
    "ENC_NO_KEY_PATH",
    "ENC_REQUIRES_CONTENT_HASH",
    "ENC_PASSPHRASE_ALG_UNSUPPORTED",
    "ENC_PASSPHRASE_SALT_TOO_SHORT",
    "ENC_PASSPHRASE_SALT_TOO_LONG",
    "ENC_PASSPHRASE_ARGON2_PARAMS_TOO_LOW",
    "ENC_PASSPHRASE_PARAMS_EXCEED_POLICY",
    "MALFORMED_SIG_COSE_SIGN1",
    "SIGNATURE_UNSUPPORTED",
    "SIG_ENTRY_INVALID_SHAPE",
    "SIG_ENTRY_KID_COSE_KEY_CONFLICT",
    "SIG_PRIVATE_KEY_LEAKED",
    "SUPERSEDES_TX_INVALID_LENGTH",
    "EXTENSION_UNSUPPORTED_CRITICAL",
    "CRIT_SHAPE_INVALID",
    "TX_NOT_FOUND",
    "PROVIDER_UNAVAILABLE",
    "TX_INTEGRITY_MISMATCH",
    "METADATA_NOT_FOUND",
    "INSUFFICIENT_CONFIRMATIONS",
    "SIGNATURE_INVALID",
    "SIGNER_KEY_UNRESOLVED",
    "WALLET_ADDRESS_MISMATCH",
    "URI_TARGET_FORBIDDEN",
    "URI_INTEGRITY_MISMATCH",
    "URI_PROVIDER_INTEGRITY_MISMATCH",
    "URI_FETCH_FAILED",
    "CONTENT_UNAVAILABLE",
    "CONTENT_FETCH_LIMIT_EXCEEDED",
    "CIPHERTEXT_UNAVAILABLE",
    "SERVICE_INDEPENDENCE_VIOLATION",
    "WRONG_DECRYPTION_INPUT_SHAPE",
    "WRONG_RECIPIENT_KEY",
    "TAMPERED_HEADER",
    "TAMPERED_CIPHERTEXT",
    "KDF_DERIVATION_FAILED",
    "ENC_PASSPHRASE_UNNORMALIZABLE",
    "ENC_PASSPHRASE_EMPTY",
    "SCHEMA_MERKLE_LEAF_COUNT_MISMATCH",
    "SCHEMA_MERKLE_LEAVES_FORMAT_UNSUPPORTED",
    "SCHEMA_MERKLE_LEAVES_MALFORMED",
    "MERKLE_ROOT_MISMATCH",
    "MERKLE_LEAVES_UNAVAILABLE",
    "MERKLE_UNSUPPORTED",
    "OUT_OF_PROFILE_SKIPPED",
]

# The canonical catalogue in registry entry order. The tuple IS the
# cross-implementation tie-break key: do not reorder.
ERROR_CODES: Final[tuple[ErrorCode, ...]] = (
    "MALFORMED_CBOR",
    "SCHEMA_TYPE_MISMATCH",
    "SCHEMA_MISSING_REQUIRED",
    "SCHEMA_UNKNOWN_FIELD",
    "SCHEMA_INVALID_LITERAL",
    "SCHEMA_EMPTY_RECORD",
    "HASH_DIGEST_LENGTH_MISMATCH",
    "UNSUPPORTED_HASH_ALG",
    "UNSUPPORTED_MERKLE_COMMIT_ALG",
    "SCHEMA_MERKLE_LEAF_COUNT_INVALID",
    "INVALID_URI",
    "CHUNK_TOO_LARGE",
    "UNAUTHENTICATED_CIPHER_FORBIDDEN",
    "UNSUPPORTED_AEAD_ALG",
    "NONCE_LENGTH_MISMATCH",
    "UNSUPPORTED_ENVELOPE_SCHEME",
    "ENC_UNSUPPORTED",
    "ENC_SLOTS_EMPTY",
    "ENC_SLOT_INVALID_SHAPE",
    "UNSUPPORTED_KEM_ALG",
    "ENC_KEM_REQUIRED",
    "KEM_EPK_LENGTH_MISMATCH",
    "KEM_CT_LENGTH_MISMATCH",
    "WRAP_LENGTH_MISMATCH",
    "ENC_SLOTS_MAC_INVALID_LENGTH",
    "ENC_SLOTS_MAC_REQUIRED",
    "ENC_SLOTS_REQUIRED",
    "ENC_SLOTS_DUPLICATE_KEM_MATERIAL",
    "ENC_SLOTS_TOO_MANY",
    "ENC_ENVELOPE_TOO_LARGE",
    "ENC_EXCLUSIVITY_VIOLATION",
    "ENC_NO_KEY_PATH",
    "ENC_REQUIRES_CONTENT_HASH",
    "ENC_PASSPHRASE_ALG_UNSUPPORTED",
    "ENC_PASSPHRASE_SALT_TOO_SHORT",
    "ENC_PASSPHRASE_SALT_TOO_LONG",
    "ENC_PASSPHRASE_ARGON2_PARAMS_TOO_LOW",
    "ENC_PASSPHRASE_PARAMS_EXCEED_POLICY",
    "MALFORMED_SIG_COSE_SIGN1",
    "SIGNATURE_UNSUPPORTED",
    "SIG_ENTRY_INVALID_SHAPE",
    "SIG_ENTRY_KID_COSE_KEY_CONFLICT",
    "SIG_PRIVATE_KEY_LEAKED",
    "SUPERSEDES_TX_INVALID_LENGTH",
    "EXTENSION_UNSUPPORTED_CRITICAL",
    "CRIT_SHAPE_INVALID",
    "TX_NOT_FOUND",
    "PROVIDER_UNAVAILABLE",
    "TX_INTEGRITY_MISMATCH",
    "METADATA_NOT_FOUND",
    "INSUFFICIENT_CONFIRMATIONS",
    "SIGNATURE_INVALID",
    "SIGNER_KEY_UNRESOLVED",
    "WALLET_ADDRESS_MISMATCH",
    "URI_TARGET_FORBIDDEN",
    "URI_INTEGRITY_MISMATCH",
    "URI_PROVIDER_INTEGRITY_MISMATCH",
    "URI_FETCH_FAILED",
    "CONTENT_UNAVAILABLE",
    "CONTENT_FETCH_LIMIT_EXCEEDED",
    "CIPHERTEXT_UNAVAILABLE",
    "SERVICE_INDEPENDENCE_VIOLATION",
    "WRONG_DECRYPTION_INPUT_SHAPE",
    "WRONG_RECIPIENT_KEY",
    "TAMPERED_HEADER",
    "TAMPERED_CIPHERTEXT",
    "KDF_DERIVATION_FAILED",
    "ENC_PASSPHRASE_UNNORMALIZABLE",
    "ENC_PASSPHRASE_EMPTY",
    "SCHEMA_MERKLE_LEAF_COUNT_MISMATCH",
    "SCHEMA_MERKLE_LEAVES_FORMAT_UNSUPPORTED",
    "SCHEMA_MERKLE_LEAVES_MALFORMED",
    "MERKLE_ROOT_MISMATCH",
    "MERKLE_LEAVES_UNAVAILABLE",
    "MERKLE_UNSUPPORTED",
    "OUT_OF_PROFILE_SKIPPED",
)

# ---------------------------------------------------------------------------
# Emitting layer (`part` in the registry)
# ---------------------------------------------------------------------------

ErrorCodePart = Literal["A", "B", "carriage"]

ERROR_CODE_PART: Final[dict[ErrorCode, ErrorCodePart]] = {
    "MALFORMED_CBOR": "A",
    "SCHEMA_TYPE_MISMATCH": "A",
    "SCHEMA_MISSING_REQUIRED": "A",
    "SCHEMA_UNKNOWN_FIELD": "A",
    "SCHEMA_INVALID_LITERAL": "A",
    "SCHEMA_EMPTY_RECORD": "A",
    "HASH_DIGEST_LENGTH_MISMATCH": "A",
    "UNSUPPORTED_HASH_ALG": "A",
    "UNSUPPORTED_MERKLE_COMMIT_ALG": "A",
    "SCHEMA_MERKLE_LEAF_COUNT_INVALID": "A",
    "INVALID_URI": "A",
    "CHUNK_TOO_LARGE": "carriage",
    "UNAUTHENTICATED_CIPHER_FORBIDDEN": "A",
    "UNSUPPORTED_AEAD_ALG": "A",
    "NONCE_LENGTH_MISMATCH": "A",
    "UNSUPPORTED_ENVELOPE_SCHEME": "A",
    "ENC_UNSUPPORTED": "A",
    "ENC_SLOTS_EMPTY": "A",
    "ENC_SLOT_INVALID_SHAPE": "A",
    "UNSUPPORTED_KEM_ALG": "A",
    "ENC_KEM_REQUIRED": "A",
    "KEM_EPK_LENGTH_MISMATCH": "A",
    "KEM_CT_LENGTH_MISMATCH": "A",
    "WRAP_LENGTH_MISMATCH": "A",
    "ENC_SLOTS_MAC_INVALID_LENGTH": "A",
    "ENC_SLOTS_MAC_REQUIRED": "A",
    "ENC_SLOTS_REQUIRED": "A",
    "ENC_SLOTS_DUPLICATE_KEM_MATERIAL": "A",
    "ENC_SLOTS_TOO_MANY": "A",
    "ENC_ENVELOPE_TOO_LARGE": "A",
    "ENC_EXCLUSIVITY_VIOLATION": "A",
    "ENC_NO_KEY_PATH": "A",
    "ENC_REQUIRES_CONTENT_HASH": "A",
    "ENC_PASSPHRASE_ALG_UNSUPPORTED": "A",
    "ENC_PASSPHRASE_SALT_TOO_SHORT": "A",
    "ENC_PASSPHRASE_SALT_TOO_LONG": "A",
    "ENC_PASSPHRASE_ARGON2_PARAMS_TOO_LOW": "A",
    "ENC_PASSPHRASE_PARAMS_EXCEED_POLICY": "A",
    "MALFORMED_SIG_COSE_SIGN1": "A",
    "SIGNATURE_UNSUPPORTED": "A",
    "SIG_ENTRY_INVALID_SHAPE": "A",
    "SIG_ENTRY_KID_COSE_KEY_CONFLICT": "A",
    "SIG_PRIVATE_KEY_LEAKED": "A",
    "SUPERSEDES_TX_INVALID_LENGTH": "A",
    "EXTENSION_UNSUPPORTED_CRITICAL": "A",
    "CRIT_SHAPE_INVALID": "A",
    "TX_NOT_FOUND": "B",
    "PROVIDER_UNAVAILABLE": "B",
    "TX_INTEGRITY_MISMATCH": "B",
    "METADATA_NOT_FOUND": "B",
    "INSUFFICIENT_CONFIRMATIONS": "B",
    "SIGNATURE_INVALID": "B",
    "SIGNER_KEY_UNRESOLVED": "B",
    "WALLET_ADDRESS_MISMATCH": "B",
    "URI_TARGET_FORBIDDEN": "B",
    "URI_INTEGRITY_MISMATCH": "B",
    "URI_PROVIDER_INTEGRITY_MISMATCH": "B",
    "URI_FETCH_FAILED": "B",
    "CONTENT_UNAVAILABLE": "B",
    "CONTENT_FETCH_LIMIT_EXCEEDED": "B",
    "CIPHERTEXT_UNAVAILABLE": "B",
    "SERVICE_INDEPENDENCE_VIOLATION": "B",
    "WRONG_DECRYPTION_INPUT_SHAPE": "B",
    "WRONG_RECIPIENT_KEY": "B",
    "TAMPERED_HEADER": "B",
    "TAMPERED_CIPHERTEXT": "B",
    "KDF_DERIVATION_FAILED": "B",
    "ENC_PASSPHRASE_UNNORMALIZABLE": "B",
    "ENC_PASSPHRASE_EMPTY": "B",
    "SCHEMA_MERKLE_LEAF_COUNT_MISMATCH": "B",
    "SCHEMA_MERKLE_LEAVES_FORMAT_UNSUPPORTED": "B",
    "SCHEMA_MERKLE_LEAVES_MALFORMED": "B",
    "MERKLE_ROOT_MISMATCH": "B",
    "MERKLE_LEAVES_UNAVAILABLE": "B",
    "MERKLE_UNSUPPORTED": "B",
    "OUT_OF_PROFILE_SKIPPED": "B",
}

# Layer-filtered views, in registry order. The structural validator emits only
# Part A codes; the carriage (transport) step emits only the carriage code;
# the verifier layer emits Part B codes (and re-runs the first two layers).
STRUCTURAL_ERROR_CODES: Final[tuple[ErrorCode, ...]] = tuple(
    code for code in ERROR_CODES if ERROR_CODE_PART[code] == "A"
)
CARRIAGE_ERROR_CODES: Final[tuple[ErrorCode, ...]] = tuple(
    code for code in ERROR_CODES if ERROR_CODE_PART[code] == "carriage"
)
VERIFIER_ERROR_CODES: Final[tuple[ErrorCode, ...]] = tuple(
    code for code in ERROR_CODES if ERROR_CODE_PART[code] == "B"
)

# ---------------------------------------------------------------------------
# Severity
# ---------------------------------------------------------------------------
#
# `error` fails the record; `warning` is a non-fatal runtime anomaly; `info`
# is a deliberate non-failing disposition. Four codes carry DUAL severity —
# the map records their DEFAULT reading, and a strict context promotes them
# to `error`:
#
#   - ENC_UNSUPPORTED            — info by default; error for the recipient
#                                  role / strict sealed-crypto mode.
#   - MERKLE_LEAVES_UNAVAILABLE  — warning beside a verified content
#                                  commitment; error when its absence leaves
#                                  the record with no verified commitment.
#   - MERKLE_UNSUPPORTED         — info beside a validated items[] claim;
#                                  error on a merkle-only record.
#   - OUT_OF_PROFILE_SKIPPED     — info in render mode; error in strict
#                                  end-to-end mode.
#
# No layer may soften an `error` into a `warning` to make a record pass.

Severity = Literal["error", "warning", "info"]

SEVERITY: Final[dict[ErrorCode, Severity]] = {
    "MALFORMED_CBOR": "error",
    "SCHEMA_TYPE_MISMATCH": "error",
    "SCHEMA_MISSING_REQUIRED": "error",
    "SCHEMA_UNKNOWN_FIELD": "error",
    "SCHEMA_INVALID_LITERAL": "error",
    "SCHEMA_EMPTY_RECORD": "error",
    "HASH_DIGEST_LENGTH_MISMATCH": "error",
    "UNSUPPORTED_HASH_ALG": "error",
    "UNSUPPORTED_MERKLE_COMMIT_ALG": "error",
    "SCHEMA_MERKLE_LEAF_COUNT_INVALID": "error",
    "INVALID_URI": "error",
    "CHUNK_TOO_LARGE": "error",
    "UNAUTHENTICATED_CIPHER_FORBIDDEN": "error",
    "UNSUPPORTED_AEAD_ALG": "error",
    "NONCE_LENGTH_MISMATCH": "error",
    "UNSUPPORTED_ENVELOPE_SCHEME": "error",
    "ENC_UNSUPPORTED": "info",
    "ENC_SLOTS_EMPTY": "error",
    "ENC_SLOT_INVALID_SHAPE": "error",
    "UNSUPPORTED_KEM_ALG": "error",
    "ENC_KEM_REQUIRED": "error",
    "KEM_EPK_LENGTH_MISMATCH": "error",
    "KEM_CT_LENGTH_MISMATCH": "error",
    "WRAP_LENGTH_MISMATCH": "error",
    "ENC_SLOTS_MAC_INVALID_LENGTH": "error",
    "ENC_SLOTS_MAC_REQUIRED": "error",
    "ENC_SLOTS_REQUIRED": "error",
    "ENC_SLOTS_DUPLICATE_KEM_MATERIAL": "error",
    "ENC_SLOTS_TOO_MANY": "error",
    "ENC_ENVELOPE_TOO_LARGE": "error",
    "ENC_EXCLUSIVITY_VIOLATION": "error",
    "ENC_NO_KEY_PATH": "error",
    "ENC_REQUIRES_CONTENT_HASH": "error",
    "ENC_PASSPHRASE_ALG_UNSUPPORTED": "error",
    "ENC_PASSPHRASE_SALT_TOO_SHORT": "error",
    "ENC_PASSPHRASE_SALT_TOO_LONG": "error",
    "ENC_PASSPHRASE_ARGON2_PARAMS_TOO_LOW": "error",
    "ENC_PASSPHRASE_PARAMS_EXCEED_POLICY": "error",
    "MALFORMED_SIG_COSE_SIGN1": "error",
    "SIGNATURE_UNSUPPORTED": "info",
    "SIG_ENTRY_INVALID_SHAPE": "error",
    "SIG_ENTRY_KID_COSE_KEY_CONFLICT": "error",
    "SIG_PRIVATE_KEY_LEAKED": "error",
    "SUPERSEDES_TX_INVALID_LENGTH": "error",
    "EXTENSION_UNSUPPORTED_CRITICAL": "error",
    "CRIT_SHAPE_INVALID": "error",
    "TX_NOT_FOUND": "error",
    "PROVIDER_UNAVAILABLE": "error",
    "TX_INTEGRITY_MISMATCH": "error",
    "METADATA_NOT_FOUND": "error",
    "INSUFFICIENT_CONFIRMATIONS": "info",
    "SIGNATURE_INVALID": "error",
    "SIGNER_KEY_UNRESOLVED": "error",
    "WALLET_ADDRESS_MISMATCH": "error",
    "URI_TARGET_FORBIDDEN": "error",
    "URI_INTEGRITY_MISMATCH": "error",
    "URI_PROVIDER_INTEGRITY_MISMATCH": "warning",
    "URI_FETCH_FAILED": "warning",
    "CONTENT_UNAVAILABLE": "error",
    "CONTENT_FETCH_LIMIT_EXCEEDED": "error",
    "CIPHERTEXT_UNAVAILABLE": "error",
    "SERVICE_INDEPENDENCE_VIOLATION": "error",
    "WRONG_DECRYPTION_INPUT_SHAPE": "error",
    "WRONG_RECIPIENT_KEY": "error",
    "TAMPERED_HEADER": "error",
    "TAMPERED_CIPHERTEXT": "error",
    "KDF_DERIVATION_FAILED": "error",
    "ENC_PASSPHRASE_UNNORMALIZABLE": "error",
    "ENC_PASSPHRASE_EMPTY": "error",
    "SCHEMA_MERKLE_LEAF_COUNT_MISMATCH": "error",
    "SCHEMA_MERKLE_LEAVES_FORMAT_UNSUPPORTED": "error",
    "SCHEMA_MERKLE_LEAVES_MALFORMED": "error",
    "MERKLE_ROOT_MISMATCH": "error",
    "MERKLE_LEAVES_UNAVAILABLE": "warning",
    "MERKLE_UNSUPPORTED": "info",
    "OUT_OF_PROFILE_SKIPPED": "info",
}

# Codes whose severity is context-dependent. `SEVERITY` records the default
# reading; the promoting context escalates to `error`.
DUAL_SEVERITY_CODES: Final[frozenset[ErrorCode]] = frozenset(
    {
        "ENC_UNSUPPORTED",
        "MERKLE_LEAVES_UNAVAILABLE",
        "MERKLE_UNSUPPORTED",
        "OUT_OF_PROFILE_SKIPPED",
    }
)


def severity_of(code: ErrorCode) -> Severity:
    return SEVERITY[code]


_REGISTRY_INDEX: Final[dict[ErrorCode, int]] = {
    code: index for index, code in enumerate(ERROR_CODES)
}


def error_code_registry_index(code: ErrorCode) -> int:
    """Position of a code in the canonical registry. Issues that carry an
    identical path are ordered by this index, so every implementation sorts an
    issue list identically."""
    return _REGISTRY_INDEX[code]


__all__ = [
    "CARRIAGE_ERROR_CODES",
    "DUAL_SEVERITY_CODES",
    "ERROR_CODES",
    "ERROR_CODE_PART",
    "SEVERITY",
    "STRUCTURAL_ERROR_CODES",
    "VERIFIER_ERROR_CODES",
    "ErrorCode",
    "ErrorCodePart",
    "Severity",
    "error_code_registry_index",
    "severity_of",
]
