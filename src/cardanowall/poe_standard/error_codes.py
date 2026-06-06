from __future__ import annotations

from typing import Final, Literal

# Label 309 error-code catalogue. Single source of truth for SCREAMING_SNAKE
# code strings emitted by the structural validator (Part A) AND the verifier
# layer (Part B) — verifier-only codes are exported here so downstream
# verifiers can `from cardanowall.poe_standard.error_codes import ErrorCode`
# and obtain the canonical type.

ErrorCode = Literal[
    # ---- Structural-validator codes ----
    # CBOR decode — one code for every canonical-decode failure (malformed,
    # indefinite-length, unsorted keys, duplicate keys, non-minimal ints,
    # invalid UTF-8); no separate duplicate-key code in the taxonomy.
    "MALFORMED_CBOR",
    # Schema
    "SCHEMA_TYPE_MISMATCH",
    "SCHEMA_MISSING_REQUIRED",
    "SCHEMA_UNKNOWN_FIELD",
    "SCHEMA_INVALID_LITERAL",
    "SCHEMA_EMPTY_RECORD",
    # Hash
    "HASH_DIGEST_LENGTH_MISMATCH",
    "UNSUPPORTED_HASH_ALG",
    # Merkle
    "UNSUPPORTED_MERKLE_COMMIT_ALG",
    # URI / chunked. A chunk whose bytes do not reconstruct to valid UTF-8
    # surfaces as MALFORMED_CBOR at decode (cbor2 rejects invalid-UTF-8 tstr)
    # or, in the residual reconstruct guard, as INVALID_URI — there is no
    # separate codepoint-split code.
    "INVALID_URI",
    "CHUNK_TOO_LARGE",
    # Encryption envelope — algorithm-agility floor
    "UNAUTHENTICATED_CIPHER_FORBIDDEN",
    "UNSUPPORTED_AEAD_ALG",
    "UNSUPPORTED_KEM_ALG",
    "NONCE_LENGTH_MISMATCH",
    "UNSUPPORTED_ENVELOPE_SCHEME",
    # Encryption envelope — slots (sealed-recipient) path
    "ENC_SLOTS_EMPTY",
    "ENC_SLOT_INVALID_SHAPE",
    "ENC_SLOTS_DUPLICATE_KEM_MATERIAL",
    "ENC_SLOTS_TOO_MANY",
    "ENC_ENVELOPE_TOO_LARGE",
    "ENC_KEM_REQUIRED",
    "KEM_EPK_LENGTH_MISMATCH",
    "KEM_CT_LENGTH_MISMATCH",
    "WRAP_LENGTH_MISMATCH",
    "ENC_SLOTS_MAC_INVALID_LENGTH",
    "ENC_SLOTS_MAC_REQUIRED",
    "ENC_SLOTS_REQUIRED",
    # Encryption envelope — passphrase path
    "ENC_EXCLUSIVITY_VIOLATION",
    "ENC_NO_KEY_PATH",
    "ENC_REQUIRES_CONTENT_HASH",
    "ENC_PASSPHRASE_ALG_UNSUPPORTED",
    "ENC_PASSPHRASE_SALT_TOO_SHORT",
    "ENC_PASSPHRASE_SALT_TOO_LONG",
    "ENC_PASSPHRASE_ARGON2_PARAMS_TOO_LOW",
    "ENC_PASSPHRASE_PARAMS_EXCEED_POLICY",
    # Signatures (structural)
    "MALFORMED_SIG_COSE_SIGN1",
    "SIG_ENTRY_INVALID_SHAPE",
    "SIG_ENTRY_KID_COSE_KEY_CONFLICT",
    "SIG_PRIVATE_KEY_LEAKED",
    "SIGNATURE_UNSUPPORTED",
    # Supersedence
    "SUPERSEDES_TX_INVALID_LENGTH",
    # crit[] forward-compat
    "EXTENSION_UNSUPPORTED_CRITICAL",
    "CRIT_SHAPE_INVALID",
    # ---- Verifier-only codes (emitted during verification, not structural validation) ----
    "METADATA_NOT_FOUND",
    "INSUFFICIENT_CONFIRMATIONS",
    "SIGNER_KEY_UNRESOLVED",
    "SIGNATURE_INVALID",
    "URI_INTEGRITY_MISMATCH",
    "URI_FETCH_FAILED",
    "CONTENT_UNAVAILABLE",
    "URI_TARGET_FORBIDDEN",
    "MERKLE_ROOT_MISMATCH",
    "MERKLE_LEAVES_UNAVAILABLE",
    "MERKLE_UNSUPPORTED",
    "OUT_OF_PROFILE_SKIPPED",
    "CIPHERTEXT_UNAVAILABLE",
    "PROVIDER_UNAVAILABLE",
    "SERVICE_INDEPENDENCE_VIOLATION",
    "WRONG_DECRYPTION_INPUT_SHAPE",
    "KDF_DERIVATION_FAILED",
    "SCHEMA_MERKLE_LEAF_COUNT_MISMATCH",
    "SCHEMA_MERKLE_LEAVES_FORMAT_UNSUPPORTED",
    "SCHEMA_MERKLE_LEAVES_MALFORMED",
    "MERKLE_LEAVES_INFORMATIVE_FORM",
    "WALLET_ADDRESS_MISMATCH",
    "WRONG_RECIPIENT_KEY",
    "TAMPERED_HEADER",
    "TAMPERED_CIPHERTEXT",
]


Severity = Literal["error", "warning", "info"]

# Default severity per code. The validator MUST consult this map (or
# match the same value) when deciding which bucket — issues / warnings / info
# — to push an entry into. Codes whose severity is decided per-call (e.g.
# `MERKLE_UNSUPPORTED` is info vs. error depending on whether the record also
# carries items[]) are pinned to their default-error severity here; callers
# that need the per-call value MUST override at emission time.
SEVERITY: Final[dict[str, Severity]] = {
    # validator
    "MALFORMED_CBOR": "error",
    "SCHEMA_TYPE_MISMATCH": "error",
    "SCHEMA_MISSING_REQUIRED": "error",
    "SCHEMA_UNKNOWN_FIELD": "error",
    "SCHEMA_INVALID_LITERAL": "error",
    "SCHEMA_EMPTY_RECORD": "error",
    "HASH_DIGEST_LENGTH_MISMATCH": "error",
    "UNSUPPORTED_HASH_ALG": "error",
    "UNSUPPORTED_MERKLE_COMMIT_ALG": "error",
    "INVALID_URI": "error",
    "CHUNK_TOO_LARGE": "error",
    "UNAUTHENTICATED_CIPHER_FORBIDDEN": "error",
    "UNSUPPORTED_AEAD_ALG": "error",
    "UNSUPPORTED_KEM_ALG": "error",
    "NONCE_LENGTH_MISMATCH": "error",
    "UNSUPPORTED_ENVELOPE_SCHEME": "error",
    "ENC_SLOTS_EMPTY": "error",
    "ENC_SLOT_INVALID_SHAPE": "error",
    "ENC_SLOTS_DUPLICATE_KEM_MATERIAL": "error",
    "ENC_SLOTS_TOO_MANY": "error",
    "ENC_ENVELOPE_TOO_LARGE": "error",
    "ENC_KEM_REQUIRED": "error",
    "KEM_EPK_LENGTH_MISMATCH": "error",
    "KEM_CT_LENGTH_MISMATCH": "error",
    "WRAP_LENGTH_MISMATCH": "error",
    "ENC_SLOTS_MAC_INVALID_LENGTH": "error",
    "ENC_SLOTS_MAC_REQUIRED": "error",
    "ENC_SLOTS_REQUIRED": "error",
    "ENC_EXCLUSIVITY_VIOLATION": "error",
    "ENC_NO_KEY_PATH": "error",
    "ENC_REQUIRES_CONTENT_HASH": "error",
    "ENC_PASSPHRASE_ALG_UNSUPPORTED": "error",
    "ENC_PASSPHRASE_SALT_TOO_SHORT": "error",
    "ENC_PASSPHRASE_SALT_TOO_LONG": "error",
    "ENC_PASSPHRASE_ARGON2_PARAMS_TOO_LOW": "error",
    "ENC_PASSPHRASE_PARAMS_EXCEED_POLICY": "error",
    "MALFORMED_SIG_COSE_SIGN1": "error",
    "SIG_ENTRY_INVALID_SHAPE": "error",
    "SIG_ENTRY_KID_COSE_KEY_CONFLICT": "error",
    "SIG_PRIVATE_KEY_LEAKED": "error",
    # SIGNATURE_UNSUPPORTED is info, not error — the content claim survives an
    # unrecognised signature algorithm (an optional authorship signature the
    # verifier cannot check does not invalidate the content existence proof).
    "SIGNATURE_UNSUPPORTED": "info",
    "SUPERSEDES_TX_INVALID_LENGTH": "error",
    "EXTENSION_UNSUPPORTED_CRITICAL": "error",
    "CRIT_SHAPE_INVALID": "error",
    # verifier-only codes (defaults; a verifier may override severity per emission)
    "METADATA_NOT_FOUND": "error",
    "INSUFFICIENT_CONFIRMATIONS": "error",  # special — maps to verdict='pending'
    "SIGNER_KEY_UNRESOLVED": "error",
    "SIGNATURE_INVALID": "error",
    "URI_INTEGRITY_MISMATCH": "error",
    "URI_FETCH_FAILED": "warning",
    "CONTENT_UNAVAILABLE": "error",
    "URI_TARGET_FORBIDDEN": "error",
    "MERKLE_ROOT_MISMATCH": "error",
    "MERKLE_LEAVES_UNAVAILABLE": "warning",
    "MERKLE_UNSUPPORTED": "info",
    "OUT_OF_PROFILE_SKIPPED": "info",
    "CIPHERTEXT_UNAVAILABLE": "error",
    "PROVIDER_UNAVAILABLE": "error",
    "SERVICE_INDEPENDENCE_VIOLATION": "error",
    "WRONG_DECRYPTION_INPUT_SHAPE": "error",
    "KDF_DERIVATION_FAILED": "error",
    "SCHEMA_MERKLE_LEAF_COUNT_MISMATCH": "error",
    "SCHEMA_MERKLE_LEAVES_FORMAT_UNSUPPORTED": "error",
    "SCHEMA_MERKLE_LEAVES_MALFORMED": "error",
    "MERKLE_LEAVES_INFORMATIVE_FORM": "info",
    "WALLET_ADDRESS_MISMATCH": "error",
    "WRONG_RECIPIENT_KEY": "error",
    "TAMPERED_HEADER": "error",
    "TAMPERED_CIPHERTEXT": "error",
}


__all__ = ["SEVERITY", "ErrorCode", "Severity"]
