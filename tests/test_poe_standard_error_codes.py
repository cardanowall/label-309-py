from __future__ import annotations

from typing import get_args

from cardanowall.poe_standard import SEVERITY, ErrorCode


def test_every_code_has_severity() -> None:
    codes = set(get_args(ErrorCode))
    assert codes == set(SEVERITY.keys())


def test_validator_codes_present() -> None:
    codes = set(get_args(ErrorCode))
    # Spot-check both renamed and net-new codes from the Label 309 v2 catalogue.
    for code in (
        "MALFORMED_CBOR",
        "SCHEMA_EMPTY_RECORD",
        "NONCE_LENGTH_MISMATCH",
        "UNSUPPORTED_ENVELOPE_SCHEME",
        "ENC_SLOTS_MAC_REQUIRED",
        "ENC_SLOTS_MAC_INVALID_LENGTH",
        "ENC_SLOTS_REQUIRED",
        "KEM_EPK_LENGTH_MISMATCH",
        "ENC_PASSPHRASE_ALG_UNSUPPORTED",
        "ENC_PASSPHRASE_ARGON2_PARAMS_TOO_LOW",
        "ENC_PASSPHRASE_SALT_TOO_SHORT",
        "ENC_PASSPHRASE_SALT_TOO_LONG",
        "ENC_SLOTS_EMPTY",
        "ENC_KEM_REQUIRED",
        "ENC_REQUIRES_CONTENT_HASH",
        "SIG_ENTRY_INVALID_SHAPE",
        "SIG_ENTRY_KID_COSE_KEY_CONFLICT",
        "SIG_PRIVATE_KEY_LEAKED",
        "EXTENSION_UNSUPPORTED_CRITICAL",
        "CRIT_SHAPE_INVALID",
        "INVALID_URI",
        "UNSUPPORTED_MERKLE_COMMIT_ALG",
        "UNSUPPORTED_HASH_ALG",
        "UNSUPPORTED_AEAD_ALG",
        "UNSUPPORTED_KEM_ALG",
        "MALFORMED_SIG_COSE_SIGN1",
        "SIGNATURE_UNSUPPORTED",
    ):
        assert code in codes, f"missing validator code {code}"


def test_verifier_codes_present() -> None:
    codes = set(get_args(ErrorCode))
    for code in (
        "INSUFFICIENT_CONFIRMATIONS",
        "SIGNATURE_INVALID",
        "SIGNER_KEY_UNRESOLVED",
        "WALLET_ADDRESS_MISMATCH",
        "URI_TARGET_FORBIDDEN",
        "URI_INTEGRITY_MISMATCH",
        "URI_FETCH_FAILED",
        "CONTENT_UNAVAILABLE",
        "CIPHERTEXT_UNAVAILABLE",
        "PROVIDER_UNAVAILABLE",
        "SCHEMA_MERKLE_LEAF_COUNT_MISMATCH",
        "SCHEMA_MERKLE_LEAVES_FORMAT_UNSUPPORTED",
        "MERKLE_ROOT_MISMATCH",
        "MERKLE_LEAVES_UNAVAILABLE",
        "MERKLE_UNSUPPORTED",
        "OUT_OF_PROFILE_SKIPPED",
    ):
        assert code in codes, f"missing verifier code {code}"


def test_removed_codes_absent() -> None:
    codes = set(get_args(ErrorCode))
    # Pre-rewrite catalogue entries that MUST NOT appear in v2.
    for removed in (
        "IV_LENGTH_MISMATCH",
        "UNSUPPORTED_ENC_VERSION",
        "ENC_HDR_MAC_REQUIRED",
        "ENC_HDR_MAC_INVALID_LENGTH",
        "ENC_RECIPIENTS_REQUIRED",
        "ENC_RECIPIENTS_OUT_OF_RANGE",
        "KEM_EPH_LENGTH_MISMATCH",
        "UNSUPPORTED_KDF_ALG",
        "KDF_ITERATIONS_TOO_LOW",
        "UNSUPPORTED_SIG_ALG",
        "MALFORMED_SIG_COSE",
        "EMPTY_RECORD",
        "HASH_ALG_DUPLICATE",
        "SINGLE_HASH",
    ):
        assert removed not in codes, f"removed code {removed} still present"


def test_signature_unsupported_is_info() -> None:
    assert SEVERITY["SIGNATURE_UNSUPPORTED"] == "info"


def test_uri_fetch_failed_is_warning() -> None:
    assert SEVERITY["URI_FETCH_FAILED"] == "warning"
