"""Catalogue invariants for the Label 309 v1 error-code taxonomy.

The Python catalogue is a projection of the canonical machine-readable
registry; its entry ORDER is load-bearing (same-path issues tie-break by
registry position), so these tests pin the structural invariants every
implementation's projection must satisfy.
"""

from __future__ import annotations

import re
from typing import get_args

from cardanowall.poe_standard import (
    CARRIAGE_ERROR_CODES,
    DUAL_SEVERITY_CODES,
    ERROR_CODE_PART,
    ERROR_CODES,
    SEVERITY,
    STRUCTURAL_ERROR_CODES,
    VERIFIER_ERROR_CODES,
    ErrorCode,
    error_code_registry_index,
    severity_of,
)


def test_codes_are_unique_and_match_the_literal_union() -> None:
    assert len(set(ERROR_CODES)) == len(ERROR_CODES)
    assert set(get_args(ErrorCode)) == set(ERROR_CODES)


def test_every_code_is_screaming_snake_case() -> None:
    for code in ERROR_CODES:
        assert re.fullmatch(r"[A-Z][A-Z0-9_]*", code), code


def test_per_layer_views_partition_the_catalogue_in_registry_order() -> None:
    union = [*STRUCTURAL_ERROR_CODES, *CARRIAGE_ERROR_CODES, *VERIFIER_ERROR_CODES]
    assert len(union) == len(ERROR_CODES)
    assert len(set(union)) == len(ERROR_CODES)
    for view in (STRUCTURAL_ERROR_CODES, CARRIAGE_ERROR_CODES, VERIFIER_ERROR_CODES):
        indices = [error_code_registry_index(code) for code in view]
        assert indices == sorted(indices)


def test_every_code_carries_a_part_and_a_severity() -> None:
    for code in ERROR_CODES:
        assert ERROR_CODE_PART[code] in ("A", "B", "carriage")
        assert SEVERITY[code] in ("error", "warning", "info")
    assert set(ERROR_CODE_PART) == set(ERROR_CODES)
    assert set(SEVERITY) == set(ERROR_CODES)


def test_registry_index_is_the_position_in_error_codes() -> None:
    for index, code in enumerate(ERROR_CODES):
        assert error_code_registry_index(code) == index


def test_chunk_too_large_is_the_sole_carriage_layer_code() -> None:
    assert CARRIAGE_ERROR_CODES == ("CHUNK_TOO_LARGE",)


def test_structural_validator_owns_the_schema_enc_sig_crit_families() -> None:
    for code in (
        "MALFORMED_CBOR",
        "SCHEMA_EMPTY_RECORD",
        "SCHEMA_MERKLE_LEAF_COUNT_INVALID",
        "ENC_REQUIRES_CONTENT_HASH",
        "ENC_UNSUPPORTED",
        "SIG_PRIVATE_KEY_LEAKED",
        "EXTENSION_UNSUPPORTED_CRITICAL",
        "CRIT_SHAPE_INVALID",
    ):
        assert ERROR_CODE_PART[code] == "A"


def test_chain_fetch_decrypt_outcomes_are_verifier_layer_codes() -> None:
    for code in (
        "TX_INTEGRITY_MISMATCH",
        "TX_NOT_FOUND",
        "METADATA_NOT_FOUND",
        "URI_INTEGRITY_MISMATCH",
        "URI_PROVIDER_INTEGRITY_MISMATCH",
        "TAMPERED_CIPHERTEXT",
        "ENC_PASSPHRASE_UNNORMALIZABLE",
        "ENC_PASSPHRASE_EMPTY",
    ):
        assert ERROR_CODE_PART[code] == "B"


def test_non_failing_dispositions_carry_their_pinned_default_severities() -> None:
    assert severity_of("SIGNATURE_UNSUPPORTED") == "info"
    assert severity_of("ENC_UNSUPPORTED") == "info"
    assert severity_of("INSUFFICIENT_CONFIRMATIONS") == "info"
    assert severity_of("MERKLE_UNSUPPORTED") == "info"
    assert severity_of("OUT_OF_PROFILE_SKIPPED") == "info"
    assert severity_of("URI_FETCH_FAILED") == "warning"
    assert severity_of("URI_PROVIDER_INTEGRITY_MISMATCH") == "warning"
    assert severity_of("MERKLE_LEAVES_UNAVAILABLE") == "warning"


def test_dual_severity_set_is_exactly_the_four_context_promoted_codes() -> None:
    assert DUAL_SEVERITY_CODES == frozenset(
        {
            "ENC_UNSUPPORTED",
            "MERKLE_LEAVES_UNAVAILABLE",
            "MERKLE_UNSUPPORTED",
            "OUT_OF_PROFILE_SKIPPED",
        }
    )


def test_every_other_code_is_a_hard_error_or_a_pinned_non_failing_disposition() -> None:
    non_failing = {
        "SIGNATURE_UNSUPPORTED",
        "INSUFFICIENT_CONFIRMATIONS",
        "URI_FETCH_FAILED",
        "URI_PROVIDER_INTEGRITY_MISMATCH",
    }
    for code in ERROR_CODES:
        if code in DUAL_SEVERITY_CODES or code in non_failing:
            continue
        assert SEVERITY[code] == "error", code
