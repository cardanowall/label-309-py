"""Structural-validator conformance replay + behaviours the corpus cannot pin.

The shared validator corpora are the cross-language oracle: byte-pinned record
bodies, each with the exact distinct error-severity code set a conformant
structural validator emits (an empty expected set pins an accepted record),
the exact info-severity set on accepted records, and — for the role corpus —
both readings of the unknown-envelope rule. The TypeScript, Python, and Rust
validators replay the same bytes and must agree code-for-code.

The targeted tests below cover the seams a frozen corpus cannot exercise:
default option wiring, the ceiling-disable switch, issue-path attribution,
deterministic issue ordering, and the encode→validate round-trip.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

import pytest

from cardanowall._crypto.cbor import encode_canonical_cbor
from cardanowall.poe_standard import (
    ValidateFail,
    ValidateOk,
    ValidateResult,
    encode_poe_record,
    validate,
)

_FIXTURES = Path(__file__).parent / "fixtures" / "validator"


def _load_vectors(name: str) -> list[dict[str, Any]]:
    corpus = json.loads((_FIXTURES / f"{name}.json").read_text(encoding="utf-8"))
    return cast("list[dict[str, Any]]", corpus["vectors"])


def _validate_kwargs(options: dict[str, Any] | None) -> dict[str, Any]:
    """Map fixture `validator_options` 1:1 onto the validate() kwargs."""
    kwargs: dict[str, Any] = {}
    if options is None:
        return kwargs
    if "supportedCriticalExtensions" in options:
        kwargs["supported_critical_extensions"] = frozenset(options["supportedCriticalExtensions"])
    if "maxSlots" in options:
        kwargs["max_slots"] = options["maxSlots"]
    if "maxEncEnvelopeBytes" in options:
        kwargs["max_enc_envelope_bytes"] = options["maxEncEnvelopeBytes"]
    if "passphraseParamsCeiling" in options:
        ceiling = options["passphraseParamsCeiling"]
        kwargs["passphrase_params_ceiling"] = (
            None if ceiling is None else {"m": ceiling["m"], "t": ceiling["t"], "p": ceiling["p"]}
        )
    return kwargs


def _distinct_error_codes(result: ValidateResult) -> list[str]:
    if isinstance(result, ValidateOk):
        return []
    return sorted({issue.code for issue in result.issues if issue.severity == "error"})


def _distinct_info_codes(result: ValidateResult) -> list[str]:
    if isinstance(result, ValidateOk):
        return sorted({issue.code for issue in result.info})
    return sorted({issue.code for issue in result.issues if issue.severity == "info"})


def _enc(value: object) -> bytes:
    return encode_canonical_cbor(value)  # type: ignore[arg-type]


def _ok_record_dict() -> dict[str, Any]:
    return {
        "v": 1,
        "items": [{"hashes": {"sha2-256": b"\x11" * 32}}],
    }


# ---------------------------------------------------------------------------
# Corpus replay — rejection vectors (error-code sets compare sorted-distinct)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "vector",
    _load_vectors("validator-negative"),
    ids=lambda v: cast("str", v["name"]),
)
def test_validator_negative_corpus(vector: dict[str, Any]) -> None:
    result = validate(
        bytes.fromhex(vector["cbor_hex"]),
        **_validate_kwargs(vector.get("validator_options")),
    )
    expected = sorted(vector["expected_error_codes"])
    if not expected:
        assert isinstance(result, ValidateOk), _distinct_error_codes(result)
    else:
        assert _distinct_error_codes(result) == expected


@pytest.mark.parametrize(
    "vector",
    _load_vectors("validator-bounds-negative"),
    ids=lambda v: cast("str", v["name"]),
)
def test_validator_bounds_negative_corpus(vector: dict[str, Any]) -> None:
    result = validate(
        bytes.fromhex(vector["cbor_hex"]),
        **_validate_kwargs(vector.get("validator_options")),
    )
    assert _distinct_error_codes(result) == sorted(vector["expected_error_codes"])


@pytest.mark.parametrize(
    "vector",
    _load_vectors("validator-bounds-negative"),
    ids=lambda v: cast("str", v["name"]),
)
def test_validator_bounds_defaults_match_fixture_options(vector: dict[str, Any]) -> None:
    # The bounds vectors carry the reference bounds explicitly; a
    # default-configured validator MUST trip the identical codes, proving the
    # default maxSlots / maxEncEnvelopeBytes wiring equals the reference.
    result = validate(bytes.fromhex(vector["cbor_hex"]))
    assert _distinct_error_codes(result) == sorted(vector["expected_error_codes"])


# ---------------------------------------------------------------------------
# Corpus replay — acceptance vectors (exact info sets, zero warnings)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "vector",
    _load_vectors("validator-positive"),
    ids=lambda v: cast("str", v["name"]),
)
def test_validator_positive_corpus(vector: dict[str, Any]) -> None:
    assert vector["expected_error_codes"] == []
    result = validate(bytes.fromhex(vector["cbor_hex"]))
    assert isinstance(result, ValidateOk), _distinct_error_codes(result)
    assert _distinct_info_codes(result) == sorted(vector.get("expected_info_codes", []))
    assert result.warnings == ()


# ---------------------------------------------------------------------------
# Corpus replay — role-dependent envelope dispositions
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "vector",
    _load_vectors("enc-unsupported-roles"),
    ids=lambda v: cast("str", v["name"]),
)
@pytest.mark.parametrize("role", ["public", "recipient_or_strict"])
def test_enc_unsupported_roles_corpus(vector: dict[str, Any], role: str) -> None:
    expected = vector["expected_by_role"][role]
    result = validate(
        bytes.fromhex(vector["cbor_hex"]),
        role=cast("Any", role),
    )
    assert isinstance(result, ValidateOk) == expected["valid"]
    assert _distinct_error_codes(result) == sorted(expected["error_codes"])
    assert _distinct_info_codes(result) == sorted(expected["info_codes"])


def test_role_defaults_to_the_public_reading() -> None:
    vector = _load_vectors("enc-unsupported-roles")[0]
    result = validate(bytes.fromhex(vector["cbor_hex"]))
    assert isinstance(result, ValidateOk) == vector["expected_by_role"]["public"]["valid"]


# ---------------------------------------------------------------------------
# Default options the corpus cannot pin
# ---------------------------------------------------------------------------


def _passphrase_record(m: int, t: int = 3, p: int = 1) -> dict[str, Any]:
    rec = _ok_record_dict()
    rec["items"][0]["enc"] = {
        "scheme": 1,
        "aead": "chacha20-poly1305-stream64k",
        "nonce": b"\x00" * 24,
        "passphrase": {
            "alg": "argon2id",
            "salt": b"\x00" * 16,
            "params": {"m": m, "t": t, "p": p},
        },
    }
    return rec


def test_passphrase_ceiling_is_enforced_by_default() -> None:
    # One above the reference ceiling (m = 2 GiB in KiB), still within uint32:
    # the DEFAULT-configured validator rejects, no options passed.
    result = validate(_enc(_passphrase_record(m=2_097_153)))
    assert _distinct_error_codes(result) == ["ENC_PASSPHRASE_PARAMS_EXCEED_POLICY"]


def test_passphrase_ceiling_none_disables_the_policy() -> None:
    result = validate(_enc(_passphrase_record(m=2_097_153)), passphrase_params_ceiling=None)
    assert isinstance(result, ValidateOk)


def test_passphrase_ceiling_never_relaxes_the_uint32_wire_range() -> None:
    # Disabling the deployment ceiling does not admit values beyond the
    # pinned wire range; 2^32 is still a type-range violation.
    result = validate(_enc(_passphrase_record(m=2**32)), passphrase_params_ceiling=None)
    assert _distinct_error_codes(result) == ["SCHEMA_TYPE_MISMATCH"]


def test_supported_critical_extensions_default_is_empty() -> None:
    rec = _ok_record_dict()
    rec["x-note"] = "value"
    rec["crit"] = ["x-note"]
    default = validate(_enc(rec))
    assert _distinct_error_codes(default) == ["EXTENSION_UNSUPPORTED_CRITICAL"]
    supported = validate(_enc(rec), supported_critical_extensions=frozenset({"x-note"}))
    assert isinstance(supported, ValidateOk)


# ---------------------------------------------------------------------------
# Issue-path attribution and deterministic ordering
# ---------------------------------------------------------------------------


def test_registry_codes_attach_at_the_offending_entry() -> None:
    rec = _ok_record_dict()
    rec["items"][0]["hashes"] = {"md5": b"\x00" * 16, "sha2-256": b"\x11" * 31}
    rec["merkle"] = [{"alg": "rfc9162-sha256", "root": b"\x00" * 32, "leaf_count": 0}]
    result = validate(_enc(rec))
    assert isinstance(result, ValidateFail)
    by_code = {issue.code: issue.path for issue in result.issues}
    assert by_code["UNSUPPORTED_HASH_ALG"] == ("items", 0, "hashes", "md5")
    assert by_code["HASH_DIGEST_LENGTH_MISMATCH"] == ("items", 0, "hashes", "sha2-256")
    assert by_code["SCHEMA_MERKLE_LEAF_COUNT_INVALID"] == ("merkle", 0, "leaf_count")


def test_cross_field_key_path_codes_attach_at_the_enc_map() -> None:
    rec = {
        "v": 1,
        "items": [
            {
                "hashes": {"md5": b"\x00" * 16},
                "enc": {
                    "scheme": 1,
                    "aead": "chacha20-poly1305-stream64k",
                    "nonce": b"\x00" * 24,
                },
            }
        ],
    }
    result = validate(_enc(rec))
    assert isinstance(result, ValidateFail)
    paths = {issue.code: issue.path for issue in result.issues}
    assert paths["ENC_NO_KEY_PATH"] == ("items", 0, "enc")
    assert paths["ENC_REQUIRES_CONTENT_HASH"] == ("items", 0, "enc")


def test_slot_codes_attach_at_the_offending_slot_field() -> None:
    rec = _ok_record_dict()
    rec["items"][0]["enc"] = {
        "scheme": 1,
        "aead": "chacha20-poly1305-stream64k",
        "kem": "x25519",
        "nonce": b"\x00" * 24,
        "slots": [
            {"epk": b"\x00" * 32, "wrap": b"\x06" * 48},
            {"epk": b"\x01" * 31, "wrap": b"\x06" * 47},
        ],
        "slots_mac": b"\x00" * 32,
    }
    result = validate(_enc(rec))
    assert isinstance(result, ValidateFail)
    paths = {issue.code: issue.path for issue in result.issues}
    assert paths["KEM_EPK_LENGTH_MISMATCH"] == ("items", 0, "enc", "slots", 1, "epk")
    assert paths["WRAP_LENGTH_MISMATCH"] == ("items", 0, "enc", "slots", 1, "wrap")


def test_sig_entry_codes_attach_at_the_entry_and_cose_key_sub_issues_below_it() -> None:
    rec = _ok_record_dict()
    rec["sigs"] = [
        {
            "cose_sign1": b"\x00" * 10,
            "cose_key": encode_canonical_cbor({1: 1, -1: 6, -2: b"\xab" * 32, -4: b"\xcd" * 32}),
        }
    ]
    result = validate(_enc(rec))
    assert isinstance(result, ValidateFail)
    leaked = [issue for issue in result.issues if issue.code == "SIG_PRIVATE_KEY_LEAKED"]
    assert [issue.path for issue in leaked] == [("sigs", 0, "cose_key")]
    # The bad cose_key forecloses the rest of the entry — no co-fired
    # MALFORMED_SIG_COSE_SIGN1 from the (also malformed) cose_sign1 bytes.
    assert _distinct_error_codes(result) == ["SIG_PRIVATE_KEY_LEAKED"]


def test_issue_order_is_segmentwise_with_registry_tie_break() -> None:
    # Two same-path issues (ENC_NO_KEY_PATH and ENC_REQUIRES_CONTENT_HASH both
    # attach at the enc map) beside issues at sibling and ancestor-extension
    # paths: a strict prefix orders before its extensions, text segments order
    # by UTF-8 bytes ("enc" < "hashes", "items" < "sigs"), and the same-path
    # pair tie-breaks by registry position (ENC_NO_KEY_PATH precedes
    # ENC_REQUIRES_CONTENT_HASH in the canonical catalogue).
    rec = {
        "v": 1,
        "items": [
            {
                "hashes": {"md5": b"\x00" * 16},
                "enc": {
                    "scheme": 1,
                    "aead": "chacha20-poly1305-stream64k",
                    "nonce": b"\x00" * 23,
                },
            }
        ],
        "sigs": [],
    }
    result = validate(_enc(rec))
    assert isinstance(result, ValidateFail)
    assert [(issue.code, issue.path) for issue in result.issues] == [
        ("ENC_NO_KEY_PATH", ("items", 0, "enc")),
        ("ENC_REQUIRES_CONTENT_HASH", ("items", 0, "enc")),
        ("NONCE_LENGTH_MISMATCH", ("items", 0, "enc", "nonce")),
        ("UNSUPPORTED_HASH_ALG", ("items", 0, "hashes", "md5")),
        ("SCHEMA_TYPE_MISMATCH", ("sigs",)),
    ]


# ---------------------------------------------------------------------------
# Decode-layer dispositions
# ---------------------------------------------------------------------------


def test_malformed_cbor_forecloses_everything() -> None:
    result = validate(b"\x5b\x00\x00")
    assert isinstance(result, ValidateFail)
    assert [issue.code for issue in result.issues] == ["MALFORMED_CBOR"]


def test_duplicate_map_keys_are_malformed_cbor_at_decode() -> None:
    # {"a": 1, "a": 2} — duplicate keys are rejected at canonical decode; the
    # taxonomy has no separate duplicate-key code.
    duplicate = bytes.fromhex("a2616101616102")
    result = validate(duplicate)
    assert _distinct_error_codes(result) == ["MALFORMED_CBOR"]


def test_unsorted_map_keys_are_malformed_cbor_at_decode() -> None:
    unsorted = bytes.fromhex("a2616201616102")
    result = validate(unsorted)
    assert _distinct_error_codes(result) == ["MALFORMED_CBOR"]


def test_non_text_map_key_rejected_at_the_containing_map() -> None:
    rec = {
        "v": 1,
        "items": [{"hashes": {"sha2-256": b"\x11" * 32, 5: b"\x22" * 32}}],
    }
    result = validate(_enc(rec))
    assert isinstance(result, ValidateFail)
    assert [(issue.code, issue.path) for issue in result.issues] == [
        ("SCHEMA_TYPE_MISMATCH", ("items", 0, "hashes")),
    ]


def test_non_text_key_in_slot_map_forecloses_the_typed_envelope() -> None:
    rec = _ok_record_dict()
    rec["items"][0]["enc"] = {
        "scheme": 1,
        "aead": "chacha20-poly1305-stream64k",
        "kem": "x25519",
        "nonce": b"\x00" * 24,
        "slots": [{5: b"\x00", "wrap": b"\x06" * 48}],
        "slots_mac": b"\x00" * 32,
    }
    result = validate(_enc(rec))
    assert isinstance(result, ValidateFail)
    assert [(issue.code, issue.path) for issue in result.issues] == [
        ("SCHEMA_TYPE_MISMATCH", ("items", 0, "enc", "slots", 0)),
    ]


# ---------------------------------------------------------------------------
# Round-trip property
# ---------------------------------------------------------------------------


def test_roundtrip_encode_validate_property() -> None:
    rec_minimal: dict[str, Any] = _ok_record_dict()
    rec_merkle: dict[str, Any] = {
        "v": 1,
        "merkle": [{"alg": "rfc9162-sha256", "root": b"\x00" * 32, "leaf_count": 4}],
    }
    rec_both: dict[str, Any] = {**rec_minimal, "merkle": rec_merkle["merkle"]}
    rec_with_supersedes: dict[str, Any] = {**rec_minimal, "supersedes": b"\xaa" * 32}
    rec_with_uris: dict[str, Any] = {
        "v": 1,
        "items": [
            {
                "hashes": {"sha2-256": b"\x11" * 32},
                "uris": ["ar://" + "a" * 43],
            }
        ],
    }
    for rec in (rec_minimal, rec_merkle, rec_both, rec_with_supersedes, rec_with_uris):
        encoded = encode_poe_record(rec)  # type: ignore[arg-type]
        result = validate(encoded)
        assert isinstance(result, ValidateOk), f"failed on {rec}: {result}"
        assert result.record == rec
        assert encode_poe_record(result.record) == encoded
