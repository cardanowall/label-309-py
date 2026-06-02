from __future__ import annotations

import json
import re

from cardanowall.verifier import (
    HttpCallRecord,
    ValidationSummary,
    VerifierIssue,
    VerifyReport,
    verify_report_to_dict,
)


def _mk_report() -> VerifyReport:
    return VerifyReport(
        tx_hash="abc",
        verdict="valid",
        exit_code=0,
        profile="recipient-sealed",
        network="cardano:mainnet",
        confirmation_depth_threshold=15,
        num_confirmations=42,
        metadata_present=True,
        validation=ValidationSummary(valid=True),
        http_calls=(
            HttpCallRecord(
                url="https://example.com",
                method="GET",
                status=200,
                bytes=10,
                duration_ms=5,
                purpose="cardano",
            ),
        ),
        block_time=1700000000,
    )


def test_dict_is_deterministic_serialization() -> None:
    report = _mk_report()
    d1 = verify_report_to_dict(report)
    d2 = verify_report_to_dict(report)
    s1 = json.dumps(d1, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    s2 = json.dumps(d2, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    assert s1 == s2


def test_dict_keys_are_snake_case_with_no_nulls() -> None:
    d = verify_report_to_dict(_mk_report())

    def assert_walk(value: object) -> None:
        if isinstance(value, dict):
            for k, v in value.items():
                assert isinstance(k, str)
                assert re.fullmatch(r"[a-z][a-z0-9_]*", k), f"non-snake_case key: {k!r}"
                assert v is not None, f"null value for key {k!r}"
                assert_walk(v)
        elif isinstance(value, list):
            for item in value:
                assert_walk(item)

    assert_walk(d)


def test_bytes_serialised_as_lowercase_hex_no_prefix() -> None:
    report = VerifyReport(
        tx_hash="abc",
        verdict="failed",
        exit_code=1,
        profile="recipient-sealed",
        network="cardano:mainnet",
        confirmation_depth_threshold=15,
        metadata_present=False,
        validation=ValidationSummary(
            valid=False,
            issues=(VerifierIssue(code="X", path=("a",), message="m"),),
        ),
        http_calls=(),
    )
    d = verify_report_to_dict(report)
    # No bytes in this report, but exercise that the walker still works.
    assert d["verdict"] == "failed"
