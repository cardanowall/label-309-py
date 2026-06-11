"""Wire projection of VerifyReport.

The projection is the cross-language report contract: schema-pinned camelCase
keys (with the spec-pinned snake_case exceptions), hex-rendered bytes,
omitted None fields — and every emitted report must validate against the
published verify-report JSON Schema (mirrored at
``tests/fixtures/verify-report.schema.json``).
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any, cast

import jsonschema

from cardanowall.poe_standard import PoeRecord, encode_poe_record
from cardanowall.verifier import (
    DecryptionOutcome,
    HttpCallRecord,
    VerifierIssue,
    VerifyItemEntry,
    VerifyMerkleEntry,
    VerifyRecordSignature,
    VerifyReport,
    VerifyTxInput,
    VerifyTxOutput,
    VerifyTxSummary,
    VerifyTxWitness,
    verify_report_to_dict,
    verify_tx,
)

from ._verify_stubs import KOIOS_URL, koios_routes, make_bound_tx, route_fetch

_SCHEMA = json.loads(
    (Path(__file__).parent / "fixtures" / "verify-report.schema.json").read_text(encoding="utf-8")
)


def _mk_report() -> VerifyReport:
    return VerifyReport(
        verdict="valid",
        exit_code=0,
        issues=(
            VerifierIssue(
                code="OUT_OF_PROFILE_SKIPPED", path=("sigs",), message="m", severity="info"
            ),
        ),
        items=(
            VerifyItemEntry(
                content_check="checked",
                decryption=DecryptionOutcome(decrypted=True, plaintext_hash_ok=True),
            ),
        ),
        merkle=(VerifyMerkleEntry(content_check="not_checked"),),
        audit_trail=(
            HttpCallRecord(
                url="https://example.com",
                method="GET",
                status=200,
                bytes=10,
                duration_ms=5,
                purpose="cardano",
            ),
        ),
        network="cardano:mainnet",
        profile="recipient-sealed",
        tx_hash="ab" * 32,
        confirmation_depth=42,
        confirmation_threshold=15,
        block_time=1_700_000_000,
        block_slot=12345,
        signatures=(
            VerifyRecordSignature(
                index=0, verdict="valid", signer_pub="cd" * 32, signer_type="in-signature-kid"
            ),
        ),
        tx_witnesses=(
            VerifyTxWitness(type="vkey", vkey="ee" * 32, key_hash="ff" * 28, signature_valid=True),
        ),
        tx_summary=VerifyTxSummary(
            fee_lovelace="171617",
            input_count=1,
            output_count=1,
            outputs=(VerifyTxOutput(address="addr1xyz", lovelace="999"),),
            total_output_lovelace="999",
            script_witness_count=0,
        ),
        metadata_labels=(309,),
    )


def test_schema_pinned_key_names() -> None:
    d = verify_report_to_dict(_mk_report())
    # Schema-required keys, exact casing.
    assert set(d) >= {"verdict", "exitCode", "issues", "items", "merkle", "auditTrail"}
    # Camelized report-level extras.
    assert d["txHash"] == "ab" * 32
    assert d["confirmationDepth"] == 42
    assert d["confirmationThreshold"] == 15
    # Spec-pinned snake_case chain facts.
    assert d["block_time"] == 1_700_000_000
    assert d["block_slot"] == 12345
    # Per-claim entries.
    assert d["items"][0]["contentCheck"] == "checked"
    assert d["items"][0]["decryption"] == {"decrypted": True, "plaintextHashOk": True}
    assert d["merkle"][0] == {"contentCheck": "not_checked"}
    # Audit-trail entry shape.
    assert d["auditTrail"][0]["durationMs"] == 5
    # Signature entries camelize signerPub / signerType.
    assert d["signatures"][0]["signerPub"] == "cd" * 32
    assert d["signatures"][0]["signerType"] == "in-signature-kid"
    # Transaction-description sub-objects keep their wire-form snake_case.
    assert d["txWitnesses"][0]["key_hash"] == "ff" * 28
    assert d["txWitnesses"][0]["signature_valid"] is True
    assert d["txSummary"]["fee_lovelace"] == "171617"
    assert d["metadataLabels"] == [309]


def test_none_fields_are_omitted_and_bytes_hex() -> None:
    report = VerifyReport(
        verdict="unverifiable",
        exit_code=2,
        issues=(VerifierIssue(code="TX_NOT_FOUND", path=(), message="m"),),
        items=(),
        merkle=(),
        audit_trail=(),
        network="cardano:mainnet",
        profile="recipient-sealed",
        tx_hash="ab" * 32,
        record=cast(PoeRecord, {"v": 1, "items": [{"hashes": {"sha2-256": b"\x00\xab\xff"}}]}),
    )
    d = verify_report_to_dict(report)
    assert "confirmationDepth" not in d
    assert "block_time" not in d
    assert "signatures" not in d

    def walk(value: object) -> None:
        if isinstance(value, dict):
            for v in value.values():
                assert v is not None
                walk(v)
        elif isinstance(value, list):
            for item in value:
                walk(item)

    walk(d)
    # bytes render as lowercase hex without a 0x prefix, inside the embedded
    # record too.
    assert d["record"]["items"][0]["hashes"]["sha2-256"] == "00abff"


def test_projection_is_deterministic() -> None:
    report = _mk_report()
    s1 = json.dumps(verify_report_to_dict(report), sort_keys=True)
    s2 = json.dumps(verify_report_to_dict(report), sort_keys=True)
    assert s1 == s2


def test_hand_rolled_report_validates_against_published_schema() -> None:
    jsonschema.validate(verify_report_to_dict(_mk_report()), _SCHEMA)


def test_emitted_pipeline_report_validates_against_published_schema() -> None:
    """End-to-end: a report emitted by the live pipeline (hermetic explorer
    stub) conforms to the published verify-report schema."""
    record: PoeRecord = cast(PoeRecord, {"v": 1, "items": [{"hashes": {"sha2-256": b"\x11" * 32}}]})
    tx_hash, tx_cbor = make_bound_tx(encode_poe_record(record))
    report = asyncio.run(
        verify_tx(
            VerifyTxInput(
                tx_hash=tx_hash,
                cardano_gateway_chain=(KOIOS_URL,),
                fetch_outbound=route_fetch(koios_routes(tx_hash, tx_cbor)),
            )
        )
    )
    assert report.verdict == "valid"
    d = verify_report_to_dict(report)
    jsonschema.validate(d, _SCHEMA)
    # The verdict/exit-code projection the schema's allOf branches pin.
    assert d["exitCode"] == 0


def test_failure_report_validates_against_published_schema() -> None:
    async def unreachable(url: str, opts: Any) -> Any:
        raise RuntimeError("provider down")

    report = asyncio.run(
        verify_tx(
            VerifyTxInput(
                tx_hash="ab" * 32,
                cardano_gateway_chain=(KOIOS_URL,),
                fetch_outbound=unreachable,
            )
        )
    )
    assert report.verdict == "unverifiable"
    d = verify_report_to_dict(report)
    jsonschema.validate(d, _SCHEMA)
    assert d["exitCode"] == 2
