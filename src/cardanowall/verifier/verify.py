from __future__ import annotations

from typing import Any, Final

from cardanowall.poe_standard import validate

from .cbor_walker import slice_tx_components
from .decrypt import try_decryptions
from .fetch import DenyHostError, default_fetch_outbound, wrap_fetch_outbound
from .merkle import check_merkle_commitments
from .profile import out_of_profile_issues, profile_at_least
from .resolve import (
    NotACardanowallRecordError,
    extract_label_309_metadata,
    resolve_cardano_tx,
)
from .signatures import verify_record_signatures
from .tx_witnesses import decode_tx_summary, decode_tx_witnesses
from .types import (
    VERIFIER_ONLY_ERROR_CODES,
    HttpCallRecord,
    ValidationSummary,
    VerifierIssue,
    VerifyItemDecryption,
    VerifyRecordSignature,
    VerifyReport,
    VerifyTxInput,
    VerifyTxSummary,
    VerifyTxWitness,
    VerifyUriCheck,
)

# Deployment-policy threshold; the verifier surfaces this in
# `VerifyReport.confirmation_depth_threshold` so consumers can apply their
# own policy on top. v1 does not encode a normative floor.
CONFIRMATION_DEPTH_THRESHOLD_DEFAULT: Final[int] = 15


async def verify_tx(input: VerifyTxInput) -> VerifyReport:
    threshold = (
        input.confirmation_depth_threshold
        if input.confirmation_depth_threshold is not None
        else CONFIRMATION_DEPTH_THRESHOLD_DEFAULT
    )
    audit: list[HttpCallRecord] = []
    fetch_fn = wrap_fetch_outbound(
        input.fetch_outbound or default_fetch_outbound, audit, input.deny_hosts
    )

    def _base_report(**over: Any) -> VerifyReport:
        defaults: dict[str, Any] = {
            "tx_hash": input.tx_hash,
            "profile": input.profile,
            "network": input.network,
            "num_confirmations": 0,
            "confirmation_depth_threshold": threshold,
            "metadata_present": False,
            "validation": ValidationSummary(valid=False),
            "http_calls": tuple(audit),
        }
        defaults.update(over)
        # Re-snapshot audit at the time of return so any side-effect HTTP
        # calls executed before short-circuiting are preserved.
        defaults["http_calls"] = tuple(audit)
        return VerifyReport(**defaults)

    # 1. Resolve tx CBOR + confirmation depth via the Cardano gateway chain.
    try:
        resolved = await resolve_cardano_tx(input=input, fetch_fn=fetch_fn)
    except NotACardanowallRecordError as e:
        # A definitive "no metadata" response is record-attributable (the
        # tx exists but carries no label-309). Exit 1.
        return _base_report(
            verdict="failed",
            exit_code=1,
            validation=ValidationSummary(
                valid=False,
                issues=(
                    VerifierIssue(
                        path=(),
                        code=VERIFIER_ONLY_ERROR_CODES["METADATA_NOT_FOUND"],
                        message=str(e),
                    ),
                ),
            ),
        )
    except DenyHostError as e:
        # SERVICE_INDEPENDENCE_VIOLATION is integrity-class — the operator's
        # deny-policy was breached, which is a record-attributable refusal
        # rather than a transient transport failure. Exit 1.
        return _base_report(
            verdict="failed",
            exit_code=1,
            validation=ValidationSummary(
                valid=False,
                issues=(
                    VerifierIssue(
                        path=(),
                        code=VERIFIER_ONLY_ERROR_CODES["SERVICE_INDEPENDENCE_VIOLATION"],
                        message=str(e),
                    ),
                ),
            ),
        )
    except Exception as e:
        # Every other gateway failure is network-class. Exit 2 — retry against
        # a different gateway chain may succeed.
        return _base_report(
            verdict="failed",
            exit_code=2,
            validation=ValidationSummary(
                valid=False,
                issues=(
                    VerifierIssue(
                        path=(),
                        code=VERIFIER_ONLY_ERROR_CODES["PROVIDER_UNAVAILABLE"],
                        message=str(e),
                    ),
                ),
            ),
        )

    # 2. Extract label-309 metadata from the raw tx CBOR.
    try:
        metadata_bytes = extract_label_309_metadata(resolved.tx_cbor)
    except Exception as e:
        return _base_report(
            verdict="failed",
            exit_code=1,
            num_confirmations=resolved.num_confirmations,
            block_time=resolved.block_time,
            block_slot=resolved.block_slot,
            validation=ValidationSummary(
                valid=False,
                issues=(VerifierIssue(path=(), code="MALFORMED_CBOR", message=str(e)),),
            ),
        )
    if metadata_bytes is None:
        return _base_report(
            verdict="failed",
            exit_code=1,
            num_confirmations=resolved.num_confirmations,
            block_time=resolved.block_time,
            block_slot=resolved.block_slot,
            metadata_present=False,
            validation=ValidationSummary(
                valid=False,
                issues=(
                    VerifierIssue(
                        path=(),
                        code=VERIFIER_ONLY_ERROR_CODES["METADATA_NOT_FOUND"],
                        message="no label-309 metadata on this tx",
                    ),
                ),
            ),
        )

    # Transaction-level description — who authorised/paid for the anchoring,
    # distinct from record-level authorship. Decoded once from the raw tx CBOR,
    # then merged into every report shape below. This is pure description: it
    # never gates on profile and never changes the verdict. A decode failure
    # degrades to omitting the affected fields rather than failing the record.
    tx_description = _decode_tx_description(resolved.tx_cbor)

    # 3. Run the validator (pure function — never throws).
    validation = validate(metadata_bytes)
    if not validation.ok:
        issues = tuple(
            VerifierIssue(code=i.code, path=i.path, message=i.message) for i in validation.issues
        )
        return _base_report(
            verdict="failed",
            exit_code=1,
            num_confirmations=resolved.num_confirmations,
            block_time=resolved.block_time,
            block_slot=resolved.block_slot,
            metadata_present=True,
            validation=ValidationSummary(valid=False, issues=issues),
            **tx_description,
        )
    record = validation.record
    validator_warnings = tuple(
        VerifierIssue(code=w.code, path=w.path, message=w.message) for w in validation.warnings
    )
    validator_info = tuple(
        VerifierIssue(code=v.code, path=v.path, message=v.message) for v in validation.info
    )

    # 4. Confirmation depth — `INSUFFICIENT_CONFIRMATIONS` maps to verdict
    # `pending` with exit code 3 (NOT `failed`): the record is structurally
    # sound but the chain has not yet buried it deep enough to be final, so the
    # correct response is "check again later", not a permanent rejection.
    if resolved.num_confirmations < threshold:
        return _base_report(
            verdict="pending",
            exit_code=3,
            num_confirmations=resolved.num_confirmations,
            block_time=resolved.block_time,
            block_slot=resolved.block_slot,
            metadata_present=True,
            record=record,
            validation=ValidationSummary(
                valid=False,
                issues=(
                    VerifierIssue(
                        path=(),
                        code="INSUFFICIENT_CONFIRMATIONS",
                        message=f"{resolved.num_confirmations} < threshold {threshold}",
                    ),
                ),
            ),
            **tx_description,
        )

    # 5. Profile-gating — emit OUT_OF_PROFILE_SKIPPED info entries for fields
    # the configured profile does not read. A field the verifier deliberately
    # does not process is not a defect in the record, so these are info-only and
    # never invalidate the verdict.
    profile_info = out_of_profile_issues(record, input.profile)
    combined_info: list[VerifierIssue] = list(validator_info) + list(profile_info)
    combined_warnings: list[VerifierIssue] = list(validator_warnings)

    # 6. Optimistic happy-path report; mutate verdict if any check fails.
    report_dict: dict[str, Any] = {
        "tx_hash": input.tx_hash,
        "profile": input.profile,
        "network": input.network,
        "num_confirmations": resolved.num_confirmations,
        "confirmation_depth_threshold": threshold,
        "block_time": resolved.block_time,
        "block_slot": resolved.block_slot,
        "metadata_present": True,
        "validation": ValidationSummary(valid=True),
        "record": record,
        "verdict": "valid",
        "exit_code": 0,
        **tx_description,
    }
    uri_checks: list[VerifyUriCheck] = []

    # 7. Record-level signatures (signed+ profile only).
    if (
        profile_at_least(input.profile, "signed")
        and record.get("sigs")
        and len(record.get("sigs", [])) > 0
    ):
        record_signatures = await verify_record_signatures(record, input)
        report_dict["record_signatures"] = record_signatures
        # `unsupported` (SIGNATURE_UNSUPPORTED) is info severity and does NOT
        # fail a public hash-only PoE; `invalid` and `unresolved` hard-fail.
        if _record_signatures_should_fail(record_signatures):
            report_dict["verdict"] = "failed"
            report_dict["exit_code"] = 1

    # `verify_merkle` is the offline switch: it suppresses every outbound URI
    # fetch past the chain resolve step — both the sealed-item ciphertext
    # download (step 8) and the Merkle leaves-list fetch (step 9). Defaults to
    # full pipeline. (Mirrors the TS `verifyMerkle` flag.)
    allow_uri_fetch = True

    # 8. Decryption (sealed+ profile required to even read `enc`; recipient-
    # sealed required to actually decrypt). The verifier guards by profile at
    # this entry point — out-of-profile envelopes were already surfaced via
    # OUT_OF_PROFILE_SKIPPED in step 5.
    if (
        profile_at_least(input.profile, "recipient-sealed")
        and input.decryption
        and len(input.decryption) > 0
    ):
        item_decryptions = await try_decryptions(
            record, input, fetch_fn, uri_checks, allow_uri_fetch=allow_uri_fetch
        )
        report_dict["item_decryptions"] = item_decryptions
        dec_failure = _decryptions_should_fail(item_decryptions)
        if dec_failure is not None:
            report_dict["verdict"] = "failed"
            # `network` (content/ciphertext-unavailable) is exit 2 — a retry
            # against a different gateway may succeed; everything else is exit 1.
            report_dict["exit_code"] = 2 if dec_failure == "network" else 1

    # 9. Merkle list-commitments (read structurally in every profile — the
    # on-chain root is part of the core record surface). A verifier that does
    # not implement Merkle-fold reports MERKLE_UNSUPPORTED per-entry; this
    # verifier DOES implement Merkle-fold, so it recomputes each root.
    if allow_uri_fetch and record.get("merkle") and len(record.get("merkle", [])) > 0:
        merkle_checks, merkle_warnings = await check_merkle_commitments(record, input, fetch_fn)
        report_dict["merkle_checks"] = merkle_checks
        combined_warnings.extend(merkle_warnings)
        # `mismatch` is error-class (drives 'failed', exit 1). `unavailable`,
        # `format-unsupported`, and `unsupported` are warning/info-severity —
        # the on-chain root is structurally valid on its own, so they do NOT
        # escalate to verdict 'failed'.
        has_merkle_mismatch = any(m.verdict == "mismatch" for m in merkle_checks)
        if has_merkle_mismatch and report_dict["verdict"] == "valid":
            report_dict["verdict"] = "failed"
            report_dict["exit_code"] = 1

    if len(uri_checks) > 0:
        report_dict["uri_checks"] = tuple(uri_checks)

    # Finalise the validation summary — `valid=True` only if verdict stayed
    # `valid`; otherwise existing issues already point at the failure root.
    validation_summary = ValidationSummary(
        valid=report_dict["verdict"] == "valid",
        issues=() if report_dict["verdict"] == "valid" else report_dict["validation"].issues,
        warnings=tuple(combined_warnings),
        info=tuple(combined_info),
    )
    report_dict["validation"] = validation_summary
    report_dict["http_calls"] = tuple(audit)
    return VerifyReport(**report_dict)


def _record_signatures_should_fail(checks: tuple[VerifyRecordSignature, ...]) -> bool:
    # A public hash-only PoE stays valid when every signature is `unsupported`;
    # `invalid` / `unresolved` hard-fail the record (the content claim does not
    # depend on signer identity, but a present-and-broken claim does).
    return any(s.verdict in ("invalid", "unresolved") for s in checks)


def _decryptions_should_fail(
    results: tuple[VerifyItemDecryption, ...],
) -> str | None:
    """Returns None on success, 'network' for content/ciphertext-unavailable
    (exit 2), or 'integrity' for any other failure (exit 1). Matches the TS
    `decryptionsShouldFail` policy."""
    saw: str | None = None
    for d in results:
        if d.verdict == "decrypted" and d.plaintext_hash_ok is not False:
            continue
        if d.verdict in ("content-unavailable", "ciphertext-unavailable"):
            saw = "integrity" if saw == "integrity" else "network"
            continue
        saw = "integrity"
    return saw


# Decode the transaction-level description (witnesses, summary, co-published
# metadata labels) from raw tx CBOR. Purely informational, so a decode failure
# must NOT propagate into the verdict — it degrades to omitting the affected
# fields. The label-309 record is validated separately; this view only
# describes the carrying transaction.
def _decode_tx_description(tx_cbor: bytes) -> dict[str, Any]:
    # Product policy is mainnet-only; `VerifyReport.network` is pinned to
    # `cardano:mainnet`, so the bech32 address encoder always uses the mainnet
    # HRP. (The header byte's network nibble remains authoritative per address.)
    network = "mainnet"
    out: dict[str, Any] = {}
    try:
        components = slice_tx_components(tx_cbor)
    except Exception:
        return out
    out["metadata_labels"] = components.aux_metadata_labels
    witnesses: tuple[VerifyTxWitness, ...] | None
    try:
        witnesses = decode_tx_witnesses(components.witness_set, components.tx_body)
    except Exception:
        witnesses = None
    if witnesses is not None:
        out["tx_witnesses"] = witnesses
    summary: VerifyTxSummary | None
    try:
        summary = decode_tx_summary(components.tx_body, components.witness_set, network)
    except Exception:
        summary = None
    if summary is not None:
        out["tx_summary"] = summary
    return out


__all__ = ["CONFIRMATION_DEPTH_THRESHOLD_DEFAULT", "verify_tx"]
