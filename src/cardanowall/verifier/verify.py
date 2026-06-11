"""The Label 309 standalone verifier — the public / recipient pipeline.

``verify_tx`` executes, in order; a step whose outcome forecloses the rest
short-circuits the pipeline:

  1.  Resolve the transaction via the explorer chain (raw tx CBOR, never a
      JSON projection). Negative outcomes: TX_NOT_FOUND / PROVIDER_UNAVAILABLE
      → ``unverifiable``.
  2.  Bind the fetched bytes to the transaction reference — blake2b-256 over
      the body vs the requested hash, blake2b-256 over the auxiliary data vs
      the body's ``auxiliary_data_hash``; no surviving response →
      TX_INTEGRITY_MISMATCH, ``unverifiable`` (provider-provable, never
      record-attributable).
  3.  Unwrap the auxiliary data (all three Conway envelope forms, dispatch on
      type/tag only) and reassemble the label-309 chunk array. No label-309
      entry → METADATA_NOT_FOUND, ``failed`` (the absence is proven by the
      integrity-bound transaction itself).
  4.  Structurally validate (``validate``), with the validator role matching
      the verifier mode: a run that will actually decrypt — decryption
      credentials held AND the profile admits sealed decryption — is a
      RECIPIENT verifier (``recipient_or_strict``); otherwise ``public``.
  5.  Check confirmation depth — below threshold → INSUFFICIENT_CONFIRMATIONS,
      verdict ``pending``, pipeline halts (results computed against a
      transaction that may yet be orphaned must not be presented as final).
  6.  Verify record signatures (strict Ed25519, detached payload, verbatim
      protected bytes, wallet-address network binding).
  7.  Fetch and hash-check plain-item content and Merkle leaves-lists
      (first-success-for-availability; integrity vs attribution vs
      availability split; suppressed by ``fetch_content=False``).
  8.  Decrypt ``enc``-bearing items with the keyring (recipient verifier),
      including the post-decryption plaintext-hash recheck.
  9.  (``supersedes`` is an advisory pointer; this implementation performs no
      existence hop — the check is a MAY.)
  10. Emit the report: verdict ∈ valid | pending | unverifiable | failed,
      exit codes 0 | 3 | 2 | 1 respectively, issues sorted by path then
      registry order, one per-claim entry per item / commitment, and the
      complete audit trail of every outbound call.

``verify_record_bytes`` runs the same pipeline from step 4 onward over
caller-supplied record-body bytes plus an explorer-asserted block-info tuple
— the path a server-rendered viewer uses to display on-chain data without a
render-time chain fetch.
"""

from __future__ import annotations

import contextlib
from typing import Any, Final

from cardanowall.poe_standard import (
    ERROR_CODES,
    Item,
    PoeRecord,
    ValidationIssue,
    ValidatorRole,
    error_code_registry_index,
    validate,
)

from .carriage import Label309ReassemblyOk, reassemble_label_309_value
from .cbor_walker import (
    MalformedTxCborError,
    slice_tx_components,
    unwrap_auxiliary_data,
)
from .decrypt import decrypt_item
from .fetch import (
    ARWEAVE_GATEWAY_DEFAULTS,
    ContentFetchContext,
    default_fetch_outbound,
    wrap_fetch_outbound,
)
from .items import check_item_content
from .merkle import MerkleCommitOutcome, check_merkle_commit
from .profile import out_of_profile_issues, profile_at_least
from .resolve import ResolveFailure, resolve_cardano_tx
from .signatures import verify_record_signatures
from .tx_witnesses import decode_tx_summary, decode_tx_witnesses
from .types import (
    NETWORK_CLASS_CODES,
    BlockInfo,
    FetchOutbound,
    HttpCallRecord,
    IssueSink,
    Verdict,
    VerifierIssue,
    VerifyItemEntry,
    VerifyMerkleEntry,
    VerifyRecordInput,
    VerifyRecordSignature,
    VerifyReport,
    VerifyTxInput,
    exit_code_for_verdict,
)

# Deployment-policy confirmation-depth threshold (RECOMMENDED >= 15 blocks,
# raised for high-value notarisation). Surfaced in the report alongside the
# resolved depth so consumers can apply their own policy on top.
CONFIRMATION_DEPTH_THRESHOLD_DEFAULT: Final[int] = 15


def _verdict_from_issues(issues: list[VerifierIssue]) -> Verdict:
    """``failed`` is reserved for record-attributable outcomes; an
    error-severity issue set drawn entirely from the network / policy /
    provider-integrity class maps to ``unverifiable``. Integrity outcomes are
    untouched by availability: one record-attributable error produces
    ``failed`` regardless of what else was or was not available."""
    saw_network_error = False
    for issue in issues:
        if issue.severity != "error":
            continue
        if issue.code not in NETWORK_CLASS_CODES:
            return "failed"
        saw_network_error = True
    return "unverifiable" if saw_network_error else "valid"


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
    sink = IssueSink()

    def _report(verdict: Verdict, **over: Any) -> VerifyReport:
        return _assemble_report(
            verdict=verdict,
            sink=sink,
            audit=audit,
            input=input,
            threshold=threshold,
            tx_hash=input.tx_hash,
            **over,
        )

    # Steps 1 + 2 — resolve via the explorer chain with the integrity binding
    # applied per response (nothing is read out of a response that fails it).
    resolved = await resolve_cardano_tx(input=input, fetch_fn=fetch_fn)
    if isinstance(resolved, ResolveFailure):
        sink.add(resolved.code, (), resolved.message)
        return _report(_verdict_from_issues(sink.issues))

    chain_facts: dict[str, Any] = {
        "confirmation_depth": resolved.confirmation_depth,
        "block_time": resolved.block_time,
        "block_slot": resolved.block_slot,
    }
    tx_description = _decode_tx_description(resolved.tx_cbor, input)

    # Step 3 — unwrap the bound auxiliary data and reassemble the record body.
    try:
        label_309 = (
            None
            if resolved.components.auxiliary_data is None
            else unwrap_auxiliary_data(resolved.components.auxiliary_data).label_309
        )
    except MalformedTxCborError as e:
        sink.add("MALFORMED_CBOR", (), str(e))
        return _report("failed", **chain_facts, **tx_description)
    if label_309 is None:
        sink.add(
            "METADATA_NOT_FOUND",
            (),
            "the integrity-bound transaction carries no metadata under label 309",
        )
        return _report("failed", **chain_facts, **tx_description)
    reassembly = reassemble_label_309_value(label_309)
    if not isinstance(reassembly, Label309ReassemblyOk):
        sink.issues.append(reassembly.issue)
        return _report("failed", **chain_facts, **tx_description)

    # Steps 4-10 are shared with the record-bytes entry point.
    return await _verify_from_record_bytes(
        record_body=reassembly.body,
        block_info=BlockInfo(
            confirmation_depth=resolved.confirmation_depth,
            block_time=resolved.block_time,
            block_slot=resolved.block_slot,
        ),
        input=input,
        fetch_fn=fetch_fn,
        sink=sink,
        audit=audit,
        threshold=threshold,
        tx_hash=input.tx_hash,
        tx_description=tx_description,
    )


async def verify_record_bytes(
    record_body: bytes,
    block_info: BlockInfo,
    input: VerifyRecordInput | None = None,
    *,
    tx_hash: str | None = None,
    tx_cbor: bytes | None = None,
) -> VerifyReport:
    """Run the pipeline from the structural-validator step onward over
    caller-supplied record-body bytes plus an explorer-asserted block-info
    tuple. The caller is responsible for having reassembled the label-309
    chunk array (``reassemble_label_309_value``) and for the confidence that
    the bytes came from the label-309 metadata of a real Cardano transaction.
    When ``tx_cbor`` is supplied, the report also carries the
    transaction-level description (``tx_witnesses`` / ``tx_summary`` /
    ``metadata_labels``); the label-309 record is always taken from
    ``record_body``."""
    opts = input if input is not None else VerifyRecordInput()
    threshold = (
        opts.confirmation_depth_threshold
        if opts.confirmation_depth_threshold is not None
        else CONFIRMATION_DEPTH_THRESHOLD_DEFAULT
    )
    audit: list[HttpCallRecord] = []
    fetch_fn = wrap_fetch_outbound(
        opts.fetch_outbound or default_fetch_outbound, audit, opts.deny_hosts
    )
    sink = IssueSink()
    return await _verify_from_record_bytes(
        record_body=record_body,
        block_info=block_info,
        input=opts,
        fetch_fn=fetch_fn,
        sink=sink,
        audit=audit,
        threshold=threshold,
        tx_hash=tx_hash,
        tx_description=_decode_tx_description(tx_cbor, opts) if tx_cbor is not None else {},
    )


async def _verify_from_record_bytes(
    *,
    record_body: bytes,
    block_info: BlockInfo,
    input: VerifyRecordInput,
    fetch_fn: FetchOutbound,
    sink: IssueSink,
    audit: list[HttpCallRecord],
    threshold: int,
    tx_hash: str | None,
    tx_description: dict[str, Any],
) -> VerifyReport:
    chain_facts: dict[str, Any] = {
        "confirmation_depth": block_info.confirmation_depth,
        "block_time": block_info.block_time,
        "block_slot": block_info.block_slot,
    }

    def _report(verdict: Verdict, **over: Any) -> VerifyReport:
        merged: dict[str, Any] = {**chain_facts, **tx_description, **over}
        return _assemble_report(
            verdict=verdict,
            sink=sink,
            audit=audit,
            input=input,
            threshold=threshold,
            tx_hash=tx_hash,
            **merged,
        )

    # Step 4 — structural validation, with the role matching the verifier
    # mode: a run that will actually decrypt (credentials held AND the
    # profile implements decryption) is a recipient verifier, whose validator
    # hard-rejects envelopes it cannot fully validate (ENC_UNSUPPORTED
    # escalates to error) — a sealed delivery is never processed under a
    # half-validated envelope. A lower profile never decrypts, so it keeps
    # the public reading even when credentials were supplied.
    keyring = input.decryption or ()
    will_decrypt = len(keyring) > 0 and profile_at_least(input.profile, "recipient-sealed")
    role: ValidatorRole = "recipient_or_strict" if will_decrypt else "public"
    validation = validate(record_body, role=role)
    if not validation.ok:
        sink.issues.extend(_from_validator(validation.issues))
        return _report("failed")
    record = validation.record
    sink.issues.extend(_from_validator(validation.warnings))
    sink.issues.extend(_from_validator(validation.info))

    record_items: list[Item] = list(record.get("items") or [])
    record_merkle = list(record.get("merkle") or [])

    # Step 5 — confirmation depth. Below threshold the record is well-formed
    # but not final: verdict `pending` (exit 3, never `failed`), and the
    # signature / content / decrypt steps are skipped so nothing computed
    # against a possibly-orphaned transaction can be presented as final.
    if block_info.confirmation_depth < threshold:
        sink.add(
            "INSUFFICIENT_CONFIRMATIONS",
            (),
            f"confirmation depth {block_info.confirmation_depth} is below the threshold "
            f"{threshold}; signature, content, and decryption steps did not run",
        )
        return _report(
            "pending",
            record=record,
            items=tuple(VerifyItemEntry(content_check="not_checked") for _ in record_items),
            merkle=tuple(VerifyMerkleEntry(content_check="not_checked") for _ in record_merkle),
        )

    # Profile gating: fields above the active profile are skipped with
    # OUT_OF_PROFILE_SKIPPED (info) — the record is never invalid solely
    # because this verifier does not implement a profile extension.
    sink.issues.extend(out_of_profile_issues(record, input.profile))

    # Step 6 — record-level signatures (signed+ profile). Optional by design:
    # a public hash-only PoE remains valid when every signature is
    # unsupported.
    signatures: tuple[VerifyRecordSignature, ...] | None = None
    if profile_at_least(input.profile, "signed") and record.get("sigs"):
        signatures = verify_record_signatures(record, network=input.network, sink=sink)

    # Steps 7 + 8 — content checks and sealed decryption.
    ctx = ContentFetchContext(
        fetch_fn=fetch_fn,
        arweave_gateways=(
            input.arweave_gateway_chain if input.arweave_gateway_chain else ARWEAVE_GATEWAY_DEFAULTS
        ),
        ipfs_gateways=input.ipfs_gateway_chain or (),
        max_fetch_bytes=input.max_fetch_bytes,
        issues=sink,
    )
    item_entries: list[VerifyItemEntry] = []
    for idx, item in enumerate(record_items):
        if item.get("enc") is not None:
            if will_decrypt:
                result = await decrypt_item(
                    item=item,
                    item_index=idx,
                    credentials=keyring,
                    ctx=ctx,
                    fetch_content=input.fetch_content,
                    out_of_band_ciphertext=(
                        input.ciphertext_bytes.get(idx)
                        if input.ciphertext_bytes is not None
                        else None
                    ),
                )
                item_entries.append(
                    VerifyItemEntry(
                        content_check=result.content_check, decryption=result.decryption
                    )
                )
            else:
                # Public verifier (or a profile below recipient-sealed): a
                # sealed item's plaintext claim cannot be checked without
                # decrypting, and the URIs hold ciphertext, not the committed
                # plaintext.
                item_entries.append(VerifyItemEntry(content_check="not_checked"))
            continue
        content_check = await check_item_content(
            item=item, item_index=idx, fetch_content=input.fetch_content, ctx=ctx
        )
        item_entries.append(VerifyItemEntry(content_check=content_check))

    merkle_outcomes: list[MerkleCommitOutcome] = []
    for idx, commit in enumerate(record_merkle):
        merkle_outcomes.append(
            await check_merkle_commit(
                commit=commit,
                commit_index=idx,
                ctx=ctx,
                fetch_content=input.fetch_content,
                out_of_band=(
                    input.merkle_leaves.get(idx) if input.merkle_leaves is not None else None
                ),
            )
        )

    # The commitment floor resolves the dual severity of
    # MERKLE_LEAVES_UNAVAILABLE: warning when at least one other content
    # commitment of the record was verified in this run, error (network
    # class, verdict `unverifiable`) when the unavailability leaves the
    # record with no verified content commitment.
    any_commitment_verified = any(e.content_check == "checked" for e in item_entries) or any(
        o.content_check == "checked" for o in merkle_outcomes
    )
    for outcome in merkle_outcomes:
        if outcome.unavailable is None:
            continue
        if outcome.unavailable.limit_exceeded:
            sink.add(
                "CONTENT_FETCH_LIMIT_EXCEEDED",
                outcome.unavailable.path,
                "a leaves-list fetch was aborted at the maxFetchBytes ceiling; the "
                "commitment is unchecked",
            )
            continue
        sink.add(
            "MERKLE_LEAVES_UNAVAILABLE",
            outcome.unavailable.path,
            "no attributable leaves-list could be obtained; another content commitment "
            "of the record was verified"
            if any_commitment_verified
            else "no attributable leaves-list could be obtained and no content "
            "commitment of the record was verified",
            None if any_commitment_verified else "error",
        )

    # Step 10 — verdict + report.
    return _report(
        _verdict_from_issues(sink.issues),
        record=record,
        signatures=signatures,
        items=tuple(item_entries),
        merkle=tuple(VerifyMerkleEntry(content_check=o.content_check) for o in merkle_outcomes),
    )


def _from_validator(issues: tuple[ValidationIssue, ...]) -> list[VerifierIssue]:
    return [
        VerifierIssue(code=i.code, path=i.path, message=i.message, severity=i.severity)
        for i in issues
    ]


def _assemble_report(
    *,
    verdict: Verdict,
    sink: IssueSink,
    audit: list[HttpCallRecord],
    input: VerifyRecordInput,
    threshold: int,
    tx_hash: str | None,
    record: PoeRecord | None = None,
    signatures: tuple[VerifyRecordSignature, ...] | None = None,
    items: tuple[VerifyItemEntry, ...] = (),
    merkle: tuple[VerifyMerkleEntry, ...] = (),
    confirmation_depth: int | None = None,
    block_time: int | None = None,
    block_slot: int | None = None,
    tx_witnesses: Any = None,
    tx_summary: Any = None,
    metadata_labels: tuple[int, ...] | None = None,
) -> VerifyReport:
    return VerifyReport(
        verdict=verdict,
        exit_code=exit_code_for_verdict(verdict),
        issues=tuple(_sort_issues(sink.issues)),
        items=items,
        merkle=merkle,
        audit_trail=tuple(audit),
        network=input.network,
        profile=input.profile,
        tx_hash=tx_hash,
        confirmation_depth=confirmation_depth,
        confirmation_threshold=threshold,
        block_time=block_time,
        block_slot=block_slot,
        record=record,
        signatures=signatures if signatures else None,
        tx_witnesses=tx_witnesses,
        tx_summary=tx_summary,
        metadata_labels=metadata_labels,
    )


# -----------------------------------------------------------------------------
# Issue ordering — the normative sort shared with the structural validator, so
# two implementations replaying the same run emit byte-identical issue order.
# -----------------------------------------------------------------------------


def _segment_key(seg: str | int) -> tuple[int, int, bytes]:
    # Integer segments order before text segments; two integers compare
    # numerically; two text segments compare by the bytewise order of their
    # UTF-8 encodings. No locale-dependent collation.
    if isinstance(seg, int):
        return (0, seg, b"")
    return (1, 0, seg.encode("utf-8"))


def _registry_index(code: str) -> int:
    try:
        return error_code_registry_index(code)  # type: ignore[arg-type]
    except Exception:
        return len(ERROR_CODES)


def _sort_issues(issues: list[VerifierIssue]) -> list[VerifierIssue]:
    # Segment-wise path sort (a path that is a strict prefix of another orders
    # before it — tuple comparison gives this directly); identical paths
    # tie-break by error-code-registry order.
    return sorted(
        issues,
        key=lambda i: (tuple(_segment_key(s) for s in i.path), _registry_index(i.code)),
    )


# -----------------------------------------------------------------------------
# Transaction-level description
# -----------------------------------------------------------------------------
#
# Decode the witnesses / summary / co-published-labels view from raw tx CBOR.
# Purely informational: a decode failure degrades to omitting the affected
# fields and never propagates into the verdict. The label-309 record is
# validated separately from the record-body bytes; this view only describes
# the carrying transaction.


def _decode_tx_description(tx_cbor: bytes | None, input: VerifyRecordInput) -> dict[str, Any]:
    out: dict[str, Any] = {}
    if tx_cbor is None:
        return out
    network = "mainnet" if input.network == "cardano:mainnet" else "preprod"
    try:
        components = slice_tx_components(tx_cbor)
    except Exception:
        return out
    if components.auxiliary_data is not None:
        with contextlib.suppress(Exception):  # leave metadata_labels unset on failure
            out["metadata_labels"] = unwrap_auxiliary_data(
                components.auxiliary_data
            ).metadata_labels
    else:
        out["metadata_labels"] = ()
    with contextlib.suppress(Exception):  # leave tx_witnesses unset on failure
        out["tx_witnesses"] = decode_tx_witnesses(components.witness_set, components.tx_body)
    with contextlib.suppress(Exception):  # leave tx_summary unset on failure
        out["tx_summary"] = decode_tx_summary(components.tx_body, components.witness_set, network)
    return out


__all__ = ["CONFIRMATION_DEPTH_THRESHOLD_DEFAULT", "verify_record_bytes", "verify_tx"]
