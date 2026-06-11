"""Verifier pipeline tests.

Hermetic end-to-end coverage of the four-state verdict machine and its
exit-code projection: the transaction-reference integrity binding, the
carriage + structural-validation gate, the confirmation-depth pending gate,
the signature step, content checking under the integrity / attribution /
availability split, and the Merkle commitment floor. Every stub transaction
satisfies both blake2b-256 bindings (see ``tests/_verify_stubs.py``) — the
pipeline reads nothing out of an unbound response.
"""

from __future__ import annotations

import asyncio
import hashlib
from typing import cast

import pytest

from cardanowall._crypto.cose_sign1 import cose_sign1_label309_build
from cardanowall._crypto.hash import sha256
from cardanowall._crypto.merkle_leaves_list import encode_leaves_list
from cardanowall._crypto.merkle_sha2_256 import merkle_sha2_256_root
from cardanowall._crypto.sig import get_public_key_ed25519
from cardanowall.poe_standard import (
    PoeRecord,
    encode_poe_record,
    encode_record_body_for_signing,
)
from cardanowall.verifier import (
    BlockInfo,
    BodyTooLargeError,
    DecryptionRecipient,
    FetchOutboundOptions,
    FetchOutboundResult,
    VerifyReport,
    VerifyTxInput,
    verify_report_to_dict,
    verify_tx,
)

from ._verify_stubs import KOIOS_URL, koios_routes, make_bound_tx, route_fetch

ARWEAVE_GW = "https://arweave.gw.test"
AR_TXID = "A" * 43


def _hash_only_record(digest: bytes = b"\x00" * 32) -> PoeRecord:
    return cast(PoeRecord, {"v": 1, "items": [{"hashes": {"sha2-256": digest}}]})


def _verify(
    record: PoeRecord | None,
    *,
    extra_routes: dict[str, FetchOutboundResult] | None = None,
    num_confirmations: int = 100,
    **input_kwargs: object,
) -> VerifyReport:
    record_body = encode_poe_record(record) if record is not None else None
    tx_hash, tx_cbor = make_bound_tx(record_body)
    routes = koios_routes(tx_hash, tx_cbor, num_confirmations=num_confirmations)
    if extra_routes:
        routes.update(extra_routes)
    return asyncio.run(
        verify_tx(
            VerifyTxInput(
                tx_hash=tx_hash,
                cardano_gateway_chain=(KOIOS_URL,),
                fetch_outbound=route_fetch(routes),
                **input_kwargs,  # type: ignore[arg-type]
            )
        )
    )


# ---- Verdict / exit-code transitions ----------------------------------------


def test_happy_path_hash_only_record_is_valid_exit_0() -> None:
    report = _verify(_hash_only_record())
    assert report.verdict == "valid"
    assert report.exit_code == 0
    assert report.record is not None
    assert report.confirmation_depth == 100
    assert report.confirmation_threshold == 15
    assert report.block_time == 1_700_000_000
    assert report.block_slot == 12_345
    # A hash-only claim has nothing to fetch: not_checked, no availability
    # issue, and the record still verifies on the on-chain commitment alone.
    assert [e.content_check for e in report.items] == ["not_checked"]
    assert not any(i.severity == "error" for i in report.issues)
    # Every outbound call of the run is on the audit trail.
    assert {c.url for c in report.audit_trail} == {
        f"{KOIOS_URL}/tx_cbor",
        f"{KOIOS_URL}/tx_info",
    }


def test_below_threshold_is_pending_exit_3_and_halts() -> None:
    report = _verify(_hash_only_record(), num_confirmations=5)
    assert report.verdict == "pending"
    assert report.exit_code == 3
    codes = {i.code for i in report.issues}
    assert "INSUFFICIENT_CONFIRMATIONS" in codes
    # The pending gate halts the pipeline: every content claim is unchecked.
    assert [e.content_check for e in report.items] == ["not_checked"]
    assert report.record is not None


def test_depth_exactly_at_threshold_is_not_pending() -> None:
    report = _verify(_hash_only_record(), num_confirmations=15)
    assert report.verdict == "valid"


def test_provider_unavailable_is_unverifiable_exit_2() -> None:
    async def unreachable(url: str, opts: FetchOutboundOptions) -> FetchOutboundResult:
        raise RuntimeError("simulated network error")

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
    assert report.exit_code == 2
    assert any(i.code == "PROVIDER_UNAVAILABLE" for i in report.issues)


def test_tx_integrity_mismatch_is_unverifiable_exit_2() -> None:
    # Serve a binding-correct transaction under the WRONG requested hash: the
    # provider actively served bytes that fail the blake2b-256 binding, which
    # is provable against the provider, never the record.
    _, tx_cbor = make_bound_tx(encode_poe_record(_hash_only_record()))
    wrong_hash = "00" * 32
    report = asyncio.run(
        verify_tx(
            VerifyTxInput(
                tx_hash=wrong_hash,
                cardano_gateway_chain=(KOIOS_URL,),
                fetch_outbound=route_fetch(koios_routes(wrong_hash, tx_cbor)),
            )
        )
    )
    assert report.verdict == "unverifiable"
    assert report.exit_code == 2
    assert any(i.code == "TX_INTEGRITY_MISMATCH" for i in report.issues)


def test_metadata_not_found_is_failed_exit_1() -> None:
    # The bound transaction carries metadata under another label only. The
    # absence of label 309 is proven by the integrity-bound transaction
    # itself — record-attributable, verdict `failed`.
    report = _verify(None)
    assert report.verdict == "failed"
    assert report.exit_code == 1
    assert any(i.code == "METADATA_NOT_FOUND" for i in report.issues)
    assert report.metadata_labels == (674,)


def test_structural_rejection_is_failed_exit_1() -> None:
    tx_hash, _ = make_bound_tx(b"\xa0")  # empty map: schema-invalid record body
    _, tx_cbor = make_bound_tx(b"\xa0")
    report = asyncio.run(
        verify_tx(
            VerifyTxInput(
                tx_hash=tx_hash,
                cardano_gateway_chain=(KOIOS_URL,),
                fetch_outbound=route_fetch(koios_routes(tx_hash, tx_cbor)),
            )
        )
    )
    assert report.verdict == "failed"
    assert report.exit_code == 1


# ---- Profile boundary --------------------------------------------------------


def _record_with_valid_sig(seed: bytes) -> PoeRecord:
    record_base = _hash_only_record()
    pub = get_public_key_ed25519(seed)
    cose = cose_sign1_label309_build(
        protected_header={1: -8, 4: pub},
        unprotected_header={},
        record_body_cbor=encode_record_body_for_signing(record_base),
        signer_secret_key=seed,
    )
    return cast(PoeRecord, {**record_base, "sigs": [{"cose_sign1": cose}]})


def test_core_profile_skips_sigs_with_info_and_stays_valid() -> None:
    report = _verify(_record_with_valid_sig(bytes([7]) * 32), profile="core")
    assert report.verdict == "valid"
    assert report.exit_code == 0
    skipped = [i for i in report.issues if i.code == "OUT_OF_PROFILE_SKIPPED"]
    assert skipped and all(i.severity == "info" for i in skipped)
    assert skipped[0].path == ("sigs",)
    # The core verifier did not verify the signatures.
    assert report.signatures is None


def test_signed_profile_verifies_sigs() -> None:
    report = _verify(_record_with_valid_sig(bytes([8]) * 32))
    assert report.verdict == "valid"
    assert report.signatures is not None
    assert report.signatures[0].verdict == "valid"
    assert report.signatures[0].signer_type == "in-signature-kid"


def test_keyring_below_recipient_sealed_profile_keeps_the_public_reading() -> None:
    # Credentials alone do not make the run a recipient verifier: a profile
    # below recipient-sealed never decrypts, so the structural validator keeps
    # the public role even when a keyring was supplied. An envelope sealed
    # under an unknown scheme then degrades to opaque (ENC_UNSUPPORTED, info)
    # instead of the strict-role hard reject, and the sealed material is
    # skipped as out-of-profile.
    record = cast(
        PoeRecord,
        {"v": 1, "items": [{"hashes": {"sha2-256": b"\x00" * 32}, "enc": {"scheme": 2}}]},
    )
    report = _verify(
        record,
        profile="signed",
        decryption=(DecryptionRecipient(recipient_secret_key=b"\x01" * 32),),
    )
    assert report.verdict == "valid"
    assert report.exit_code == 0
    enc_unsupported = [i for i in report.issues if i.code == "ENC_UNSUPPORTED"]
    assert enc_unsupported and all(i.severity == "info" for i in enc_unsupported)
    assert any(
        i.code == "OUT_OF_PROFILE_SKIPPED" and i.path == ("items", 0, "enc") for i in report.issues
    )
    # No decryption was attempted: the sealed claim is simply unchecked.
    assert [e.content_check for e in report.items] == ["not_checked"]
    assert report.items[0].decryption is None


def test_invalid_signature_fails_the_record() -> None:
    # Sign a DIFFERENT record body than the one published.
    seed = bytes([9]) * 32
    pub = get_public_key_ed25519(seed)
    other = _hash_only_record(b"\x42" * 32)
    cose = cose_sign1_label309_build(
        protected_header={1: -8, 4: pub},
        unprotected_header={},
        record_body_cbor=encode_record_body_for_signing(other),
        signer_secret_key=seed,
    )
    record = cast(PoeRecord, {**_hash_only_record(), "sigs": [{"cose_sign1": cose}]})
    report = _verify(record)
    assert report.verdict == "failed"
    assert report.exit_code == 1
    assert report.signatures is not None
    assert report.signatures[0].reason == "SIGNATURE_INVALID"
    assert any(i.code == "SIGNATURE_INVALID" and i.path == ("sigs", 0) for i in report.issues)


def test_unsupported_sig_alg_never_fails_a_hash_only_poe() -> None:
    # -19 (fully-specified Ed25519) is a registered OPT-INFO codepoint this
    # verifier does not implement: the entry surfaces as SIGNATURE_UNSUPPORTED
    # and the record's content claim still validates.
    seed = bytes([10]) * 32
    record_base = _hash_only_record()
    pub = get_public_key_ed25519(seed)
    cose = cose_sign1_label309_build(
        protected_header={1: -19, 4: pub},
        unprotected_header={},
        record_body_cbor=encode_record_body_for_signing(record_base),
        signer_secret_key=seed,
    )
    record = cast(PoeRecord, {**record_base, "sigs": [{"cose_sign1": cose}]})
    report = _verify(record)
    assert report.verdict == "valid"
    assert report.exit_code == 0
    assert report.signatures is not None
    assert report.signatures[0].verdict == "unsupported"
    assert report.signatures[0].reason == "SIGNATURE_UNSUPPORTED"
    assert not any(i.severity == "error" for i in report.issues)
    # The unsupported entry is named on the report exactly once — a registered
    # algorithm passes the structural validator silently, so only the
    # signature pass contributes the issue.
    unsupported = [i for i in report.issues if i.code == "SIGNATURE_UNSUPPORTED"]
    assert len(unsupported) == 1
    assert unsupported[0].path == ("sigs", 0)
    assert unsupported[0].severity == "info"


def test_unregistered_sig_alg_reports_signature_unsupported_exactly_once() -> None:
    # -7 (ES256) is outside the signature-algorithm registry: the structural
    # validator tags the entry AND the signature pass concludes unsupported;
    # the report still carries exactly one SIGNATURE_UNSUPPORTED at the entry.
    seed = bytes([11]) * 32
    record_base = _hash_only_record()
    pub = get_public_key_ed25519(seed)
    cose = cose_sign1_label309_build(
        protected_header={1: -7, 4: pub},
        unprotected_header={},
        record_body_cbor=encode_record_body_for_signing(record_base),
        signer_secret_key=seed,
    )
    record = cast(PoeRecord, {**record_base, "sigs": [{"cose_sign1": cose}]})
    report = _verify(record)
    assert report.verdict == "valid"
    assert report.exit_code == 0
    assert report.signatures is not None
    assert report.signatures[0].verdict == "unsupported"
    unsupported = [i for i in report.issues if i.code == "SIGNATURE_UNSUPPORTED"]
    assert len(unsupported) == 1
    assert unsupported[0].path == ("sigs", 0)
    assert unsupported[0].severity == "info"


# ---- Content checking: integrity / attribution / availability ----------------


def _ar_record(data: bytes) -> PoeRecord:
    return cast(
        PoeRecord,
        {"v": 1, "items": [{"hashes": {"sha2-256": sha256(data)}, "uris": [f"ar://{AR_TXID}"]}]},
    )


def test_fetched_bytes_satisfying_the_commitment_check_the_claim() -> None:
    data = b"the committed content"
    report = _verify(
        _ar_record(data),
        extra_routes={
            f"{ARWEAVE_GW}/{AR_TXID}": FetchOutboundResult(status=200, bytes=data, duration_ms=3)
        },
        arweave_gateway_chain=(ARWEAVE_GW,),
    )
    assert report.verdict == "valid"
    assert [e.content_check for e in report.items] == ["checked"]


def test_unattributable_mismatch_indicts_the_provider_not_the_record() -> None:
    # ar:// has no implemented binding check, so mismatching fetched bytes are
    # never attributable: URI_PROVIDER_INTEGRITY_MISMATCH (warning), then the
    # exhausted claim ends CONTENT_UNAVAILABLE (error, network class) and the
    # verdict is `unverifiable` — the record is not condemned.
    report = _verify(
        _ar_record(b"expected bytes"),
        extra_routes={
            f"{ARWEAVE_GW}/{AR_TXID}": FetchOutboundResult(
                status=200, bytes=b"garbage from a hostile gateway", duration_ms=3
            )
        },
        arweave_gateway_chain=(ARWEAVE_GW,),
    )
    assert report.verdict == "unverifiable"
    assert report.exit_code == 2
    assert [e.content_check for e in report.items] == ["not_checked"]
    provider = [i for i in report.issues if i.code == "URI_PROVIDER_INTEGRITY_MISMATCH"]
    assert provider and provider[0].severity == "warning"
    assert provider[0].path == ("items", 0, "uris", 0)
    assert any(i.code == "CONTENT_UNAVAILABLE" and i.severity == "error" for i in report.issues)


def test_attributable_mismatch_condemns_the_record() -> None:
    # A raw-codec CIDv1 binds fetched bytes to the URI itself: the gateway
    # serves bytes matching the CID but NOT the record's hashes commitment, so
    # the mismatch is attributable and the record fails.
    served = b"bytes the producer actually uploaded"
    digest = sha256(served)
    cid = _cid_v1_raw_sha256_base16(digest)
    record = cast(
        PoeRecord,
        {
            "v": 1,
            "items": [
                {
                    "hashes": {"sha2-256": sha256(b"a different commitment")},
                    "uris": [f"ipfs://{cid}"],
                }
            ],
        },
    )
    ipfs_gw = "https://ipfs.gw.test"
    report = _verify(
        record,
        extra_routes={
            f"{ipfs_gw}/ipfs/{cid}": FetchOutboundResult(status=200, bytes=served, duration_ms=3)
        },
        ipfs_gateway_chain=(ipfs_gw,),
    )
    assert report.verdict == "failed"
    assert report.exit_code == 1
    assert [e.content_check for e in report.items] == ["mismatched"]
    assert any(i.code == "URI_INTEGRITY_MISMATCH" and i.path == ("items", 0) for i in report.issues)


def test_fetch_content_false_renders_offline_with_unchecked_claims() -> None:
    report = _verify(_ar_record(b"never fetched"), fetch_content=False)
    assert report.verdict == "valid"
    assert [e.content_check for e in report.items] == ["not_checked"]
    assert not any(i.code == "CONTENT_UNAVAILABLE" for i in report.issues)


def _cid_v1_raw_sha256_base16(digest: bytes) -> str:
    # multibase 'f' (base16) || cid-version 1 || raw codec 0x55 ||
    # multihash sha2-256 (0x12) || length 32 || digest.
    return "f" + (bytes([0x01, 0x55, 0x12, 0x20]) + digest).hex()


# ---- Service independence (deny hosts) ----------------------------------------


def test_resolve_path_deny_hit_is_terminal_service_independence_violation() -> None:
    # The explorer chain points at a denied host: terminal for the run — one
    # SERVICE_INDEPENDENCE_VIOLATION at the empty path, verdict failed, and
    # the refused call still lands on the audit trail with a null status.
    record_body = encode_poe_record(_hash_only_record())
    tx_hash, tx_cbor = make_bound_tx(record_body)
    report = asyncio.run(
        verify_tx(
            VerifyTxInput(
                tx_hash=tx_hash,
                cardano_gateway_chain=(KOIOS_URL,),
                deny_hosts=("koios.test",),
                fetch_outbound=route_fetch(koios_routes(tx_hash, tx_cbor)),
            )
        )
    )
    assert report.verdict == "failed"
    assert report.exit_code == 1
    assert [(i.code, i.path) for i in report.issues] == [("SERVICE_INDEPENDENCE_VIOLATION", ())]
    assert len(report.audit_trail) == 1
    assert report.audit_trail[0].status is None


def test_content_path_deny_hit_is_per_attempt_and_the_walk_continues() -> None:
    # A denied storage gateway is per-attempt evidence at the claim's uris[]
    # path; the claim ends unchecked (CONTENT_UNAVAILABLE), and the
    # error-severity violation forces the verdict to failed.
    report = _verify(
        _ar_record(b"never reachable"),
        arweave_gateway_chain=(ARWEAVE_GW,),
        deny_hosts=("arweave.gw.test",),
    )
    assert report.verdict == "failed"
    violations = [i for i in report.issues if i.code == "SERVICE_INDEPENDENCE_VIOLATION"]
    assert [v.path for v in violations] == [("items", 0, "uris", 0)]
    assert any(i.code == "CONTENT_UNAVAILABLE" for i in report.issues)
    assert [e.content_check for e in report.items] == ["not_checked"]


# ---- The maxFetchBytes ceiling -------------------------------------------------


def test_ceiling_abort_ends_the_claim_with_one_issue() -> None:
    # Every URI of a claim addresses the same bytes, so the first ceiling
    # abort ends the claim: exactly one CONTENT_FETCH_LIMIT_EXCEEDED at the
    # claim's path, no other availability code, and the sibling URI is never
    # fetched.
    data = b"y" * 64
    record = cast(
        PoeRecord,
        {
            "v": 1,
            "items": [
                {
                    "hashes": {"sha2-256": sha256(data)},
                    "uris": [f"ar://{AR_TXID}", f"ar://{'B' * 43}"],
                }
            ],
        },
    )
    record_body = encode_poe_record(record)
    tx_hash, tx_cbor = make_bound_tx(record_body)
    routes = koios_routes(tx_hash, tx_cbor)
    storage_urls: list[str] = []
    chain_fetch = route_fetch(routes)

    async def fetch(url: str, opts: FetchOutboundOptions) -> FetchOutboundResult:
        if opts.purpose == "arweave":
            storage_urls.append(url)
            raise BodyTooLargeError(url, 16)
        return await chain_fetch(url, opts)

    report = asyncio.run(
        verify_tx(
            VerifyTxInput(
                tx_hash=tx_hash,
                cardano_gateway_chain=(KOIOS_URL,),
                arweave_gateway_chain=(ARWEAVE_GW,),
                max_fetch_bytes=16,
                fetch_outbound=fetch,
            )
        )
    )
    assert report.verdict == "unverifiable"
    availability = [
        i
        for i in report.issues
        if i.code in ("CONTENT_FETCH_LIMIT_EXCEEDED", "CONTENT_UNAVAILABLE", "URI_FETCH_FAILED")
    ]
    assert [(i.code, i.path) for i in availability] == [
        ("CONTENT_FETCH_LIMIT_EXCEEDED", ("items", 0))
    ]
    assert [e.content_check for e in report.items] == ["not_checked"]
    # The walk ended at the first ceiling abort: one storage fetch only.
    assert storage_urls == [f"{ARWEAVE_GW}/{AR_TXID}"]


# ---- Merkle list commitments --------------------------------------------------


def _merkle_record(root: bytes, leaf_count: int) -> PoeRecord:
    return cast(
        PoeRecord,
        {"v": 1, "merkle": [{"alg": "rfc9162-sha256", "root": root, "leaf_count": leaf_count}]},
    )


def test_merkle_root_recompute_matches_yields_valid() -> None:
    leaves = [hashlib.sha256(f"x{i}".encode()).digest() for i in range(5)]
    root = merkle_sha2_256_root(leaves)
    report = _verify(
        _merkle_record(root, len(leaves)),
        merkle_leaves={0: encode_leaves_list(leaves=leaves, root=root)},
    )
    assert report.verdict == "valid"
    assert [e.content_check for e in report.merkle] == ["checked"]


def test_merkle_root_mismatch_fails_the_record() -> None:
    leaves = [hashlib.sha256(f"leaf{i}".encode()).digest() for i in range(4)]
    real_root = merkle_sha2_256_root(leaves)
    wrong_root = bytes(b ^ 0xFF for b in real_root)
    report = _verify(
        _merkle_record(wrong_root, len(leaves)),
        merkle_leaves={0: encode_leaves_list(leaves=leaves, root=real_root)},
    )
    assert report.verdict == "failed"
    assert report.exit_code == 1
    assert [e.content_check for e in report.merkle] == ["mismatched"]
    assert any(i.code == "MERKLE_ROOT_MISMATCH" and i.path == ("merkle", 0) for i in report.issues)


def test_leaf_count_disagreement_fails_the_record() -> None:
    leaves = [hashlib.sha256(b"only-leaf").digest()]
    root = merkle_sha2_256_root(leaves)
    report = _verify(
        _merkle_record(root, 2),  # on-chain commitment declares 2 leaves
        merkle_leaves={0: encode_leaves_list(leaves=leaves, root=root)},
    )
    assert report.verdict == "failed"
    assert any(i.code == "SCHEMA_MERKLE_LEAF_COUNT_MISMATCH" for i in report.issues)


def test_leaf_count_and_root_both_wrong_reports_the_leaf_count_code() -> None:
    # An internally-consistent document that disagrees with the on-chain
    # commitment on BOTH the leaf count and the root: the leaf-count binding
    # is checked before the root recompute, so the count code is the one
    # reported — the same single code every implementation emits for this
    # input.
    leaves = [hashlib.sha256(b"doc-leaf").digest()]
    doc_root = merkle_sha2_256_root(leaves)
    commit_root = bytes(b ^ 0xFF for b in doc_root)
    report = _verify(
        _merkle_record(commit_root, 2),  # declares 2 leaves AND a different root
        merkle_leaves={0: encode_leaves_list(leaves=leaves, root=doc_root)},
    )
    assert report.verdict == "failed"
    assert [e.content_check for e in report.merkle] == ["mismatched"]
    merkle_codes = [
        i.code
        for i in report.issues
        if i.code in ("SCHEMA_MERKLE_LEAF_COUNT_MISMATCH", "MERKLE_ROOT_MISMATCH")
    ]
    assert merkle_codes == ["SCHEMA_MERKLE_LEAF_COUNT_MISMATCH"]


def test_commitment_floor_escalates_unavailable_leaves_on_merkle_only_record() -> None:
    # A merkle-only record whose leaves-list cannot be obtained has NO
    # verified content commitment: MERKLE_LEAVES_UNAVAILABLE escalates to
    # error (network class) and the verdict is `unverifiable`, never `valid`.
    leaves = [hashlib.sha256(b"a").digest()]
    report = _verify(_merkle_record(merkle_sha2_256_root(leaves), 1))
    assert report.verdict == "unverifiable"
    assert report.exit_code == 2
    unavailable = [i for i in report.issues if i.code == "MERKLE_LEAVES_UNAVAILABLE"]
    assert unavailable and unavailable[0].severity == "error"
    assert [e.content_check for e in report.merkle] == ["not_checked"]


def test_unavailable_leaves_stay_warning_beside_a_verified_commitment() -> None:
    # Two commitments: one verified out-of-band, one unavailable. The floor is
    # satisfied, so the unavailable one keeps the warning reading and the
    # record stays valid.
    leaves = [hashlib.sha256(b"k").digest()]
    root = merkle_sha2_256_root(leaves)
    record = cast(
        PoeRecord,
        {
            "v": 1,
            "merkle": [
                {"alg": "rfc9162-sha256", "root": root, "leaf_count": 1},
                {"alg": "rfc9162-sha256", "root": bytes(32), "leaf_count": 1},
            ],
        },
    )
    report = _verify(record, merkle_leaves={0: encode_leaves_list(leaves=leaves, root=root)})
    assert report.verdict == "valid"
    assert [e.content_check for e in report.merkle] == ["checked", "not_checked"]
    unavailable = [i for i in report.issues if i.code == "MERKLE_LEAVES_UNAVAILABLE"]
    assert unavailable and unavailable[0].severity == "warning"
    assert unavailable[0].path == ("merkle", 1)


# ---- Issue ordering -----------------------------------------------------------


def test_issues_sort_by_path_segments_then_registry_order() -> None:
    # items/0 mismatch (attributable ipfs) + merkle-only unavailability would
    # need two failures at once; instead pin the simpler invariant — run-level
    # codes (empty path) order before record-located issues.
    report = _verify(
        _ar_record(b"expected"),
        extra_routes={
            f"{ARWEAVE_GW}/{AR_TXID}": FetchOutboundResult(status=200, bytes=b"x", duration_ms=1)
        },
        arweave_gateway_chain=(ARWEAVE_GW,),
        num_confirmations=5,
    )
    # pending halts before content: only INSUFFICIENT_CONFIRMATIONS, at the
    # empty path.
    assert report.issues[0].path == ()
    paths = [i.path for i in report.issues]
    assert paths == sorted(
        paths,
        key=lambda p: tuple((0, s, "") if isinstance(s, int) else (1, 0, s) for s in p),
    )


# ---- Chain-fact integrity -----------------------------------------------------


def test_inconsistent_provider_snapshot_yields_a_report_without_confirmation_depth() -> None:
    # The only provider's tip height is below the height of the block it
    # itself reports for the transaction: its chain facts are discarded, the
    # run ends in the network-class end state, and the report carries NO
    # confirmationDepth key — a depth of 1 fabricated from a
    # self-contradicting snapshot could satisfy a threshold-1 confirmation
    # gate.
    record_body = encode_poe_record(_hash_only_record())
    tx_hash, tx_cbor = make_bound_tx(record_body)
    routes = koios_routes(
        tx_hash, tx_cbor, num_confirmations=None, block_height=1000, tip_height=999
    )
    report = asyncio.run(
        verify_tx(
            VerifyTxInput(
                tx_hash=tx_hash,
                cardano_gateway_chain=(KOIOS_URL,),
                fetch_outbound=route_fetch(routes),
            )
        )
    )
    assert report.verdict == "unverifiable"
    assert report.exit_code == 2
    assert any(i.code == "PROVIDER_UNAVAILABLE" for i in report.issues)
    assert report.confirmation_depth is None
    projection = verify_report_to_dict(report)
    assert "confirmationDepth" not in projection
    assert "block_time" not in projection


def test_consistent_tip_block_snapshot_passes_a_threshold_1_gate_with_depth_1() -> None:
    record_body = encode_poe_record(_hash_only_record())
    tx_hash, tx_cbor = make_bound_tx(record_body)
    routes = koios_routes(
        tx_hash, tx_cbor, num_confirmations=None, block_height=1000, tip_height=1000
    )
    report = asyncio.run(
        verify_tx(
            VerifyTxInput(
                tx_hash=tx_hash,
                cardano_gateway_chain=(KOIOS_URL,),
                fetch_outbound=route_fetch(routes),
                confirmation_depth_threshold=1,
            )
        )
    )
    assert report.verdict == "valid"
    assert report.confirmation_depth == 1
    assert verify_report_to_dict(report)["confirmationDepth"] == 1


def test_caller_supplied_depth_below_1_is_a_typed_input_error() -> None:
    # The record-bytes entry point takes the caller's word for the block-info
    # tuple, and a transaction in a block has depth >= 1 by definition: a
    # smaller value contradicts the tuple itself and is rejected before any
    # report is produced.
    with pytest.raises(ValueError, match="confirmation_depth must be >= 1"):
        BlockInfo(confirmation_depth=0, block_time=1_700_000_000)
