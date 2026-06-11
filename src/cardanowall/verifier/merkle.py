"""Merkle list-commitment verification.

For each ``record.merkle[i]`` the verifier obtains the leaves-list document
(caller-supplied bytes, or fetched from ``merkle[i].uris[]`` under the same
first-success / attribution / fetch-ceiling semantics as item content),
validates it against the normative CBOR leaves-list container — the ONLY
accepted wire form — recomputes the RFC 9162 §2.1.1 root, and compares
byte-exact against the on-chain commitment.

The record-attributable codes (``SCHEMA_MERKLE_LEAVES_FORMAT_UNSUPPORTED`` /
``SCHEMA_MERKLE_LEAVES_MALFORMED`` / ``SCHEMA_MERKLE_LEAF_COUNT_MISMATCH`` /
``MERKLE_ROOT_MISMATCH``) hold the record to account only for an
ATTRIBUTABLE leaves-list — supplied out-of-band, or fetched with a verified
content-address binding. An unattributable fetched document failing them is
``URI_PROVIDER_INTEGRITY_MISMATCH`` (warning) and the remaining sources are
tried.

A claim left with no attributable leaves-list is
``MERKLE_LEAVES_UNAVAILABLE``, whose severity is context-dependent (the
commitment floor): warning when at least one other content commitment of the
record was verified, error (network class, verdict ``unverifiable``) when the
unavailability leaves the record with no verified content commitment. Because
the floor needs the whole-record picture, this module returns the
unavailability as a PENDING marker and the report assembly emits the issue
once every content check has run.
"""

from __future__ import annotations

import hmac
from dataclasses import dataclass
from typing import Final, Literal

from cardanowall._crypto.merkle_leaves_list import MerkleLeavesListError, decode_leaves_list
from cardanowall._crypto.merkle_sha2_256 import merkle_sha2_256_root
from cardanowall.poe_standard import MerkleCommit

from .fetch import BlobIterationFlags, ContentFetchContext, iterate_blob_sources

# v1 registers exactly one Merkle commitment algorithm; this verifier
# implements it, so MERKLE_UNSUPPORTED never fires here (an unregistered
# identifier is already rejected by the structural validator with
# UNSUPPORTED_MERKLE_COMMIT_ALG).
_MERKLE_ALG: Final[str] = "rfc9162-sha256"

ContentCheckOutcome = Literal["checked", "mismatched", "not_checked"]


@dataclass(frozen=True, kw_only=True)
class MerkleUnavailableMarker:
    path: tuple[str | int, ...]
    limit_exceeded: bool


@dataclass(frozen=True, kw_only=True)
class MerkleCommitOutcome:
    content_check: ContentCheckOutcome
    # Set when the claim ended unchecked because no attributable leaves-list
    # could be obtained; the report assembly emits MERKLE_LEAVES_UNAVAILABLE
    # (or CONTENT_FETCH_LIMIT_EXCEEDED) with floor-resolved severity.
    unavailable: MerkleUnavailableMarker | None = None


@dataclass(frozen=True, kw_only=True)
class _LeavesValidationFail:
    code: str
    message: str


# Validate one acquired leaves-list document against the on-chain commitment:
# container grammar, document-internal consistency, RFC 9162 root recompute,
# and the leaf-count binding.
def _validate_leaves_document(blob: bytes, commit: MerkleCommit) -> _LeavesValidationFail | None:
    try:
        decoded = decode_leaves_list(blob)
    except MerkleLeavesListError as e:
        code = (
            e.code
            if e.code
            in (
                "SCHEMA_MERKLE_LEAVES_FORMAT_UNSUPPORTED",
                "SCHEMA_MERKLE_LEAF_COUNT_MISMATCH",
                "MERKLE_ROOT_MISMATCH",
            )
            else "SCHEMA_MERKLE_LEAVES_MALFORMED"
        )
        return _LeavesValidationFail(code=code, message=str(e))
    except Exception as e:
        return _LeavesValidationFail(code="SCHEMA_MERKLE_LEAVES_MALFORMED", message=str(e))
    # The leaf-count binding is checked BEFORE the root recompute: a document
    # of the wrong size is rejected on the cheap structural disagreement
    # without folding its leaves, and a document wrong on both reports the
    # leaf-count code.
    if decoded["leaf_count"] != commit["leaf_count"]:
        return _LeavesValidationFail(
            code="SCHEMA_MERKLE_LEAF_COUNT_MISMATCH",
            message=(
                f"leaves-list carries {decoded['leaf_count']} leaves but the on-chain "
                f"commitment declares {commit['leaf_count']}"
            ),
        )
    recomputed = merkle_sha2_256_root(decoded["leaves"])
    if not hmac.compare_digest(recomputed, commit["root"]):
        return _LeavesValidationFail(
            code="MERKLE_ROOT_MISMATCH",
            message=(
                "the RFC 9162 root recomputed from the leaves-list does not equal the on-chain root"
            ),
        )
    return None


async def check_merkle_commit(
    *,
    commit: MerkleCommit,
    commit_index: int,
    ctx: ContentFetchContext,
    fetch_content: bool,
    out_of_band: bytes | None = None,
) -> MerkleCommitOutcome:
    base_path: tuple[str | int, ...] = ("merkle", commit_index)

    if commit.get("alg") != _MERKLE_ALG:
        # Defence-in-depth: the structural validator already rejected unknown
        # identifiers, so an unimplemented-but-registered algorithm cannot
        # occur in v1 (the registry has exactly one member).
        ctx.issues.add(
            "UNSUPPORTED_MERKLE_COMMIT_ALG",
            (*base_path, "alg"),
            f'merkle commitment algorithm "{commit.get("alg")}" is not implemented',
        )
        return MerkleCommitOutcome(content_check="not_checked")

    uris = commit.get("uris") or []
    # Offline with no out-of-band document: the claim is simply not checked —
    # the fetch was suppressed by policy, not unavailable.
    if not fetch_content and out_of_band is None:
        return MerkleCommitOutcome(content_check="not_checked")

    flags = BlobIterationFlags()
    async for blob in iterate_blob_sources(
        out_of_band=out_of_band,
        uris=uris,
        allow_fetch=fetch_content,
        base_path=base_path,
        ctx=ctx,
        flags=flags,
    ):
        failure = _validate_leaves_document(blob.bytes, commit)
        if failure is None:
            return MerkleCommitOutcome(content_check="checked")
        if blob.attributable():
            ctx.issues.add(failure.code, base_path, failure.message)
            return MerkleCommitOutcome(content_check="mismatched")
        ctx.issues.add(
            "URI_PROVIDER_INTEGRITY_MISMATCH",
            (*base_path, "uris", blob.uri_index) if blob.uri_index is not None else base_path,
            f'leaves-list bytes fetched from "{blob.uri or "unknown source"}" fail '
            f"validation ({failure.code}) and could not be attributed to the URI's "
            "content address; the serving provider is indicted, not the record",
        )

    return MerkleCommitOutcome(
        content_check="not_checked",
        unavailable=MerkleUnavailableMarker(path=base_path, limit_exceeded=flags.limit_exceeded),
    )


__all__ = ["MerkleCommitOutcome", "MerkleUnavailableMarker", "check_merkle_commit"]
