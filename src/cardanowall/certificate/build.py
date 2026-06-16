"""Builder for the Label 309 inclusion certificate (artifact 1, JSON form).

:func:`build_inclusion_certificate` takes the decoded Merkle leaves and a set of
targets, locates each target leaf, computes and self-verifies its inclusion
proof, and emits the typed JSON object. The output serialises directly to the
on-disk certificate; the parity twins reproduce the same value byte-for-byte.
"""

from __future__ import annotations

import hmac
from collections.abc import Sequence
from datetime import UTC, datetime

from cardanowall._crypto.merkle_sha2_256 import (
    merkle_sha2_256_inclusion_proof,
    merkle_sha2_256_root,
    merkle_sha2_256_verify_inclusion,
)

from .constants import (
    CERTIFICATE_CLAIM,
    CERTIFICATE_INDEPENDENT_TOOLS,
    CERTIFICATE_TIME_ASSERTED_BY,
    CERTIFICATE_TREE_ALG,
    CERTIFICATE_VERIFICATION_METHOD,
    INCLUSION_CERTIFICATE_FORMAT_V1,
    METADATA_LABEL_309,
)
from .types import (
    CertificateAnchor,
    CertificateMerkle,
    CertificateTarget,
    InclusionCertificateAnchor,
    InclusionCertificateItem,
    InclusionCertificateMerkle,
    InclusionCertificateV1,
)

_DIGEST_LENGTH = 32

# ``block_time`` is POSIX seconds. It must be a non-negative integer that maps to
# a calendar year in 1..=9999, so ``block_time_iso`` renders the same fixed
# ``YYYY-MM-DDTHH:MM:SS.000Z`` shape across every producer. 253402300800 is the
# POSIX second of 10000-01-01T00:00:00Z (the first instant past year 9999).
_MAX_BLOCK_TIME_EXCLUSIVE = 253_402_300_800


def _iso_from_posix(seconds: int) -> str:
    # Reproduce JavaScript's Date(...).toISOString(): always millisecond
    # precision with a trailing 'Z'. Python's datetime.isoformat() would emit
    # '+00:00' and drop zero milliseconds, so we format the fixed shape by hand
    # to keep field-value parity with the TypeScript twin.
    dt = datetime.fromtimestamp(seconds, tz=UTC)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def _now_iso() -> str:
    dt = datetime.now(tz=UTC)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def build_inclusion_certificate(
    *,
    anchor: CertificateAnchor,
    merkle: CertificateMerkle,
    leaves: Sequence[bytes],
    targets: Sequence[CertificateTarget],
    generated_at: str | None = None,
) -> InclusionCertificateV1:
    """Build an inclusion certificate over the given leaves for the given targets.

    For each target this finds the leaf's index in ``leaves``, computes its
    sibling path, re-verifies the path against ``merkle.root``, and records the
    verdict. A target not present in ``leaves`` is still emitted as an item with
    ``verified`` False and an ``error`` string — the certificate stays honest
    about misses rather than dropping them.

    ``generated_at`` is written verbatim to the certificate; supply a fixed value
    to make the emitted JSON reproducible (cross-language parity vectors pin it).
    When omitted, the current time is used. It is purely informational and never
    trusted by a verifier.

    Raises only on structural misuse of the inputs:

    - ``merkle.tree_alg`` is not ``"rfc9162-sha256"``,
    - ``merkle.root`` is not exactly 32 bytes,
    - ``merkle.tree_size`` does not equal ``len(leaves)``, or
    - ``merkle.root`` does not match the root recomputed from ``leaves``.
    """
    if merkle.tree_alg != CERTIFICATE_TREE_ALG:
        raise ValueError(
            f"build_inclusion_certificate: unsupported tree_alg {merkle.tree_alg!r} "
            f"(only {CERTIFICATE_TREE_ALG!r} is supported)"
        )
    if not isinstance(merkle.root, (bytes, bytearray)) or len(merkle.root) != _DIGEST_LENGTH:
        raise ValueError(
            f"build_inclusion_certificate: merkle.root must be a {_DIGEST_LENGTH}-byte value"
        )
    if merkle.tree_size != len(leaves):
        raise ValueError(
            f"build_inclusion_certificate: merkle.tree_size ({merkle.tree_size}) "
            f"!= len(leaves) ({len(leaves)})"
        )
    # The declared root must be the root the given leaves actually produce.
    # Building proofs against a root the leaves do not hash to would emit a
    # certificate every item of which fails verification — a structural misuse,
    # not an honest miss, so we refuse it up front. (Recomputing also validates
    # every leaf is a 32-byte digest, which the index lookup would otherwise skip.)
    recomputed_root = merkle_sha2_256_root(leaves)
    if not hmac.compare_digest(recomputed_root, bytes(merkle.root)):
        raise ValueError(
            "build_inclusion_certificate: merkle.root does not match the root "
            "recomputed from leaves"
        )
    if (
        not isinstance(anchor.block_time, int)
        or isinstance(anchor.block_time, bool)
        or anchor.block_time < 0
        or anchor.block_time >= _MAX_BLOCK_TIME_EXCLUSIVE
    ):
        raise ValueError(
            f"build_inclusion_certificate: anchor.block_time {anchor.block_time!r} out of range "
            f"[0, {_MAX_BLOCK_TIME_EXCLUSIVE}) (must map to a year in 1..=9999)"
        )

    items = [_build_item(target, leaves, bytes(merkle.root)) for target in targets]

    return {
        "format": INCLUSION_CERTIFICATE_FORMAT_V1,
        "generated_at": generated_at if generated_at is not None else _now_iso(),
        "anchor": _build_anchor(anchor),
        "merkle": _build_merkle(merkle),
        "items": items,
        "claim": CERTIFICATE_CLAIM,
        "verification": {
            "method": CERTIFICATE_VERIFICATION_METHOD,
            "independent_tools": list(CERTIFICATE_INDEPENDENT_TOOLS),
            "requires_trust_in_cardanowall": False,
            "time_asserted_by": CERTIFICATE_TIME_ASSERTED_BY,
        },
    }


def _build_item(
    target: CertificateTarget,
    leaves: Sequence[bytes],
    root: bytes,
) -> InclusionCertificateItem:
    is_well_formed = (
        isinstance(target.leaf, (bytes, bytearray)) and len(target.leaf) == _DIGEST_LENGTH
    )
    index = _find_leaf_index(leaves, bytes(target.leaf)) if is_well_formed else -1

    proof: list[str] = []
    verified = False
    error: str | None = None

    if not is_well_formed:
        error = f"leaf must be a {_DIGEST_LENGTH}-byte value"
    elif index < 0:
        error = "leaf not found in the committed leaf set"
    else:
        sibling = merkle_sha2_256_inclusion_proof(leaves, index)
        proof = [s.hex() for s in sibling]
        verified = merkle_sha2_256_verify_inclusion(
            bytes(target.leaf), index, len(leaves), sibling, root
        )

    # Construct the item in the normative key order so the serialised JSON is
    # stable across the parity twins:
    #   { leaf, leaf_alg?, index, proof, verified, label?, error? }
    item: InclusionCertificateItem = {"leaf": bytes(target.leaf).hex()}  # type: ignore[typeddict-item]
    if target.leaf_alg is not None:
        item["leaf_alg"] = target.leaf_alg
    item["index"] = index
    item["proof"] = proof
    item["verified"] = verified
    if target.label is not None:
        item["label"] = target.label
    if error is not None:
        item["error"] = error
    return item


def _find_leaf_index(leaves: Sequence[bytes], target: bytes) -> int:
    """Index of the first leaf byte-equal to ``target``, or -1.

    Equality is checked with the constant-time digest comparator on equal-length
    values, so a non-32-byte stored leaf simply does not match.
    """
    for i, leaf in enumerate(leaves):
        if (
            isinstance(leaf, (bytes, bytearray))
            and len(leaf) == len(target)
            and hmac.compare_digest(bytes(leaf), target)
        ):
            return i
    return -1


def _build_anchor(anchor: CertificateAnchor) -> InclusionCertificateAnchor:
    block_time_iso = _iso_from_posix(anchor.block_time)
    out: InclusionCertificateAnchor = {
        "chain": anchor.chain,
        "network": anchor.network,
        "tx_hash": anchor.tx_hash,
        "metadata_label": METADATA_LABEL_309,
        "block_time": anchor.block_time,
        "block_time_iso": block_time_iso,
    }
    if anchor.block_height is not None:
        out["block_height"] = anchor.block_height
    if anchor.slot is not None:
        out["slot"] = anchor.slot
    if anchor.confirmations_at_generation is not None:
        out["confirmations_at_generation"] = anchor.confirmations_at_generation
    if anchor.explorer_urls is not None:
        out["explorer_urls"] = list(anchor.explorer_urls)
    return out


def _build_merkle(merkle: CertificateMerkle) -> InclusionCertificateMerkle:
    out: InclusionCertificateMerkle = {
        "tree_alg": merkle.tree_alg,
        "root": bytes(merkle.root).hex(),
        "tree_size": merkle.tree_size,
    }
    if merkle.leaves_list_uri is not None:
        out["leaves_list_uri"] = merkle.leaves_list_uri
    if merkle.leaves_list_url is not None:
        out["leaves_list_url"] = merkle.leaves_list_url
    return out


__all__ = ["build_inclusion_certificate"]
