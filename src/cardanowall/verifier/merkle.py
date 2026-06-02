from __future__ import annotations

import hmac
import json
import re
from collections.abc import Sequence
from typing import Any, Final

from cardanowall._crypto.merkle_leaves_list import (
    MerkleLeavesListError,
    decode_leaves_list,
)
from cardanowall._crypto.merkle_sha2_256 import merkle_sha2_256_root
from cardanowall.poe_standard import PoeRecord

from .fetch import DenyHostError
from .types import (
    FetchOutbound,
    FetchOutboundOptions,
    VerifierIssue,
    VerifyMerkleCheck,
    VerifyTxInput,
)

# Single registered Merkle tree algorithm in v1.
_MERKLE_TREE_ALG_RFC9162: Final[str] = "rfc9162-sha256"

# Closed PoE fetch set. Other schemes are structurally rejected by the
# validator as INVALID_URI; the verifier-side check below is defence-in-
# depth and emits URI_TARGET_FORBIDDEN for any out-of-set scheme that
# bypassed the validator.
_URI_FETCH_SET_RE: Final[re.Pattern[str]] = re.compile(r"^(ar|ipfs)://")
_AR_TXID_RE: Final[re.Pattern[str]] = re.compile(r"[A-Za-z0-9_-]{43}")

_ARWEAVE_DEFAULTS: Final[tuple[str, ...]] = (
    "https://arweave.net",
    "https://ar-io.net",
    "https://g8way.io",
)


async def check_merkle_commitments(
    record: PoeRecord,
    input: VerifyTxInput,
    fetch_fn: FetchOutbound,
) -> tuple[tuple[VerifyMerkleCheck, ...], tuple[VerifierIssue, ...]]:
    """Walk `record.merkle[]` and recompute each canonical root.

    Returns `(checks, warnings)`:
      - per-commit outcome in `checks`,
      - per-attempt URI_FETCH_FAILED warnings + MERKLE_LEAVES_INFORMATIVE_FORM
        info-severity entries in `warnings`.

    The recompute is byte-pinned via `hmac.compare_digest` (constant-time
    comparison): a successful match yields `verdict='valid'`; mismatch yields
    `verdict='mismatch', reason='MERKLE_ROOT_MISMATCH'` (error severity, drives
    `verdict='failed'`). The 4-state `verdict` mirrors the TypeScript twin.
    """
    out: list[VerifyMerkleCheck] = []
    warnings: list[VerifierIssue] = []
    merkle_arr = record.get("merkle") or []
    for i, commit in enumerate(merkle_arr):
        # Defensive: the validator already rejects an unknown alg upstream
        # (UNSUPPORTED_MERKLE_COMMIT_ALG). This guard protects a verifier
        # invoked on un-validated bytes — only the single registered tree
        # algorithm can be folded.
        if commit.get("alg") != _MERKLE_TREE_ALG_RFC9162:
            out.append(
                VerifyMerkleCheck(
                    merkle_index=i,
                    alg=str(commit.get("alg") or ""),
                    verdict="unsupported",
                    reason="MERKLE_UNSUPPORTED",
                )
            )
            continue

        # `input.merkle_leaves` is the caller-supplied out-of-band source for
        # the leaves blob. Falls back to `merkle[i].uris[]` when absent. Failure
        # to obtain the leaves blob from any source is a warning-class outcome —
        # the on-chain root commitment alone remains structurally valid — so
        # MERKLE_LEAVES_UNAVAILABLE is emitted with severity warning, NOT error.
        leaves_bytes: bytes | None = None
        if input.merkle_leaves is not None and i in input.merkle_leaves:
            leaves_bytes = input.merkle_leaves[i]
        else:
            commit_uris = commit.get("uris") or []
            if not commit_uris:
                out.append(
                    VerifyMerkleCheck(
                        merkle_index=i,
                        alg=commit["alg"],
                        verdict="unavailable",
                        reason="MERKLE_LEAVES_UNAVAILABLE",
                    )
                )
                continue
            try:
                leaves_bytes = await _fetch_leaves_uri(
                    commit_uris,
                    input.arweave_gateway_chain,
                    fetch_fn,
                    warnings,
                    ("merkle", i),
                )
            except _LeavesUnavailableError:
                out.append(
                    VerifyMerkleCheck(
                        merkle_index=i,
                        alg=commit["alg"],
                        verdict="unavailable",
                        reason="MERKLE_LEAVES_UNAVAILABLE",
                    )
                )
                continue
            except _UriTargetForbiddenError:
                out.append(
                    VerifyMerkleCheck(
                        merkle_index=i,
                        alg=commit["alg"],
                        verdict="unavailable",
                        reason="MERKLE_LEAVES_UNAVAILABLE",
                    )
                )
                continue

        # Decode the companion. CBOR is the byte-normative wire form for the
        # leaves list; on CBOR decode failure we try the informative JSON
        # projection and emit MERKLE_LEAVES_INFORMATIVE_FORM (info).
        try:
            decoded = decode_leaves_list(leaves_bytes)
            leaves = decoded["leaves"]
            file_leaf_count = decoded["leaf_count"]
            alg_id = decoded["tree_alg"]
        except MerkleLeavesListError as e:
            if e.code == "SCHEMA_MERKLE_LEAVES_FORMAT_UNSUPPORTED":
                out.append(
                    VerifyMerkleCheck(
                        merkle_index=i,
                        alg=commit["alg"],
                        verdict="format-unsupported",
                        reason="SCHEMA_MERKLE_LEAVES_FORMAT_UNSUPPORTED",
                    )
                )
                continue
            # CBOR decode failure (SCHEMA_MERKLE_LEAVES_MALFORMED) — fall back
            # to the informative JSON projection of the leaves list.
            json_decoded = _try_decode_leaves_json(leaves_bytes)
            if json_decoded is None:
                out.append(
                    VerifyMerkleCheck(
                        merkle_index=i,
                        alg=commit["alg"],
                        verdict="unavailable",
                        reason="MERKLE_LEAVES_UNAVAILABLE",
                    )
                )
                continue
            if json_decoded["format"] != "cardano-poe-merkle-leaves-v1":
                out.append(
                    VerifyMerkleCheck(
                        merkle_index=i,
                        alg=commit["alg"],
                        verdict="format-unsupported",
                        reason="SCHEMA_MERKLE_LEAVES_FORMAT_UNSUPPORTED",
                    )
                )
                continue
            leaves = json_decoded["leaves"]
            file_leaf_count = json_decoded["leaf_count"]
            alg_id = json_decoded["tree_alg"]
            warnings.append(
                VerifierIssue(
                    code="MERKLE_LEAVES_INFORMATIVE_FORM",
                    path=("merkle", i),
                    message=(
                        "fetched leaves-list returned JSON; CBOR is the "
                        "normative wire form for the leaves list"
                    ),
                )
            )

        # `commit.alg` is already pinned to rfc9162-sha256 above; an
        # inconsistent `alg_id` from the leaves file is a structural mismatch.
        if alg_id != _MERKLE_TREE_ALG_RFC9162:
            out.append(
                VerifyMerkleCheck(
                    merkle_index=i,
                    alg=commit["alg"],
                    verdict="format-unsupported",
                    reason="SCHEMA_MERKLE_LEAVES_FORMAT_UNSUPPORTED",
                )
            )
            continue

        # Leaf-count gate fires before fold so we do not spend CPU on a
        # fold that cannot bind.
        if commit["leaf_count"] != file_leaf_count:
            out.append(
                VerifyMerkleCheck(
                    merkle_index=i,
                    alg=commit["alg"],
                    verdict="mismatch",
                    reason="SCHEMA_MERKLE_LEAF_COUNT_MISMATCH",
                )
            )
            continue

        # Defence-in-depth recompute against the on-chain root. `decode_leaves_list`
        # already cross-checks against the leaves file's own declared `root`;
        # this step pins the on-chain commitment to the recomputed value.
        recomputed = merkle_sha2_256_root(leaves)
        ok = hmac.compare_digest(recomputed, commit["root"])
        out.append(
            VerifyMerkleCheck(
                merkle_index=i,
                alg=commit["alg"],
                verdict="valid" if ok else "mismatch",
                root_recomputed=recomputed,
                reason=None if ok else "MERKLE_ROOT_MISMATCH",
            )
        )

    return tuple(out), tuple(warnings)


class _LeavesUnavailableError(Exception):
    """Raised when every gateway in the chain returned a transport-class
    failure. Caller maps to MERKLE_LEAVES_UNAVAILABLE (warning), NOT
    CONTENT_UNAVAILABLE — for Merkle commitments specifically, an unfetchable
    leaves blob is warning-class because the on-chain root remains valid."""


class _UriTargetForbiddenError(Exception):
    """Raised when the URI scheme is outside the v1 fetch set `{ar://, ipfs://}`.
    Defence-in-depth for records that bypassed structural validation."""


async def _fetch_leaves_uri(
    uri_chunks_list: Sequence[Sequence[str]],
    arweave_gateways: Sequence[str] | None,
    fetch_fn: FetchOutbound,
    warnings: list[VerifierIssue],
    issue_path: tuple[str | int, ...],
) -> bytes:
    """Iterate the URIs (each is a chunked-text-array that reconstructs to one
    absolute URI), join the chunks, try `ar://` against the gateway chain, and
    surface each gateway's failure as one URI_FETCH_FAILED warning.
    """
    # Pick the first URI whose scheme is in the closed fetch set. Other
    # schemes were already rejected as INVALID_URI by the validator; the
    # check here is defence-in-depth.
    selected: str | None = None
    for chunks in uri_chunks_list:
        joined = "".join(chunks)
        if _URI_FETCH_SET_RE.match(joined):
            selected = joined
            break
    if selected is None:
        raise _UriTargetForbiddenError("no in-set URI scheme in merkle[i].uris[]")

    if selected.startswith("ar://"):
        txid = selected[5:]
        if not _AR_TXID_RE.fullmatch(txid):
            raise _LeavesUnavailableError(f"arweave_txid_invalid: {txid}")
        gateways: Sequence[str] = (
            arweave_gateways
            if arweave_gateways and len(arweave_gateways) > 0
            else _ARWEAVE_DEFAULTS
        )
        for gw in gateways:
            try:
                res = await fetch_fn(
                    f"{gw}/{txid}",
                    FetchOutboundOptions(method="GET", purpose="arweave"),
                )
                if res.status == 200:
                    return res.bytes
                warnings.append(
                    VerifierIssue(
                        code="URI_FETCH_FAILED",
                        path=issue_path,
                        message=(f"gateway {gw} returned status {res.status} for {selected}"),
                    )
                )
            except DenyHostError as e:
                # Treat deny-host as a per-attempt URI_FETCH_FAILED so the
                # chain continues to the next gateway, mirroring the TS twin.
                warnings.append(
                    VerifierIssue(
                        code="URI_FETCH_FAILED",
                        path=issue_path,
                        message=(f"gateway {gw} denied for {selected}: {e}"),
                    )
                )
            except Exception as e:
                warnings.append(
                    VerifierIssue(
                        code="URI_FETCH_FAILED",
                        path=issue_path,
                        message=(f"gateway {gw} threw for {selected}: {e}"),
                    )
                )
        raise _LeavesUnavailableError("all_arweave_gateways_failed")

    # ipfs:// — v1 does not ship a default gateway chain; caller must supply
    # `ipfs_gateway_chain` explicitly. Without one, leaves are unavailable.
    raise _LeavesUnavailableError("ipfs_gateway_not_configured")


def _try_decode_leaves_json(blob: bytes) -> dict[str, Any] | None:
    """Parse the informative JSON projection of the leaves list. Returns None
    on any parse failure so the caller can record MERKLE_LEAVES_UNAVAILABLE.
    """
    try:
        decoded = json.loads(blob.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return None
    if not isinstance(decoded, dict):
        return None
    fmt = decoded.get("format")
    leaves_raw = decoded.get("leaves")
    if not isinstance(fmt, str) or not isinstance(leaves_raw, list):
        return None
    leaves: list[bytes] = []
    for leaf in leaves_raw:
        if not isinstance(leaf, str):
            return None
        try:
            b = bytes.fromhex(leaf)
        except ValueError:
            return None
        if len(b) != 32:
            return None
        leaves.append(b)
    leaf_count_raw = decoded.get("leaf_count")
    leaf_count = (
        leaf_count_raw
        if isinstance(leaf_count_raw, int) and not isinstance(leaf_count_raw, bool)
        else len(leaves)
    )
    tree_alg = decoded.get("tree_alg")
    if not isinstance(tree_alg, str):
        tree_alg = _MERKLE_TREE_ALG_RFC9162
    return {
        "format": fmt,
        "tree_alg": tree_alg,
        "leaves": leaves,
        "leaf_count": leaf_count,
    }


__all__ = ["check_merkle_commitments"]
