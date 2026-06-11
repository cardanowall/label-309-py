"""Plain-item content verification (non-``enc`` items).

For each item that proceeds to fetch, the verifier resolves the item's URIs
in order against the scheme-appropriate gateway chain and checks every digest
in ``item.hashes`` against the fetched bytes —
first-success-for-availability, with the integrity / attribution /
availability split:

  - bytes satisfying every committed digest      -> content check ``checked``
    (no binding check needed — the record's commitment is at least as strong
    as the storage layer's);
  - ATTRIBUTABLE bytes failing a digest          -> ``URI_INTEGRITY_MISMATCH``
    (error, record-attributable, verdict ``failed``) — one provably
    mismatching URI condemns the record even if a sibling URI matches,
    because the producer asserted at publication that every listed URI
    resolves to committed bytes;
  - UNATTRIBUTABLE bytes failing a digest        -> ``URI_PROVIDER_INTEGRITY_MISMATCH``
    (warning, provider-attributable) and the remaining sources are tried;
  - sources exhausted with nothing attributable  -> ``CONTENT_UNAVAILABLE``
    (or ``CONTENT_FETCH_LIMIT_EXCEEDED`` when an attempt aborted at the fetch
    ceiling) — network class, claim unchecked, verdict ``unverifiable``.

A hash-only item (no URIs) has nothing to fetch: its claim is reported
``not_checked`` with no availability issue — nothing failed, nothing was
expected to be fetched. Sealed (``enc``-bearing) items never enter this step;
their plaintext claim is checked by the decryption step's post-decryption
recheck.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import cast

from cardanowall._crypto.compare_ct import compare_ct
from cardanowall._crypto.hash import blake2b_256, sha256
from cardanowall.poe_standard import Item

from .fetch import BlobIterationFlags, ContentFetchContext, iterate_blob_sources
from .types import ContentCheck


def recompute_item_hashes(hashes: Mapping[str, bytes], data: bytes) -> bool:
    """True iff every entry of the item's ``hashes`` map recomputes over
    ``data``. The map must be non-empty AND every entry must name a registry
    hash this implementation computes AND every digest must match
    (constant-time comparison). An empty map, or an entry whose algorithm is
    not recognised, is never silently treated as a pass — the structural
    validator guarantees registry membership, so an unknown algorithm
    reaching here is a defensive no-certify, not a wire case."""
    entries = list(hashes.items())
    if len(entries) == 0:
        return False
    for alg, digest in entries:
        if alg == "sha2-256":
            if not compare_ct(sha256(data), digest):
                return False
        elif alg == "blake2b-256":
            if not compare_ct(blake2b_256(data), digest):
                return False
        else:
            return False
    return True


async def check_item_content(
    *,
    item: Item,
    item_index: int,
    fetch_content: bool,
    ctx: ContentFetchContext,
) -> ContentCheck:
    if not fetch_content:
        return "not_checked"

    uris = item.get("uris") or []
    if len(uris) == 0:
        return "not_checked"

    base_path: tuple[str | int, ...] = ("items", item_index)
    flags = BlobIterationFlags()
    # The wire type keys the map by the registry's Literal algorithm ids;
    # the digest helpers take the general string-keyed reading.
    hashes = cast("Mapping[str, bytes]", item["hashes"])
    async for blob in iterate_blob_sources(
        uris=uris,
        allow_fetch=True,
        base_path=base_path,
        ctx=ctx,
        flags=flags,
    ):
        if recompute_item_hashes(hashes, blob.bytes):
            return "checked"
        if blob.attributable():
            ctx.issues.add(
                "URI_INTEGRITY_MISMATCH",
                base_path,
                f'attributable bytes fetched from "{blob.uri or "out-of-band input"}" do '
                "not satisfy the item's hashes commitment",
            )
            return "mismatched"
        ctx.issues.add(
            "URI_PROVIDER_INTEGRITY_MISMATCH",
            (*base_path, "uris", blob.uri_index) if blob.uri_index is not None else base_path,
            f'bytes fetched from "{blob.uri or "unknown source"}" do not satisfy the '
            "item's hashes commitment and could not be attributed to the URI's content "
            "address; the serving provider is indicted, not the record",
        )

    if flags.limit_exceeded:
        ctx.issues.add(
            "CONTENT_FETCH_LIMIT_EXCEEDED",
            base_path,
            "a fetch for this item was aborted at the deployment's maxFetchBytes ceiling"
            + (f" ({ctx.max_fetch_bytes} bytes)" if ctx.max_fetch_bytes is not None else "")
            + "; the claim is unchecked",
        )
    else:
        ctx.issues.add(
            "CONTENT_UNAVAILABLE",
            base_path,
            "the URI list was exhausted with no attributable bytes satisfying the "
            "commitment; the claim is unchecked",
        )
    return "not_checked"


__all__ = ["check_item_content", "recompute_item_hashes"]
