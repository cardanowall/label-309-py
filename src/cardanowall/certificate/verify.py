"""Pure re-verification of a Label 309 inclusion certificate.

:func:`verify_inclusion_certificate` recomputes each item's Merkle proof from the
certificate alone — no Arweave fetch, no chain query — and reports a verdict. It
proves the *inclusion* claim (each leaf is at its stated index of a tree with the
embedded root). It does NOT and cannot prove the *anchoring* claim: that
``merkle.root`` actually appears in the Label 309 record of ``anchor.tx_hash`` on
chain. The anchor is echoed as ``anchor_claim`` for the caller to confirm on any
public Cardano explorer as a separate step.

This function never raises on attacker-controlled input: a forged or malformed
certificate (bad format, tree algorithm, anchor fixed fields, or an out-of-range
tree_size / index) is reported as ``ok`` False with a clear error, not an
exception.
"""

from __future__ import annotations

import re

from cardanowall._crypto.merkle_sha2_256 import merkle_sha2_256_verify_inclusion

from .constants import (
    CERTIFICATE_TREE_ALG,
    INCLUSION_CERTIFICATE_FORMAT_V1,
    METADATA_LABEL_309,
)
from .types import (
    CertificateAnchor,
    InclusionCertificateItem,
    InclusionCertificateItemVerdict,
    InclusionCertificateV1,
    InclusionCertificateVerifyResult,
)

# The verify primitive is only exact while tree_size stays within the 32-bit
# fold domain (the on-chain commitment caps leaf_count at the same value). A
# certificate claiming a larger tree_size is forged; we reject it here so the
# primitive's range guard is never reached from this path.
_MAX_TREE_SIZE = 0xFFFFFFFF


def _is_int(value: object) -> bool:
    # bool is an int subclass; the format's integers are plain ints.
    return isinstance(value, int) and not isinstance(value, bool)


def verify_inclusion_certificate(
    cert: InclusionCertificateV1,
) -> InclusionCertificateVerifyResult:
    """Re-verify an inclusion certificate purely from its own bytes.

    For every item this recomputes the Merkle inclusion fold and records the
    verdict. ``ok`` is true only when every item verifies. The stored
    ``verified`` flag in the certificate is never trusted — this recomputes it.

    The certificate as a whole is rejected (returns ``ok`` False with an
    ``error``, never raises) when its ``format``, ``merkle.tree_alg``, anchor
    fixed fields, or ``merkle.tree_size`` are unsupported / out of range.

    The returned ``anchor_claim`` echoes the certificate's *claimed* anchor
    verbatim. It must be confirmed on a public Cardano explorer; this function
    does no chain I/O and asserts nothing about the anchor beyond its structural
    shape.
    """
    anchor_claim = _anchor_claim_of(cert)

    if cert.get("format") != INCLUSION_CERTIFICATE_FORMAT_V1:
        return _reject(anchor_claim, f"unsupported certificate format {cert.get('format')!r}")

    merkle = cert.get("merkle") or {}
    if merkle.get("tree_alg") != CERTIFICATE_TREE_ALG:
        return _reject(anchor_claim, f"unsupported tree_alg {merkle.get('tree_alg')!r}")

    # The anchor's fixed fields are part of the format, not explorer-asserted
    # facts: a certificate that does not name Cardano / metadata label 309 is not
    # a Label 309 inclusion certificate.
    anchor = cert.get("anchor")
    if anchor is None:
        return _reject(anchor_claim, "missing anchor")
    if anchor.get("chain") != "cardano":
        return _reject(anchor_claim, f"unsupported anchor.chain {anchor.get('chain')!r}")
    if anchor.get("metadata_label") != METADATA_LABEL_309:
        return _reject(
            anchor_claim,
            f"unsupported anchor.metadata_label {anchor.get('metadata_label')!r}",
        )

    tree_size = merkle.get("tree_size")
    if not _is_int(tree_size) or tree_size < 1 or tree_size > _MAX_TREE_SIZE:
        return _reject(anchor_claim, f"merkle.tree_size {tree_size!r} out of range")

    root_bytes, root_error = _decode_hex(merkle.get("root"))
    if root_error is not None:
        return _reject(anchor_claim, f"malformed merkle.root: {root_error}")

    items = tuple(_verify_item(item, tree_size, root_bytes) for item in cert.get("items", []))
    ok = len(items) > 0 and all(v.verified for v in items)

    return InclusionCertificateVerifyResult(ok=ok, items=items, anchor_claim=anchor_claim)


def _reject(anchor_claim: CertificateAnchor, error: str) -> InclusionCertificateVerifyResult:
    return InclusionCertificateVerifyResult(
        ok=False, items=(), anchor_claim=anchor_claim, error=error
    )


def _verify_item(
    item: InclusionCertificateItem,
    tree_size: int,
    root: bytes,
) -> InclusionCertificateItemVerdict:
    index = item.get("index")
    leaf_hex = item.get("leaf", "")

    # Carry an item-level error (e.g. a build-time "leaf not found") through to
    # the verdict so a re-verifier sees why a miss is a miss.
    if item.get("error") is not None:
        return InclusionCertificateItemVerdict(
            index=index, leaf=leaf_hex, verified=False, error=item["error"]
        )

    # Pre-validate the per-item index so the primitive's range guard is never
    # reached: an out-of-range index is a non-verifying item, not an exception.
    if not _is_int(index) or index < 0 or index >= tree_size:
        return InclusionCertificateItemVerdict(
            index=index,
            leaf=leaf_hex,
            verified=False,
            error=f"index {index!r} out of range [0, {tree_size})",
        )

    leaf_bytes, leaf_error = _decode_hex(leaf_hex)
    if leaf_error is not None:
        return InclusionCertificateItemVerdict(
            index=index, leaf=leaf_hex, verified=False, error=f"malformed leaf: {leaf_error}"
        )

    proof: list[bytes] = []
    for i, sibling_hex in enumerate(item.get("proof", [])):
        sibling_bytes, sibling_error = _decode_hex(sibling_hex)
        if sibling_error is not None:
            return InclusionCertificateItemVerdict(
                index=index,
                leaf=leaf_hex,
                verified=False,
                error=f"malformed proof[{i}]: {sibling_error}",
            )
        proof.append(sibling_bytes)

    verified = merkle_sha2_256_verify_inclusion(leaf_bytes, index, tree_size, proof, root)
    return InclusionCertificateItemVerdict(index=index, leaf=leaf_hex, verified=verified)


# Producers emit lowercase, but a certificate is valid with either case. We
# accept upper or lower, but unlike ``bytes.fromhex`` we reject any non-hex
# character — including leading, trailing, or embedded whitespace — and any
# odd-length string, matching the strict TypeScript and Rust decoders.
_HEX_FIELD = re.compile(r"(?:[0-9a-fA-F]{2})*")


def _decode_hex(value: object) -> tuple[bytes, str | None]:
    if not isinstance(value, str):
        return b"", "value is not a string"
    if _HEX_FIELD.fullmatch(value) is None:
        return b"", "value is not even-length hex"
    return bytes.fromhex(value), None


def _anchor_claim_of(cert: InclusionCertificateV1) -> CertificateAnchor:
    """Reconstruct the :class:`CertificateAnchor` from the certificate's anchor
    block, echoing every present field verbatim.

    This is a faithful echo of the *claimed* anchor — never a fabrication and
    never a validation; :func:`verify_inclusion_certificate` validates the fixed
    fields separately and the byte facts are confirmed on a public explorer.
    """
    a = cert.get("anchor") or {}
    chain = a.get("chain")
    network = a.get("network")
    tx_hash = a.get("tx_hash")
    metadata_label = a.get("metadata_label")
    block_time = a.get("block_time")
    block_height = a.get("block_height")
    slot = a.get("slot")
    confirmations = a.get("confirmations_at_generation")
    explorer_urls = a.get("explorer_urls")
    return CertificateAnchor(
        # `chain` and `metadata_label` are echoed as the actual certificate
        # values (verify rejects a non-conforming value via the fixed-field
        # checks); the byte facts are confirmed on a public explorer.
        chain=chain if isinstance(chain, str) else "cardano",
        network=network if isinstance(network, str) else "",
        tx_hash=tx_hash if isinstance(tx_hash, str) else "",
        metadata_label=metadata_label if _is_int(metadata_label) else METADATA_LABEL_309,
        block_time=block_time if _is_int(block_time) else 0,
        block_height=block_height if _is_int(block_height) else None,
        slot=slot if _is_int(slot) else None,
        confirmations_at_generation=confirmations if _is_int(confirmations) else None,
        explorer_urls=tuple(explorer_urls) if isinstance(explorer_urls, list) else None,
    )


__all__ = ["verify_inclusion_certificate"]
