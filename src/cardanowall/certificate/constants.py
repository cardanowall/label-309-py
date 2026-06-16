"""Fixed string constants embedded verbatim in every inclusion certificate.

These are part of the on-disk format: the parity twins in the TypeScript and
Rust SDKs reproduce them byte-for-byte, so they are defined once here and never
templated or localised.
"""

from __future__ import annotations

from typing import Final

INCLUSION_CERTIFICATE_FORMAT_V1: Final[str] = "label-309-inclusion-certificate-v1"

# RFC 9162 (Certificate Transparency) SHA-256, IANA verifiable-data-structure 1.
CERTIFICATE_TREE_ALG: Final[str] = "rfc9162-sha256"

# Cardano metadata label that carries Label 309 records.
METADATA_LABEL_309: Final[int] = 309

# IANA "COSE Verifiable Data Structures" codepoint for RFC9162_SHA256.
VDS_RFC9162_SHA256: Final[int] = 1

CERTIFICATE_CLAIM: Final[str] = (
    "Each listed hash was included in a Merkle tree whose root was published on "
    "the Cardano blockchain in the referenced transaction under metadata label "
    "309; therefore each hash provably existed on or before the stated block time."
)

CERTIFICATE_VERIFICATION_METHOD: Final[str] = (
    "RFC 9162 (Certificate Transparency) SHA-256 inclusion proof. For each item, "
    "recompute the Merkle root from leaf+index+tree_size+proof and compare to "
    "merkle.root; then confirm merkle.root equals the merkle[].root in the "
    "Label 309 record of anchor.tx_hash on any public Cardano explorer."
)

CERTIFICATE_INDEPENDENT_TOOLS: Final[tuple[str, ...]] = (
    "cardanowall certificate verify <file>",
    "cardanowall merkle verify (per item)",
    "any RFC 9162 / COSE verifiable-data-structure verifier",
)

CERTIFICATE_TIME_ASSERTED_BY: Final[str] = "Cardano blockchain (block time), via public explorers"

__all__ = [
    "CERTIFICATE_CLAIM",
    "CERTIFICATE_INDEPENDENT_TOOLS",
    "CERTIFICATE_TIME_ASSERTED_BY",
    "CERTIFICATE_TREE_ALG",
    "CERTIFICATE_VERIFICATION_METHOD",
    "INCLUSION_CERTIFICATE_FORMAT_V1",
    "METADATA_LABEL_309",
    "VDS_RFC9162_SHA256",
]
