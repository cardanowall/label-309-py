"""Type surface for the Label 309 Inclusion Certificate.

An inclusion certificate is a downloadable, self-contained, standalone-
verifiable proof that one or more content hashes were committed as leaves of an
RFC 9162 (Certificate Transparency) SHA-256 Merkle tree whose root was published
on Cardano under metadata label 309. Each item embeds its full sibling path, so
the artifact re-verifies forever from the file alone — no network, no storage
gateway, no trust in any issuer.

Two kinds of value live here:

- the *input* shapes (``CertificateAnchor``, ``CertificateMerkle``,
  ``CertificateTarget``) the builder consumes, with raw ``bytes`` values; and
- the *output* JSON shape (``InclusionCertificateV1`` and friends) the builder
  emits, with lowercase-hex string values, so it serialises directly to the
  on-disk certificate.

The emitted shapes are typed as ``TypedDict`` and produced as plain ``dict``
values inserted in the normative key order; Python preserves dict insertion
order, so the serialised JSON is stable across the parity twins.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import NotRequired, TypedDict


@dataclass(frozen=True)
class CertificateAnchor:
    """The blockchain anchor: the Cardano transaction whose Label 309 record
    carries the Merkle root.

    Every time/height/slot value here is asserted by the public blockchain (via
    explorers), never cryptographically bound by the certificate.
    """

    network: str
    """Cardano network name, e.g. ``"mainnet"`` or ``"preprod"``."""
    tx_hash: str
    """Transaction hash, 64 lowercase hex characters."""
    block_time: int
    """Block time in POSIX seconds, as asserted by the explorer."""
    chain: str = "cardano"
    metadata_label: int = 309
    block_height: int | None = None
    slot: int | None = None
    confirmations_at_generation: int | None = None
    """Confirmation count snapshot at generation; informational, not a claim."""
    explorer_urls: tuple[str, ...] | None = None


@dataclass(frozen=True)
class CertificateMerkle:
    """The Merkle commitment the certificate proves inclusion against.

    ``root`` is the raw 32-byte tree head; ``tree_size`` is the on-chain
    ``leaf_count``.
    """

    tree_alg: str
    """Tree algorithm identifier; only ``"rfc9162-sha256"`` is supported."""
    root: bytes
    tree_size: int
    """Number of leaves in the tree (the on-chain ``leaf_count``)."""
    leaves_list_uri: str | None = None
    leaves_list_url: str | None = None


@dataclass(frozen=True)
class CertificateTarget:
    """One target the caller wants proven: a committed content hash (a leaf)
    plus an optional human label and the algorithm used to hash a file into the
    leaf.
    """

    leaf: bytes
    """The 32-byte content hash that was committed as a leaf."""
    leaf_alg: str | None = None
    """How a file is hashed to reproduce ``leaf`` (default ``"sha2-256"``)."""
    label: str | None = None
    """Optional user note / filename."""


class InclusionCertificateAnchor(TypedDict):
    """The anchor block of the emitted JSON certificate (snake_case, hex)."""

    chain: str
    network: str
    tx_hash: str
    metadata_label: int
    block_time: int
    block_time_iso: str
    block_height: NotRequired[int]
    slot: NotRequired[int]
    confirmations_at_generation: NotRequired[int]
    explorer_urls: NotRequired[list[str]]


class InclusionCertificateMerkle(TypedDict):
    """The Merkle block of the emitted JSON certificate."""

    tree_alg: str
    root: str
    """Lowercase hex of the raw 32-byte root."""
    tree_size: int
    leaves_list_uri: NotRequired[str]
    leaves_list_url: NotRequired[str]


class InclusionCertificateItem(TypedDict):
    """One certificate item: a leaf, its position, and the sibling path that
    recomputes the root.

    ``verified`` records the builder's recomputation at generation time; an
    independent verifier MUST recompute it and not trust this stored boolean. A
    target absent from the tree is still emitted, with ``verified`` False and an
    explanatory ``error``.
    """

    leaf: str
    """Lowercase hex of the committed content hash."""
    leaf_alg: NotRequired[str]
    index: int
    proof: list[str]
    """Sibling hashes, leaf->root order, lowercase hex; ``[]`` for a single-leaf tree."""
    verified: bool
    label: NotRequired[str]
    error: NotRequired[str]
    """Present only when the target could not be proven (e.g. not in the tree)."""


class InclusionCertificateVerification(TypedDict):
    """Human/machine-readable statement of what the certificate proves."""

    method: str
    independent_tools: list[str]
    requires_issuer_trust: bool
    time_asserted_by: str


class InclusionCertificateV1(TypedDict):
    """The full Label 309 inclusion certificate (artifact 1, the JSON form)."""

    format: str
    generated_at: str
    anchor: InclusionCertificateAnchor
    merkle: InclusionCertificateMerkle
    items: list[InclusionCertificateItem]
    claim: str
    verification: InclusionCertificateVerification


@dataclass(frozen=True)
class InclusionCertificateItemVerdict:
    """Per-item verdict from a pure re-verification of a certificate."""

    index: int
    leaf: str
    """Lowercase hex of the leaf, echoed from the certificate."""
    verified: bool
    error: str | None = None


@dataclass(frozen=True)
class InclusionCertificateVerifyResult:
    """Result of :func:`verify_inclusion_certificate`.

    ``ok`` is true only when every item's proof recomputes to the embedded root.
    ``anchor_claim`` is echoed from the certificate and MUST be confirmed on a
    public Cardano explorer separately — re-verification proves inclusion math,
    never the anchoring.
    """

    ok: bool
    items: tuple[InclusionCertificateItemVerdict, ...]
    anchor_claim: CertificateAnchor
    error: str | None = None
    """Present when the whole certificate was rejected (bad format / tree alg)."""


__all__ = [
    "CertificateAnchor",
    "CertificateMerkle",
    "CertificateTarget",
    "InclusionCertificateAnchor",
    "InclusionCertificateItem",
    "InclusionCertificateItemVerdict",
    "InclusionCertificateMerkle",
    "InclusionCertificateV1",
    "InclusionCertificateVerification",
    "InclusionCertificateVerifyResult",
]
