"""Public ``cardanowall.certificate`` namespace.

The inclusion certificate is a self-contained, standalone-verifiable proof that
one or more content hashes were committed as leaves of an RFC 9162 SHA-256
Merkle tree whose root was published on Cardano under metadata label 309.
Everything here is pure and I/O-free — callers fetch any external bytes (e.g.
the off-chain leaves-list) themselves and pass the decoded leaves in; the crypto
path performs no I/O.

Surface:

- :func:`build_inclusion_certificate` — compute + self-verify per-target proofs
  and emit the JSON certificate object.
- :func:`verify_inclusion_certificate` — pure re-verification of a certificate
  from its own bytes; reports per-item verdicts and echoes the anchor to confirm
  on-chain separately.
- :func:`encode_cose_inclusion_proof` / :func:`encode_ietf_inclusion_proof` —
  the per-item COSE / RFC 9162 aligned CBOR proof, and the bare IETF
  inclusion-proof byte string on its own.
- format / claim / verification string constants emitted verbatim.

Byte parity with the ``@cardanowall/sdk-ts`` certificate module is enforced by a
shared known-vector (the COSE CBOR bytes and Merkle root) reproduced
byte-for-byte on the TypeScript, Python, and Rust sides.
"""

from __future__ import annotations

from .build import build_inclusion_certificate
from .constants import (
    CERTIFICATE_CLAIM,
    CERTIFICATE_INDEPENDENT_TOOLS,
    CERTIFICATE_TIME_ASSERTED_BY,
    CERTIFICATE_TREE_ALG,
    CERTIFICATE_VERIFICATION_METHOD,
    INCLUSION_CERTIFICATE_FORMAT_V1,
    METADATA_LABEL_309,
    VDS_RFC9162_SHA256,
)
from .cose import encode_cose_inclusion_proof, encode_ietf_inclusion_proof
from .types import (
    CertificateAnchor,
    CertificateMerkle,
    CertificateTarget,
    InclusionCertificateAnchor,
    InclusionCertificateItem,
    InclusionCertificateItemVerdict,
    InclusionCertificateMerkle,
    InclusionCertificateV1,
    InclusionCertificateVerification,
    InclusionCertificateVerifyResult,
)
from .verify import verify_inclusion_certificate

__all__ = [
    "CERTIFICATE_CLAIM",
    "CERTIFICATE_INDEPENDENT_TOOLS",
    "CERTIFICATE_TIME_ASSERTED_BY",
    "CERTIFICATE_TREE_ALG",
    "CERTIFICATE_VERIFICATION_METHOD",
    "INCLUSION_CERTIFICATE_FORMAT_V1",
    "METADATA_LABEL_309",
    "VDS_RFC9162_SHA256",
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
    "build_inclusion_certificate",
    "encode_cose_inclusion_proof",
    "encode_ietf_inclusion_proof",
    "verify_inclusion_certificate",
]
