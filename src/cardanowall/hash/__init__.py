"""Public hash namespace for the CIP-309 Python SDK.

Re-exports the closed-catalogue digest primitives from
``cardanowall._crypto.hash`` so SDK consumers can build their own Merkle
leaves (``sha2_256(bytes)``) or content hashes without importing the
internal underscore-prefixed module. Both algorithms are registered in the
CIP-309 hash registry:

- ``sha2_256`` — SHA-256 (default content/leaf hash).
- ``blake2b_256`` — Blake2b-256 (alternative; both ride under ``dual_hash``).

``dual_hash`` returns a ``DualHashOutput`` ``TypedDict`` carrying both
digests for callers that publish under both algorithm identifiers in the
same record.
"""

from __future__ import annotations

from cardanowall._crypto.hash import (
    DualHashOutput,
    blake2b_256,
    dual_hash,
    dual_hash_stream,
)
from cardanowall._crypto.hash import (
    sha256 as sha2_256,
)

__all__ = [
    "DualHashOutput",
    "blake2b_256",
    "dual_hash",
    "dual_hash_stream",
    "sha2_256",
]
