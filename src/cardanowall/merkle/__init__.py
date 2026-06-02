"""Public Merkle namespace for the CIP-309 Python SDK.

The internal ``cardanowall._crypto`` namespace stays underscore-prefixed
(parity twin of the ``private: true`` ``@cardanowall/crypto-core`` TS
package). The SDK is the only public consumption surface, so we re-export
the on-wire Merkle primitives here under their canonical names.

Surface:

- ``merkle_sha2_256_root`` / ``merkle_sha2_256_inclusion_proof`` /
  ``merkle_sha2_256_verify_inclusion`` — RFC 9162 §2.1.1 binary Merkle
  tree under SHA-256.
- ``encode_leaves_list`` / ``decode_leaves_list`` — canonical-CBOR codec
  for the off-chain leaves-list artefact.
- ``MERKLE_ALG_ID`` / ``LEAVES_LIST_FORMAT_V1`` — registered string
  identifiers embedded in the on-wire ``merkle[]`` commitment and the
  CBOR leaves-list.
- ``MerkleLeavesListError`` — typed error class for codec rejections.

Byte parity with the ``@cardanowall/sdk-ts`` merkle module is enforced by a
shared KAT corpus mirrored byte-for-byte on both the TypeScript and Python
sides.
"""

from __future__ import annotations

from cardanowall._crypto.merkle_leaves_list import (
    LEAVES_LIST_FORMAT_V1,
    MerkleLeavesListError,
    decode_leaves_list,
    encode_leaves_list,
)
from cardanowall._crypto.merkle_sha2_256 import (
    MERKLE_ALG_ID,
    merkle_sha2_256_inclusion_proof,
    merkle_sha2_256_root,
    merkle_sha2_256_verify_inclusion,
)

__all__ = [
    "LEAVES_LIST_FORMAT_V1",
    "MERKLE_ALG_ID",
    "MerkleLeavesListError",
    "decode_leaves_list",
    "encode_leaves_list",
    "merkle_sha2_256_inclusion_proof",
    "merkle_sha2_256_root",
    "merkle_sha2_256_verify_inclusion",
]
