"""CIP-30 / RFC 9052 §7 COSE_Key extraction for the Ed25519 sig path.

CIP-30 wallets that don't put a 32-byte raw Ed25519 pubkey in the COSE_Sign1
protected header instead deliver the signer key as a separate ``cbor<COSE_Key>``
blob, surfaced in the CIP-309 record under the top-level ``signer_keys`` field.
This helper decodes one such blob and returns the underlying 32-byte Ed25519
pubkey, or ``None`` when the blob is malformed, uses an unexpected key type /
curve, or has the wrong ``x`` length.

Expected COSE_Key shape (RFC 9053 §7.2 + RFC 8152 §13)::

    {
       1 (kty): 1   # OKP
       3 (alg): -8  # EdDSA — OPTIONAL but if present MUST be -8
      -1 (crv): 6   # Ed25519
      -2 (x):   <32-byte raw public key>
    }
"""

from __future__ import annotations

from .cbor import CanonicalCborError, decode_canonical_cbor

_COSE_KEY_LABEL_KTY = 1
_COSE_KEY_LABEL_ALG = 3
_COSE_KEY_LABEL_CRV = -1
_COSE_KEY_LABEL_X = -2

_KTY_OKP = 1
_ALG_EDDSA = -8
_CRV_ED25519 = 6

_ED25519_PUBLIC_KEY_LENGTH = 32


def parse_cose_key_ed25519(blob: bytes) -> bytes | None:
    try:
        decoded = decode_canonical_cbor(blob)
    except CanonicalCborError:
        return None
    if not isinstance(decoded, dict):
        return None

    kty = decoded.get(_COSE_KEY_LABEL_KTY)
    if not isinstance(kty, int) or isinstance(kty, bool) or kty != _KTY_OKP:
        return None

    crv = decoded.get(_COSE_KEY_LABEL_CRV)
    if not isinstance(crv, int) or isinstance(crv, bool) or crv != _CRV_ED25519:
        return None

    if _COSE_KEY_LABEL_ALG in decoded:
        alg = decoded[_COSE_KEY_LABEL_ALG]
        if not isinstance(alg, int) or isinstance(alg, bool) or alg != _ALG_EDDSA:
            return None

    x = decoded.get(_COSE_KEY_LABEL_X)
    if not isinstance(x, bytes) or len(x) != _ED25519_PUBLIC_KEY_LENGTH:
        return None

    return x
