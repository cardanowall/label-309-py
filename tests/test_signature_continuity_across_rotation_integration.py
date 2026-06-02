"""Python sibling for signature continuity across rotation.

Mirrors the @cardanowall/crypto-core signature-continuity-across-rotation
integration test against the byte-identical Python primitives.
"""

from __future__ import annotations

from cardanowall._crypto.cose_sign1 import cose_sign1_build, cose_sign1_verify
from cardanowall._crypto.seed_derive import derive_ed25519_keypair_from_seed

S0 = b"\xe0" * 32
S1 = b"\xe1" * 32
S2 = b"\xe2" * 32

PAYLOAD = b"continuity test"
COSE_ALG_LABEL = 1
COSE_KID_LABEL = 4
COSE_ALG_EDDSA = -8
EMPTY_AAD = b""


def test_old_signature_still_verifies_after_two_rotations() -> None:
    ed0 = derive_ed25519_keypair_from_seed(S0)
    pub0 = ed0["public_key"]
    priv0 = ed0["secret_key"]

    protected_header: dict[int | str, object] = {
        COSE_ALG_LABEL: COSE_ALG_EDDSA,
        COSE_KID_LABEL: pub0,
    }
    cose_bytes = cose_sign1_build(
        protected_header=protected_header,
        unprotected_header={},
        payload=PAYLOAD,
        external_aad=EMPTY_AAD,
        signer_secret_key=priv0,
        detached=True,
    )

    # Rotate s0 → s1 → s2. Each rotation derives a fresh Ed25519 keypair
    # from the new seed only.
    ed1 = derive_ed25519_keypair_from_seed(S1)
    ed2 = derive_ed25519_keypair_from_seed(S2)
    assert ed1["public_key"] != pub0
    assert ed2["public_key"] != pub0
    assert ed1["public_key"] != ed2["public_key"]

    result = cose_sign1_verify(
        message=cose_bytes,
        external_aad=EMPTY_AAD,
        detached_payload=PAYLOAD,
    )
    assert result["ok"] is True
    # cose_sign1_verify returns a discriminated union; the True branch is
    # CoseVerifySuccess which carries signer_key.
    assert result["signer_key"] == pub0


def test_ed25519_derivation_is_deterministic() -> None:
    a = derive_ed25519_keypair_from_seed(S0)
    b = derive_ed25519_keypair_from_seed(S0)
    assert a["public_key"] == b["public_key"]
