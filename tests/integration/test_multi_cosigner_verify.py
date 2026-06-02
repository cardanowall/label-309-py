"""Multi-cosigner record-level sigs[] verifier parity test.

Python mirror of the @cardanowall/sdk-ts multi-cosigner-verify integration
test. Builds a mixed-paths record inline (no JSON fixture file) from
byte-pinned seeds (RFC 8032 §7.1 Test 2 for the identity signer,
`0x11` repeated 32 times for the wallet signer), then exercises
`verify_record_signatures` in both identity-first and wallet-first sigs[]
orderings.

The Python side reuses the same `NormalizedSigVerdict` projection
(in `tests/wallet_cose/_normalized_verdict.py`) to bridge any TS/Python
verifier-output drift. We bind the wallet stake address
to the REAL Blake2b-224(pubkey) instead of a synthetic mock — the
verifier's WALLET_ADDRESS_MISMATCH
check requires a real binding to surface `valid: true`.
"""

from __future__ import annotations

import asyncio
import hashlib
from typing import cast

from cardanowall._crypto.cbor import (
    CanonicalCborValue,
    decode_canonical_cbor,
    encode_canonical_cbor,
)
from cardanowall._crypto.cose_sign1 import (
    build_cip309_sig_structure,
    encode_cose_sign1,
)
from cardanowall._crypto.sig import get_public_key_ed25519, sign_ed25519
from cardanowall.poe_standard import (
    PoeRecord,
    chunk_bytes,
    encode_poe_record,
    encode_record_body_for_signing,
)
from cardanowall.verifier import VerifyTxInput, verify_record_signatures

IDENTITY_SEED_HEX = "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"
WALLET_SEED_HEX = "1111111111111111111111111111111111111111111111111111111111111111"
IDENTITY_PUBKEY_HEX = "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"
WALLET_PUBKEY_HEX = "d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737"
AR_URI = "ar://qP3RkY7nBs2Fz9HxV1WuC5oJ4mE6tN8aL0iDXgQrU0K"
A2_SHA = "97a7881ce48f5bf457261797e06e3387a904f0ee70488d3c03090635800320ee"
A2_BLAKE = "2d3b9520f17f6be4e26361b18afc8d7bbdbc2cd4209319a77f014f2fd0d409a4"


def _blake2b_224(data: bytes) -> bytes:
    return hashlib.blake2b(data, digest_size=28).digest()


def _build_record_body() -> PoeRecord:
    body: PoeRecord = cast(
        PoeRecord,
        {
            "v": 1,
            "items": [
                {
                    "hashes": {
                        "sha2-256": bytes.fromhex(A2_SHA),
                        "blake2b-256": bytes.fromhex(A2_BLAKE),
                    },
                    "uris": [[AR_URI]],
                }
            ],
        },
    )
    return body


def _build_identity_sig_entry(body: PoeRecord) -> dict[str, list[bytes]]:
    seed = bytes.fromhex(IDENTITY_SEED_HEX)
    pubkey = get_public_key_ed25519(seed)
    assert pubkey.hex() == IDENTITY_PUBKEY_HEX
    protected: dict[int | str, object] = {1: -8, 4: pubkey}
    protected_bytes = encode_canonical_cbor(cast(CanonicalCborValue, protected))
    sig_structure = build_cip309_sig_structure(
        body_protected_bytes=protected_bytes,
        record_body_cbor=encode_record_body_for_signing(body),
    )
    signature = sign_ed25519(seed, sig_structure)
    cose = encode_cose_sign1(
        protected_header=protected,
        unprotected_header={},
        payload=None,
        signature=signature,
    )
    return {"cose_sign1": chunk_bytes(cose)}


def _build_wallet_sig_entry(body: PoeRecord) -> dict[str, list[bytes]]:
    seed = bytes.fromhex(WALLET_SEED_HEX)
    pubkey = get_public_key_ed25519(seed)
    assert pubkey.hex() == WALLET_PUBKEY_HEX
    # See TS twin: bind to the real Blake2b-224(pubkey) stake address rather
    # than a synthetic mock so the verifier's path-2 binding check succeeds.
    MAINNET_HEADER = 0xE1
    stake_addr = bytes([MAINNET_HEADER]) + _blake2b_224(pubkey)
    protected: dict[int | str, object] = {1: -8, "address": stake_addr}
    protected_bytes = encode_canonical_cbor(cast(CanonicalCborValue, protected))
    sig_structure = build_cip309_sig_structure(
        body_protected_bytes=protected_bytes,
        record_body_cbor=encode_record_body_for_signing(body),
    )
    signature = sign_ed25519(seed, sig_structure)
    cose = encode_cose_sign1(
        protected_header=protected,
        unprotected_header={},
        payload=None,
        signature=signature,
    )
    cose_key: dict[int, object] = {1: 1, 3: -8, -1: 6, -2: pubkey}
    cose_key_bytes = encode_canonical_cbor(cast(CanonicalCborValue, cose_key))
    return {
        "cose_sign1": chunk_bytes(cose),
        "cose_key": chunk_bytes(cose_key_bytes),
    }


def test_identity_first_ordering_verifies_both_entries() -> None:
    body = _build_record_body()
    record = cast(
        PoeRecord,
        {**body, "sigs": [_build_identity_sig_entry(body), _build_wallet_sig_entry(body)]},
    )
    out = asyncio.run(
        verify_record_signatures(record, VerifyTxInput(tx_hash="00" * 32))
    )
    assert len(out) == 2
    assert out[0].verdict == "valid"
    assert out[0].signer_type == "in-signature-kid"
    assert out[1].verdict == "valid"
    assert out[1].signer_type == "wallet-inline-key"


def test_wallet_first_ordering_verifies_both_entries() -> None:
    body = _build_record_body()
    record = cast(
        PoeRecord,
        {**body, "sigs": [_build_wallet_sig_entry(body), _build_identity_sig_entry(body)]},
    )
    out = asyncio.run(
        verify_record_signatures(record, VerifyTxInput(tx_hash="00" * 32))
    )
    assert len(out) == 2
    assert out[0].verdict == "valid"
    assert out[0].signer_type == "wallet-inline-key"
    assert out[1].verdict == "valid"
    assert out[1].signer_type == "in-signature-kid"


def test_canonical_cbor_round_trip_is_byte_stable() -> None:
    body = _build_record_body()
    record = cast(
        PoeRecord,
        {**body, "sigs": [_build_identity_sig_entry(body), _build_wallet_sig_entry(body)]},
    )
    cbor = encode_poe_record(record)
    decoded = decode_canonical_cbor(cbor)
    reencoded = encode_canonical_cbor(cast(CanonicalCborValue, decoded))
    assert reencoded == cbor
