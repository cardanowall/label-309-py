"""Per-signature path-1 / path-2 verification suite.

Covers the full per-entry verification flow (steps 1-8) plus the path-2
WALLET_ADDRESS_MISMATCH binding check. Sealed/recipient-sealed profile is
the default so `sigs[]` is always read.
"""

from __future__ import annotations

import hashlib
from typing import cast

from cardanowall._crypto.cbor import CanonicalCborValue, encode_canonical_cbor
from cardanowall._crypto.cose_sign1 import cose_sign1_build
from cardanowall._crypto.sig import get_public_key_ed25519
from cardanowall.poe_standard import (
    PoeRecord,
)
from cardanowall.verifier import verify_record_signatures
from cardanowall.verifier.signatures import CARDANO_POE_SIG_DOMAIN_PREFIX


def _blake2b_224(data: bytes) -> bytes:
    return hashlib.blake2b(data, digest_size=28).digest()


def _to_sign(record: PoeRecord) -> bytes:
    body = {k: v for k, v in record.items() if k != "sigs"}
    return CARDANO_POE_SIG_DOMAIN_PREFIX + encode_canonical_cbor(cast(CanonicalCborValue, body))


def _stable_seed(i: int) -> bytes:
    return bytes([i]) * 32


def _mk_record_with_sig_path1(seed: bytes) -> PoeRecord:
    """Build a record carrying a path-1 (in-signature 32-byte protected `kid`)
    Ed25519 signature over the canonical record body. The cose_sign1 entry
    embeds the 32-byte raw public key as the protected-header `kid` (path 1).
    """
    pub = get_public_key_ed25519(seed)
    record_base: PoeRecord = {
        "v": 1,
        "items": [{"hashes": {"sha2-256": b"\x00" * 32}}],
    }
    to_sign = _to_sign(record_base)
    cose = cose_sign1_build(
        protected_header={1: -8, 4: pub},
        unprotected_header={},
        payload=to_sign,
        external_aad=b"",
        signer_secret_key=seed,
        detached=True,
    )
    return cast(
        PoeRecord,
        {
            **record_base,
            "sigs": [{"cose_sign1": cose}],
        },
    )


def _mk_cose_key_blob(pub: bytes) -> bytes:
    # RFC 9053 §7.2 / RFC 8152 §13 — COSE_Key for Ed25519:
    # {1: 1 (OKP), 3: -8 (EdDSA), -1: 6 (Ed25519), -2: <pubkey>}
    return encode_canonical_cbor(
        cast(
            CanonicalCborValue,
            {1: 1, 3: -8, -1: 6, -2: pub},
        )
    )


def _mk_record_with_sig_path2(seed: bytes, *, address_override: bytes | None = None) -> PoeRecord:
    """Build a record carrying a path-2 (CIP-30 wallet inline `cose_key`)
    Ed25519 signature. The cose_sign1 entry's protected header carries the
    29-byte CIP-19 stake address (`0xE1 || Blake2b-224(pubkey)`) at the
    `"address"` label.
    """
    pub = get_public_key_ed25519(seed)
    address = (
        address_override if address_override is not None else bytes([0xE1]) + _blake2b_224(pub)
    )
    record_base: PoeRecord = {
        "v": 1,
        "items": [{"hashes": {"sha2-256": b"\x11" * 32}}],
    }
    to_sign = _to_sign(record_base)
    cose = cose_sign1_build(
        protected_header={1: -8, "address": address},
        unprotected_header={},
        payload=to_sign,
        external_aad=b"",
        signer_secret_key=seed,
        detached=True,
    )
    return cast(
        PoeRecord,
        {
            **record_base,
            "sigs": [
                {
                    "cose_sign1": cose,
                    "cose_key": _mk_cose_key_blob(pub),
                }
            ],
        },
    )


def test_path1_in_signature_kid_verifies() -> None:
    seed = _stable_seed(1)
    record = _mk_record_with_sig_path1(seed)
    results = verify_record_signatures(record)
    assert len(results) == 1
    r = results[0]
    assert r.verdict == "valid"
    assert r.signer_type == "in-signature-kid"
    assert r.reason is None
    assert r.signer_pub == get_public_key_ed25519(seed).hex()


def test_path2_wallet_inline_key_with_correct_address_verifies() -> None:
    seed = _stable_seed(2)
    record = _mk_record_with_sig_path2(seed)
    results = verify_record_signatures(record)
    assert len(results) == 1
    r = results[0]
    assert r.verdict == "valid"
    assert r.signer_type == "wallet-inline-key"
    assert r.reason is None


def test_path2_with_wrong_address_emits_wallet_address_mismatch() -> None:
    # 29-byte stake-address shape but address bytes deliberately do not bind
    # to the actual signing pubkey — recompute fails the constant-time compare.
    seed = _stable_seed(3)
    bad_address = bytes([0xE1]) + b"\x00" * 28
    record = _mk_record_with_sig_path2(seed, address_override=bad_address)
    results = verify_record_signatures(record)
    assert len(results) == 1
    r = results[0]
    assert r.verdict == "invalid"
    assert r.reason == "WALLET_ADDRESS_MISMATCH"
    # The Ed25519 signature itself verified; only the address binding failed,
    # so the signer_pub MUST still be surfaced for diagnostic display.
    assert r.signer_pub == get_public_key_ed25519(seed).hex()


def test_path2_with_non29_byte_address_fails_wallet_binding() -> None:
    # v1 wallet path binds to 29-byte CIP-19 stake addresses only. A
    # 28-byte payment-only or 57-byte base-address claim is rejected by the
    # address-binding check.
    seed = _stable_seed(4)
    record = _mk_record_with_sig_path2(seed, address_override=b"\x00" * 28)
    results = verify_record_signatures(record)
    assert results[0].reason == "WALLET_ADDRESS_MISMATCH"


def test_path2_with_missing_address_fails_wallet_binding() -> None:
    # A wallet-path entry MUST carry the protected `"address"` field; a
    # missing field is non-conformant.
    seed = _stable_seed(5)
    pub = get_public_key_ed25519(seed)
    record_base: PoeRecord = {
        "v": 1,
        "items": [{"hashes": {"sha2-256": b"\x22" * 32}}],
    }
    to_sign = _to_sign(record_base)
    cose = cose_sign1_build(
        protected_header={1: -8},  # no "address" field
        unprotected_header={},
        payload=to_sign,
        external_aad=b"",
        signer_secret_key=seed,
        detached=True,
    )
    record: PoeRecord = cast(
        PoeRecord,
        {
            **record_base,
            "sigs": [
                {
                    "cose_sign1": cose,
                    "cose_key": _mk_cose_key_blob(pub),
                }
            ],
        },
    )
    results = verify_record_signatures(record)
    assert results[0].reason == "WALLET_ADDRESS_MISMATCH"


def test_unsupported_alg_emits_signature_unsupported() -> None:
    seed = _stable_seed(6)
    pub = get_public_key_ed25519(seed)
    record_base: PoeRecord = {
        "v": 1,
        "items": [{"hashes": {"sha2-256": b"\x33" * 32}}],
    }
    to_sign = _to_sign(record_base)
    cose = cose_sign1_build(
        # -19 (fully-specified Ed25519) is a registered OPT-INFO codepoint this
        # verifier does not implement; it surfaces as SIGNATURE_UNSUPPORTED.
        protected_header={1: -19, 4: pub},
        unprotected_header={},
        payload=to_sign,
        external_aad=b"",
        signer_secret_key=seed,
        detached=True,
    )
    record: PoeRecord = cast(
        PoeRecord,
        {**record_base, "sigs": [{"cose_sign1": cose}]},
    )
    results = verify_record_signatures(record)
    assert results[0].verdict == "unsupported"
    assert results[0].reason == "SIGNATURE_UNSUPPORTED"


def test_bad_signature_emits_signature_invalid() -> None:
    seed = _stable_seed(7)
    # Sign over the WRONG payload (no domain prefix), so the verifier-side
    # canonical Sig_structure rebuild produces a different hash to verify.
    pub = get_public_key_ed25519(seed)
    record_base: PoeRecord = {
        "v": 1,
        "items": [{"hashes": {"sha2-256": b"\x44" * 32}}],
    }
    cose = cose_sign1_build(
        protected_header={1: -8, 4: pub},
        unprotected_header={},
        payload=b"not-the-real-payload",
        external_aad=b"",
        signer_secret_key=seed,
        detached=True,
    )
    record: PoeRecord = cast(
        PoeRecord,
        {**record_base, "sigs": [{"cose_sign1": cose}]},
    )
    results = verify_record_signatures(record)
    assert results[0].verdict == "invalid"
    assert results[0].reason == "SIGNATURE_INVALID"


def test_malformed_cose_sign1_emits_malformed() -> None:
    record: PoeRecord = cast(
        PoeRecord,
        {
            "v": 1,
            "items": [{"hashes": {"sha2-256": b"\x55" * 32}}],
            "sigs": [{"cose_sign1": b"\xff" * 10}],  # not a valid COSE_Sign1
        },
    )
    results = verify_record_signatures(record)
    assert results[0].verdict == "invalid"
    assert results[0].reason == "MALFORMED_SIG_COSE_SIGN1"


def test_path1_unresolved_signer_key_emits_signer_key_unresolved() -> None:
    # Path 1 with a non-32-byte protected kid, NO cose_key sidecar — the
    # verifier cannot resolve a public key and reports SIGNER_KEY_UNRESOLVED.
    seed = _stable_seed(8)
    record_base: PoeRecord = {
        "v": 1,
        "items": [{"hashes": {"sha2-256": b"\x66" * 32}}],
    }
    to_sign = _to_sign(record_base)
    cose = cose_sign1_build(
        protected_header={1: -8, 4: b"\xaa" * 16},  # 16-byte kid, NOT 32
        unprotected_header={},
        payload=to_sign,
        external_aad=b"",
        signer_secret_key=seed,
        detached=True,
    )
    record: PoeRecord = cast(
        PoeRecord,
        {**record_base, "sigs": [{"cose_sign1": cose}]},
    )
    results = verify_record_signatures(record)
    assert results[0].verdict == "unresolved"
    assert results[0].reason == "SIGNER_KEY_UNRESOLVED"
