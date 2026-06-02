"""Python crypto-core verifier hashed-mode dedicated test.

Python parity twin of the @cardanowall/crypto-core hashed-mode COSE_Sign1 test.
Covers `cose_sign1_cip309_verify`'s branching on the unprotected
`"hashed": True` flag in isolation.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, cast

import pytest

from cardanowall._crypto.cbor import CanonicalCborValue, encode_canonical_cbor
from cardanowall._crypto.cose_sign1 import (
    CARDANO_POE_SIG_DOMAIN_PREFIX,
    build_cip309_sig_structure,
    build_sig_structure,
    cose_sign1_cip309_verify,
    encode_cose_sign1,
)
from cardanowall._crypto.sig import sign_ed25519

FIXTURE_PATH = Path(__file__).parent / "fixtures" / "cose" / "sign1-build.json"
CORPUS: dict[str, Any] = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
CARDANO_POE_VECTORS: list[dict[str, Any]] = CORPUS["cardano_poe_vectors"]


def _build_hashed_mode_cose(
    *, signer_pubkey: bytes, seed: bytes, record_body_cbor: bytes
) -> tuple[bytes, bytes]:
    protected_header: dict[int | str, object] = {1: -8, 4: signer_pubkey}
    protected_bytes = encode_canonical_cbor(cast(CanonicalCborValue, protected_header))
    to_sign = CARDANO_POE_SIG_DOMAIN_PREFIX + record_body_cbor
    hashed = hashlib.blake2b(to_sign, digest_size=28).digest()
    sig_struct = build_sig_structure(
        context="Signature1",
        body_protected_bytes=protected_bytes,
        external_aad=b"",
        payload=hashed,
    )
    sig = sign_ed25519(seed, sig_struct)
    cose_bytes = encode_cose_sign1(
        protected_header=protected_header,
        unprotected_header={"hashed": True},
        payload=None,
        signature=sig,
    )
    return cose_bytes, sig_struct


@pytest.mark.parametrize("vector", CARDANO_POE_VECTORS, ids=lambda v: cast(str, v["name"]))
def test_accepts_valid_hashed_mode_cose(vector: dict[str, Any]) -> None:
    record_body_cbor = bytes.fromhex(vector["record_body_cbor_hex"])
    cose_bytes, _ = _build_hashed_mode_cose(
        signer_pubkey=bytes.fromhex(vector["signer_public_key_hex"]),
        seed=bytes.fromhex(vector["signer_secret_key_hex"]),
        record_body_cbor=record_body_cbor,
    )
    result = cose_sign1_cip309_verify(
        message=cose_bytes, detached_record_body_cbor=record_body_cbor
    )
    assert result["ok"] is True


@pytest.mark.parametrize("vector", CARDANO_POE_VECTORS, ids=lambda v: cast(str, v["name"]))
def test_rejects_hashed_mode_with_flag_removed(vector: dict[str, Any]) -> None:
    record_body_cbor = bytes.fromhex(vector["record_body_cbor_hex"])
    signer_pubkey = bytes.fromhex(vector["signer_public_key_hex"])
    seed = bytes.fromhex(vector["signer_secret_key_hex"])
    _, sig_struct = _build_hashed_mode_cose(
        signer_pubkey=signer_pubkey, seed=seed, record_body_cbor=record_body_cbor
    )
    sig = sign_ed25519(seed, sig_struct)
    protected_header: dict[int | str, object] = {1: -8, 4: signer_pubkey}
    stripped_cose = encode_cose_sign1(
        protected_header=protected_header,
        unprotected_header={},
        payload=None,
        signature=sig,
    )
    result = cose_sign1_cip309_verify(
        message=stripped_cose, detached_record_body_cbor=record_body_cbor
    )
    assert result["ok"] is False
    assert result["error"]["code"] == "SIGNATURE_INVALID"


@pytest.mark.parametrize("vector", CARDANO_POE_VECTORS, ids=lambda v: cast(str, v["name"]))
def test_rejects_wrong_signature(vector: dict[str, Any]) -> None:
    record_body_cbor = bytes.fromhex(vector["record_body_cbor_hex"])
    signer_pubkey = bytes.fromhex(vector["signer_public_key_hex"])
    protected_header: dict[int | str, object] = {1: -8, 4: signer_pubkey}
    bogus_sig = b"\xab" * 64
    cose_bytes = encode_cose_sign1(
        protected_header=protected_header,
        unprotected_header={"hashed": True},
        payload=None,
        signature=bogus_sig,
    )
    result = cose_sign1_cip309_verify(
        message=cose_bytes, detached_record_body_cbor=record_body_cbor
    )
    assert result["ok"] is False
    assert result["error"]["code"] == "SIGNATURE_INVALID"


@pytest.mark.parametrize("vector", CARDANO_POE_VECTORS, ids=lambda v: cast(str, v["name"]))
def test_non_hashed_path_unchanged(vector: dict[str, Any]) -> None:
    """Regression: when the flag is absent the verifier behaves identically to before."""
    record_body_cbor = bytes.fromhex(vector["record_body_cbor_hex"])
    signer_pubkey = bytes.fromhex(vector["signer_public_key_hex"])
    seed = bytes.fromhex(vector["signer_secret_key_hex"])
    protected_header: dict[int | str, object] = {1: -8, 4: signer_pubkey}
    protected_bytes = encode_canonical_cbor(cast(CanonicalCborValue, protected_header))
    sig_struct = build_cip309_sig_structure(
        body_protected_bytes=protected_bytes,
        record_body_cbor=record_body_cbor,
    )
    sig = sign_ed25519(seed, sig_struct)
    cose_bytes = encode_cose_sign1(
        protected_header=protected_header,
        unprotected_header={},
        payload=None,
        signature=sig,
    )
    result = cose_sign1_cip309_verify(
        message=cose_bytes, detached_record_body_cbor=record_body_cbor
    )
    assert result["ok"] is True
