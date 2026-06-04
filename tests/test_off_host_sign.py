"""Off-host signing helper KAT + round-trip + negative tests.

Python parity twin of the off-host helper test surface in the
@cardanowall/sdk-ts client. Loads the byte-identical fixture mirror at
`tests/fixtures/cose/sign1-build.json` enforced by the
cross-language parity gate.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
from pathlib import Path
from typing import Any, cast

import pytest

from cardanowall._crypto.cbor import (
    CanonicalCborValue,
    decode_canonical_cbor,
    encode_canonical_cbor,
)
from cardanowall._crypto.cose_sign1 import (
    build_label309_sig_structure,
    build_sig_structure,
    decode_cose_sign1,
    encode_cose_sign1,
)
from cardanowall._crypto.sig import get_public_key_ed25519, sign_ed25519
from cardanowall.client import (
    OffHostSignError,
    assemble_cose_sign1,
    assemble_cose_sign1_hashed,
    build_to_sign,
    prepare_sig_structure,
    prepare_sig_structure_hashed,
)
from cardanowall.poe_standard import PoeRecord, chunk_bytes, encode_record_body_for_signing
from cardanowall.verifier import VerifyTxInput, verify_record_signatures

FIXTURE_PATH = Path(__file__).parent / "fixtures" / "cose" / "sign1-build.json"
CORPUS: dict[str, Any] = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
CARDANO_POE_VECTORS: list[dict[str, Any]] = CORPUS["cardano_poe_vectors"]

DOMAIN_PREFIX_HEX = "63617264616e6f2d706f652d7265636f72642d7369672d7631"


def _record_from_vector(vector: dict[str, Any]) -> PoeRecord:
    decoded = decode_canonical_cbor(bytes.fromhex(vector["record_body_cbor_hex"]))
    assert isinstance(decoded, dict)
    return cast(PoeRecord, decoded)


# ---------------------------------------------------------------------------
# Byte-pin against sign1-build.json::cardano_poe_vectors
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("vector", CARDANO_POE_VECTORS, ids=lambda v: cast(str, v["name"]))
def test_build_to_sign_byte_pin(vector: dict[str, Any]) -> None:
    record = _record_from_vector(vector)
    out = build_to_sign(record)
    assert out.hex() == DOMAIN_PREFIX_HEX + vector["record_body_cbor_hex"]
    assert out[:25].hex() == DOMAIN_PREFIX_HEX


@pytest.mark.parametrize("vector", CARDANO_POE_VECTORS, ids=lambda v: cast(str, v["name"]))
def test_prepare_sig_structure_byte_pin(vector: dict[str, Any]) -> None:
    record = _record_from_vector(vector)
    signer_pubkey = bytes.fromhex(vector["signer_public_key_hex"])
    sig_structure_bytes, protected_header_bytes = prepare_sig_structure(
        record=record, signer_pubkey=signer_pubkey
    )
    assert sig_structure_bytes.hex() == vector["expected_sig_structure_hex"]
    expected_protected_hex = "a2012704582 0".replace(" ", "") + vector["signer_public_key_hex"]
    assert protected_header_bytes.hex() == expected_protected_hex
    assert len(protected_header_bytes) == 38


@pytest.mark.parametrize("vector", CARDANO_POE_VECTORS, ids=lambda v: cast(str, v["name"]))
def test_signed_sig_structure_matches_kat_signature(vector: dict[str, Any]) -> None:
    record = _record_from_vector(vector)
    signer_pubkey = bytes.fromhex(vector["signer_public_key_hex"])
    seed = bytes.fromhex(vector["signer_secret_key_hex"])
    sig_structure_bytes, _ = prepare_sig_structure(record=record, signer_pubkey=signer_pubkey)
    sig = sign_ed25519(seed, sig_structure_bytes)
    assert sig.hex() == vector["expected_signature_hex"]


@pytest.mark.parametrize("vector", CARDANO_POE_VECTORS, ids=lambda v: cast(str, v["name"]))
def test_assemble_cose_sign1_byte_pin(vector: dict[str, Any]) -> None:
    record = _record_from_vector(vector)
    signer_pubkey = bytes.fromhex(vector["signer_public_key_hex"])
    seed = bytes.fromhex(vector["signer_secret_key_hex"])
    sig_structure_bytes, _ = prepare_sig_structure(record=record, signer_pubkey=signer_pubkey)
    sig = sign_ed25519(seed, sig_structure_bytes)
    cose_sign1_bytes, sig_entry = assemble_cose_sign1(
        record=record, signer_pubkey=signer_pubkey, signature=sig
    )
    assert cose_sign1_bytes.hex() == vector["expected_cose_sign1_hex"]
    if "expected_sigs_entry_cbor_hex" in vector:
        entry_cbor = encode_canonical_cbor(cast(CanonicalCborValue, sig_entry))
        assert entry_cbor.hex() == vector["expected_sigs_entry_cbor_hex"]
    if "expected_cose_sign1_chunks_hex" in vector:
        actual_chunks = [c.hex() for c in sig_entry["cose_sign1"]]
        assert actual_chunks == vector["expected_cose_sign1_chunks_hex"]


# ---------------------------------------------------------------------------
# Round-trip through verify_record_signatures
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("vector", CARDANO_POE_VECTORS, ids=lambda v: cast(str, v["name"]))
def test_verifier_round_trip(vector: dict[str, Any]) -> None:
    record = _record_from_vector(vector)
    signer_pubkey = bytes.fromhex(vector["signer_public_key_hex"])
    seed = bytes.fromhex(vector["signer_secret_key_hex"])
    sig_structure_bytes, _ = prepare_sig_structure(record=record, signer_pubkey=signer_pubkey)
    sig = sign_ed25519(seed, sig_structure_bytes)
    _, sig_entry = assemble_cose_sign1(record=record, signer_pubkey=signer_pubkey, signature=sig)
    completed_record = cast(PoeRecord, {**record, "sigs": [sig_entry]})
    out = asyncio.run(verify_record_signatures(completed_record, VerifyTxInput(tx_hash="00" * 32)))
    assert len(out) == 1
    assert out[0].verdict == "valid"
    assert out[0].signer_type == "in-signature-kid"
    assert out[0].signer_pub == vector["signer_public_key_hex"]
    assert out[0].reason is None


# ---------------------------------------------------------------------------
# Byte equivalence with the in-process signer (inline reconstruction)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("vector", CARDANO_POE_VECTORS, ids=lambda v: cast(str, v["name"]))
def test_in_process_byte_equivalence(vector: dict[str, Any]) -> None:
    record = _record_from_vector(vector)
    seed = bytes.fromhex(vector["signer_secret_key_hex"])
    pub = get_public_key_ed25519(seed)
    assert pub.hex() == vector["signer_public_key_hex"]

    # In-process reconstruction via the primitive layer (no server-side
    # equivalent in Python; mirrors the TS inline form): build protected_bytes →
    # build_label309_sig_structure → sign → encode_cose_sign1 → chunk_bytes.
    protected_header: dict[int | str, object] = {1: -8, 4: pub}
    protected_bytes = encode_canonical_cbor(cast(CanonicalCborValue, protected_header))
    sig_struct_in_proc = build_label309_sig_structure(
        body_protected_bytes=protected_bytes,
        record_body_cbor=encode_record_body_for_signing(record),
    )
    sig_in_proc = sign_ed25519(seed, sig_struct_in_proc)
    cose_in_proc = encode_cose_sign1(
        protected_header=protected_header,
        unprotected_header={},
        payload=None,
        signature=sig_in_proc,
    )
    chunks_in_proc = chunk_bytes(cose_in_proc)

    sig_structure_bytes, _ = prepare_sig_structure(record=record, signer_pubkey=pub)
    sig = sign_ed25519(seed, sig_structure_bytes)
    _, sig_entry = assemble_cose_sign1(record=record, signer_pubkey=pub, signature=sig)

    assert [c.hex() for c in sig_entry["cose_sign1"]] == [c.hex() for c in chunks_in_proc]


# ---------------------------------------------------------------------------
# Hashed-mode round-trip
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("vector", CARDANO_POE_VECTORS, ids=lambda v: cast(str, v["name"]))
def test_hashed_mode_byte_pin(vector: dict[str, Any]) -> None:
    record = _record_from_vector(vector)
    signer_pubkey = bytes.fromhex(vector["signer_public_key_hex"])
    seed = bytes.fromhex(vector["signer_secret_key_hex"])

    to_sign = build_to_sign(record)
    expected_hash = hashlib.blake2b(to_sign, digest_size=28).digest()
    sig_struct, protected_bytes, to_sign_hash = prepare_sig_structure_hashed(
        record=record, signer_pubkey=signer_pubkey
    )
    assert to_sign_hash == expected_hash
    assert len(to_sign_hash) == 28

    # Sig_structure[3] is the 28-byte hash; verify via independent build.
    expected_sig_struct = build_sig_structure(
        context="Signature1",
        body_protected_bytes=protected_bytes,
        external_aad=b"",
        payload=expected_hash,
    )
    assert sig_struct == expected_sig_struct

    sig = sign_ed25519(seed, sig_struct)
    cose_bytes, sig_entry = assemble_cose_sign1_hashed(
        record=record, signer_pubkey=signer_pubkey, signature=sig
    )
    decoded = decode_cose_sign1(cose_bytes)
    assert decoded["unprotected_header"].get("hashed") is True
    assert decoded["payload"] is None
    assert len(decoded["signature"]) == 64

    # Round-trip through the SDK verifier.
    completed = cast(PoeRecord, {**record, "sigs": [sig_entry]})
    out = asyncio.run(verify_record_signatures(completed, VerifyTxInput(tx_hash="00" * 32)))
    assert out[0].verdict == "valid"
    assert out[0].signer_type == "in-signature-kid"
    assert out[0].signer_pub == vector["signer_public_key_hex"]


@pytest.mark.parametrize("vector", CARDANO_POE_VECTORS, ids=lambda v: cast(str, v["name"]))
def test_hashed_signature_differs_from_non_hashed(vector: dict[str, Any]) -> None:
    record = _record_from_vector(vector)
    signer_pubkey = bytes.fromhex(vector["signer_public_key_hex"])
    seed = bytes.fromhex(vector["signer_secret_key_hex"])
    non_hashed, _ = prepare_sig_structure(record=record, signer_pubkey=signer_pubkey)
    hashed, _, _ = prepare_sig_structure_hashed(record=record, signer_pubkey=signer_pubkey)
    sig_non_hashed = sign_ed25519(seed, non_hashed)
    sig_hashed = sign_ed25519(seed, hashed)
    assert sig_non_hashed != sig_hashed
    assert sig_non_hashed.hex() == vector["expected_signature_hex"]


# ---------------------------------------------------------------------------
# Input-validation boundary surfaces OffHostSignError
# ---------------------------------------------------------------------------


def test_invalid_pubkey_length_raises_in_prepare() -> None:
    record = _record_from_vector(CARDANO_POE_VECTORS[0])
    with pytest.raises(OffHostSignError) as exc:
        prepare_sig_structure(record=record, signer_pubkey=b"\x00" * 31)
    assert exc.value.code == OffHostSignError.INVALID_PUBKEY_LENGTH


def test_invalid_pubkey_length_raises_in_assemble() -> None:
    record = _record_from_vector(CARDANO_POE_VECTORS[0])
    with pytest.raises(OffHostSignError) as exc:
        assemble_cose_sign1(record=record, signer_pubkey=b"\x00" * 31, signature=b"\x00" * 64)
    assert exc.value.code == OffHostSignError.INVALID_PUBKEY_LENGTH


def test_invalid_signature_length_raises() -> None:
    record = _record_from_vector(CARDANO_POE_VECTORS[0])
    signer_pubkey = bytes.fromhex(CARDANO_POE_VECTORS[0]["signer_public_key_hex"])
    with pytest.raises(OffHostSignError) as exc:
        assemble_cose_sign1(record=record, signer_pubkey=signer_pubkey, signature=b"\x00" * 63)
    assert exc.value.code == OffHostSignError.INVALID_SIGNATURE_LENGTH


def test_invalid_inputs_on_hashed_helpers() -> None:
    record = _record_from_vector(CARDANO_POE_VECTORS[0])
    signer_pubkey = bytes.fromhex(CARDANO_POE_VECTORS[0]["signer_public_key_hex"])
    with pytest.raises(OffHostSignError) as exc_pub:
        prepare_sig_structure_hashed(record=record, signer_pubkey=b"\x00" * 31)
    assert exc_pub.value.code == OffHostSignError.INVALID_PUBKEY_LENGTH
    with pytest.raises(OffHostSignError) as exc_sig:
        assemble_cose_sign1_hashed(
            record=record, signer_pubkey=signer_pubkey, signature=b"\x00" * 63
        )
    assert exc_sig.value.code == OffHostSignError.INVALID_SIGNATURE_LENGTH


def test_off_host_sign_error_is_exception() -> None:
    err = OffHostSignError(OffHostSignError.INVALID_PUBKEY_LENGTH, "bad")
    assert isinstance(err, Exception)
    assert err.code == OffHostSignError.INVALID_PUBKEY_LENGTH
    assert str(err) == "INVALID_PUBKEY_LENGTH: bad"
