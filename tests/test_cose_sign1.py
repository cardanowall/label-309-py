from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

import pytest

from cardanowall._crypto.cbor import encode_canonical_cbor
from cardanowall._crypto.cose_sign1 import (
    CARDANO_POE_SIG_DOMAIN_PREFIX,
    CoseSign1BuildError,
    build_label309_sig_structure,
    build_sig_structure,
    cose_sign1_build,
    cose_sign1_label309_build,
    cose_sign1_label309_verify,
    cose_sign1_verify,
)
from cardanowall._crypto.sig import sign_ed25519

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "cose"


def _load_corpus(name: str) -> list[dict[str, Any]]:
    data = json.loads((FIXTURES_DIR / name).read_text())
    return cast(list[dict[str, Any]], data["vectors"])


def test_cose_sign1_build_kat() -> None:
    vectors = _load_corpus("sign1-build.json")
    assert len(vectors) > 0
    for vector in vectors:
        protected_header: dict[int | str, object] = {
            int(k): int(v) for k, v in vector["protected_header_int_pairs"]
        }
        unprotected_header: dict[int | str, object] = {
            int(k): bytes.fromhex(str(v_hex))
            for k, v_hex in vector["unprotected_header_int_bytes_pairs"]
        }
        result = cose_sign1_build(
            protected_header=protected_header,
            unprotected_header=unprotected_header,
            payload=bytes.fromhex(str(vector["payload_hex"])),
            external_aad=bytes.fromhex(str(vector["external_aad_hex"])),
            signer_secret_key=bytes.fromhex(str(vector["signer_secret_key_hex"])),
            detached=bool(vector["detached"]),
        )
        assert result.hex() == vector["expected_cose_sign1_hex"], (
            f"{vector['name']}: COSE_Sign1 byte mismatch"
        )


def test_sig_structure_kat() -> None:
    vectors = _load_corpus("sig-structure.json")
    assert len(vectors) > 0
    for vector in vectors:
        result = build_sig_structure(
            context="Signature1",
            body_protected_bytes=bytes.fromhex(str(vector["body_protected_bytes_hex"])),
            external_aad=bytes.fromhex(str(vector["external_aad_hex"])),
            payload=bytes.fromhex(str(vector["payload_hex"])),
        )
        assert result.hex() == vector["expected_sig_structure_hex"], (
            f"{vector['name']}: Sig_structure byte mismatch"
        )


def test_cose_sign1_verify_corpus() -> None:
    vectors = _load_corpus("sign1-verify.json")
    assert len(vectors) > 0
    for vector in vectors:
        kwargs: dict[str, Any] = {
            "message": bytes.fromhex(str(vector["message_hex"])),
            "external_aad": bytes.fromhex(str(vector["external_aad_hex"])),
        }
        if "expected_signer_key_hex" in vector:
            kwargs["expected_signer_key"] = bytes.fromhex(str(vector["expected_signer_key_hex"]))
        if "detached_payload_hex" in vector:
            kwargs["detached_payload"] = bytes.fromhex(str(vector["detached_payload_hex"]))
        result = cose_sign1_verify(**kwargs)
        expected = vector["expected_result"]
        if expected["ok"]:
            assert result["ok"] is True, f"{vector['name']}: expected ok=True"
            if "signer_key_hex" in expected:
                assert result["signer_key"].hex() == expected["signer_key_hex"]
            if "alg" in expected:
                assert result["alg"] == expected["alg"]
        else:
            assert result["ok"] is False, f"{vector['name']}: expected ok=False"
            assert result["error"]["code"] == expected["error_code"]


def test_cose_sign1_strict_ed25519_low_order() -> None:
    vectors = _load_corpus("sign1-strict-ed25519.json")
    assert len(vectors) >= 1
    for vector in vectors:
        result = cose_sign1_verify(
            message=bytes.fromhex(str(vector["message_hex"])),
            external_aad=bytes.fromhex(str(vector["external_aad_hex"])),
        )
        assert result["ok"] is False, f"{vector['name']}: strict mode MUST reject low-order key"
        assert result["error"]["code"] == "SIGNATURE_INVALID"


# ---------------------------------------------------------------------------
# Label 309 v1 record-signature parity.
# Vectors live under sign1-build.json → cardano_poe_vectors (mirrored byte-
# identically with the TS canonical tree).
# ---------------------------------------------------------------------------


def _label309_vectors() -> list[dict[str, Any]]:
    data = json.loads((FIXTURES_DIR / "sign1-build.json").read_text())
    return cast(list[dict[str, Any]], data["cardano_poe_vectors"])


LABEL309_VECTORS = _label309_vectors()


def test_label309_domain_prefix_pinned() -> None:
    assert CARDANO_POE_SIG_DOMAIN_PREFIX == b"cardano-poe-record-sig-v1"
    assert len(CARDANO_POE_SIG_DOMAIN_PREFIX) == 25
    assert (
        CARDANO_POE_SIG_DOMAIN_PREFIX.hex() == "63617264616e6f2d706f652d7265636f72642d7369672d7631"
    )


def _protected_header_for(vector: dict[str, Any]) -> dict[int | str, object]:
    h: dict[int | str, object] = {}
    for k, v in vector.get("protected_header_int_int_pairs", []):
        h[int(k)] = int(v)
    for k, v in vector.get("protected_header_int_bytes_pairs", []):
        h[int(k)] = bytes.fromhex(str(v))
    return h


@pytest.mark.parametrize("vector", LABEL309_VECTORS, ids=lambda v: cast(str, v["name"]))
def test_cose_sign1_label309_build_matches_kat(vector: dict[str, Any]) -> None:
    cose = cose_sign1_label309_build(
        protected_header=_protected_header_for(vector),
        unprotected_header={},
        record_body_cbor=bytes.fromhex(vector["record_body_cbor_hex"]),
        signer_secret_key=bytes.fromhex(vector["signer_secret_key_hex"]),
    )
    assert cose.hex() == vector["expected_cose_sign1_hex"], vector["name"]


@pytest.mark.parametrize("vector", LABEL309_VECTORS, ids=lambda v: cast(str, v["name"]))
def test_build_label309_sig_structure_matches_kat(vector: dict[str, Any]) -> None:
    protected_bytes = encode_canonical_cbor(cast(Any, _protected_header_for(vector)))
    sig_structure = build_label309_sig_structure(
        body_protected_bytes=protected_bytes,
        record_body_cbor=bytes.fromhex(vector["record_body_cbor_hex"]),
    )
    assert sig_structure.hex() == vector["expected_sig_structure_hex"], vector["name"]


@pytest.mark.parametrize("vector", LABEL309_VECTORS, ids=lambda v: cast(str, v["name"]))
def test_cose_sign1_label309_verify_round_trip(vector: dict[str, Any]) -> None:
    if "expected_cose_sign1_hex" not in vector:
        pytest.skip("legacy vector without expected COSE_Sign1 hex")
    result = cose_sign1_label309_verify(
        message=bytes.fromhex(vector["expected_cose_sign1_hex"]),
        detached_record_body_cbor=bytes.fromhex(vector["record_body_cbor_hex"]),
    )
    assert result["ok"] is True, vector["name"]
    assert result["signer_key"].hex() == vector["signer_public_key_hex"]
    assert result["alg"] == -8


@pytest.mark.parametrize("vector", LABEL309_VECTORS, ids=lambda v: cast(str, v["name"]))
def test_cose_sign1_label309_verify_rejects_mutated_body(vector: dict[str, Any]) -> None:
    mutated = bytearray(bytes.fromhex(vector["record_body_cbor_hex"]))
    mutated[-1] ^= 0xFF
    result = cose_sign1_label309_verify(
        message=bytes.fromhex(vector["expected_cose_sign1_hex"]),
        detached_record_body_cbor=bytes(mutated),
    )
    assert result["ok"] is False
    assert result["error"]["code"] == "SIGNATURE_INVALID"


def test_cose_sign1_label309_verify_rejects_attached_payload() -> None:
    """MALFORMED_SIG_COSE_SIGN1 on non-null COSE_Sign1[2] (even h'')."""
    vector = LABEL309_VECTORS[-1]
    protected_bytes = encode_canonical_cbor(cast(Any, _protected_header_for(vector)))
    sig_structure = build_label309_sig_structure(
        body_protected_bytes=protected_bytes,
        record_body_cbor=bytes.fromhex(vector["record_body_cbor_hex"]),
    )
    sig = sign_ed25519(bytes.fromhex(vector["signer_secret_key_hex"]), sig_structure)
    cose_attached = encode_canonical_cbor(cast(Any, [protected_bytes, {}, b"", sig]))
    result = cose_sign1_label309_verify(
        message=cose_attached,
        detached_record_body_cbor=bytes.fromhex(vector["record_body_cbor_hex"]),
    )
    assert result["ok"] is False
    assert result["error"]["code"] == "MALFORMED_SIG_COSE_SIGN1"


def test_cose_sign1_label309_build_via_signer_closure() -> None:
    """Composer-side signing path: caller injects a closure that never reveals
    the seed to the builder. Output MUST be byte-identical to the seed path."""
    vector = LABEL309_VECTORS[-1]
    seed = bytes.fromhex(vector["signer_secret_key_hex"])
    captured: list[bytes] = []

    def signer(sig_structure: bytes) -> bytes:
        captured.append(sig_structure)
        return sign_ed25519(seed, sig_structure)

    cose = cose_sign1_label309_build(
        protected_header=_protected_header_for(vector),
        unprotected_header={},
        record_body_cbor=bytes.fromhex(vector["record_body_cbor_hex"]),
        signer=signer,
    )
    assert cose.hex() == vector["expected_cose_sign1_hex"]
    assert len(captured) == 1
    assert captured[0].hex() == vector["expected_sig_structure_hex"]


def test_cose_sign1_label309_build_rejects_missing_signer() -> None:
    vector = LABEL309_VECTORS[-1]
    with pytest.raises(CoseSign1BuildError) as exc:
        cose_sign1_label309_build(
            protected_header=_protected_header_for(vector),
            unprotected_header={},
            record_body_cbor=bytes.fromhex(vector["record_body_cbor_hex"]),
        )
    assert exc.value.code == CoseSign1BuildError.SIGNER_NOT_PROVIDED


def test_cose_sign1_label309_build_rejects_both_signer_and_seed() -> None:
    vector = LABEL309_VECTORS[-1]
    with pytest.raises(CoseSign1BuildError) as exc:
        cose_sign1_label309_build(
            protected_header=_protected_header_for(vector),
            unprotected_header={},
            record_body_cbor=bytes.fromhex(vector["record_body_cbor_hex"]),
            signer_secret_key=bytes.fromhex(vector["signer_secret_key_hex"]),
            signer=lambda _b: b"\x00" * 64,
        )
    assert exc.value.code == CoseSign1BuildError.SIGNER_AND_SEED_BOTH_PROVIDED


@pytest.mark.parametrize(
    "vector",
    [v for v in LABEL309_VECTORS if "expected_sigs_entry_cbor_hex" in v],
    ids=lambda v: cast(str, v["name"]),
)
def test_sigs_entry_cbor_matches_kat(vector: dict[str, Any]) -> None:
    """The sigs[i] entry carries the COSE_Sign1 as a SINGLE byte string."""
    cose = bytes.fromhex(vector["expected_cose_sign1_hex"])
    sigs_entry = encode_canonical_cbor(cast(Any, {"cose_sign1": cose}))
    assert sigs_entry.hex() == vector["expected_sigs_entry_cbor_hex"], vector["name"]
