"""Python parity sibling of the TS cross-service interop test.

Loads the byte-stable cross-service fixture (produced by
cardanowall._tools.generate_cross_service_interop_fixture and mirrored across
the TS canonical + Python copies), validates its Label 309 record bytes via the
Python sibling of validatePoeRecord, and runs the Python sibling of
eciesSealedPoeTrialDecrypt against the pinned recipient secret. The
(slot_idx, cek) recovered MUST byte-match the values the TS integration test
asserts — that byte-identity is the cross-language parity invariant.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

import pytest

from cardanowall._crypto.sealed_poe import (
    TRIAL_DECRYPT_KIND_MATCH,
    SealedEnvelope,
    SealedSlot,
    ecies_sealed_poe_trial_decrypt,
)
from cardanowall.poe_standard import ValidateOk, validate

_FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures" / "cross-service"
_FIXTURE_PATH = _FIXTURE_DIR / "external-sealed-record.json"
_HYBRID_FIXTURE_PATH = _FIXTURE_DIR / "external-sealed-record-hybrid.json"


def _load_fixture_at(path: Path) -> dict[str, Any]:
    if not path.exists():
        pytest.skip(
            "cross-service-interop fixture missing — run: "
            "uv run python -m cardanowall._tools.generate_cross_service_interop_fixture"
        )
    return cast(dict[str, Any], json.loads(path.read_text(encoding="utf-8")))


def _load_fixture() -> dict[str, Any]:
    return _load_fixture_at(_FIXTURE_PATH)


def test_cross_service_interop_python_parity() -> None:
    fixture = _load_fixture()
    metadata_cbor = bytes.fromhex(fixture["record"]["metadata_cbor_hex"])

    # Same pre-trial validator the TS agent invokes.
    result = validate(metadata_cbor)
    assert isinstance(result, ValidateOk), f"validator rejected fixture: {result}"
    record = result.record

    items = record.get("items")
    assert items is not None and len(items) == 1
    item = items[0]
    enc_any = cast(dict[str, Any], item["enc"])
    slots = tuple(
        SealedSlot(epk=cast(bytes, s["epk"]), wrap=cast(bytes, s["wrap"]))
        for s in cast(list[dict[str, Any]], enc_any["slots"])
    )
    envelope = SealedEnvelope(
        scheme=cast(int, enc_any["scheme"]),
        aead=cast(str, enc_any["aead"]),
        kem=cast(str, enc_any["kem"]),
        nonce=cast(bytes, enc_any["nonce"]),
        slots=slots,
        slots_mac=cast(bytes, enc_any["slots_mac"]),
    )

    recipient_priv = bytes.fromhex(fixture["inputs"]["recipient_x25519_secret_key_hex"])
    trial = ecies_sealed_poe_trial_decrypt(
        envelope=envelope,
        hashes=dict(item["hashes"].items()),
        recipient_secret_keys=[recipient_priv],
    )

    expected = fixture["expected"]
    assert trial.kind == TRIAL_DECRYPT_KIND_MATCH
    assert trial.slot_idx == expected["matched_slot_idx"]
    assert trial.cek is not None
    assert trial.cek.hex() == expected["recovered_cek_hex"]


def test_cross_service_interop_python_parity_hybrid() -> None:
    """X-Wing hybrid sibling of the classical parity test.

    A Python-produced mlkem768x25519 record must validate, then trial-decrypt to
    the publisher's pinned CEK using the recipient's X-Wing secret seed — the
    same byte-identity invariant the TS CLI integration test asserts.
    """
    fixture = _load_fixture_at(_HYBRID_FIXTURE_PATH)
    metadata_cbor = bytes.fromhex(fixture["record"]["metadata_cbor_hex"])

    result = validate(metadata_cbor)
    assert isinstance(result, ValidateOk), f"validator rejected hybrid fixture: {result}"
    record = result.record

    items = record.get("items")
    assert items is not None and len(items) == 1
    enc_any = cast(dict[str, Any], items[0]["enc"])
    assert enc_any["kem"] == "mlkem768x25519"
    # Wire `kem_ct` is the single 1120-byte X-Wing ciphertext byte string.
    slots = tuple(
        SealedSlot(
            kem_ct=cast(bytes, s["kem_ct"]),
            wrap=cast(bytes, s["wrap"]),
        )
        for s in cast(list[dict[str, Any]], enc_any["slots"])
    )
    envelope = SealedEnvelope(
        scheme=cast(int, enc_any["scheme"]),
        aead=cast(str, enc_any["aead"]),
        kem=cast(str, enc_any["kem"]),
        nonce=cast(bytes, enc_any["nonce"]),
        slots=slots,
        slots_mac=cast(bytes, enc_any["slots_mac"]),
    )

    recipient_seed = bytes.fromhex(fixture["inputs"]["recipient_mlkem768x25519_secret_seed_hex"])
    trial = ecies_sealed_poe_trial_decrypt(
        envelope=envelope,
        hashes=dict(items[0]["hashes"].items()),
        recipient_secret_keys=[recipient_seed],
    )

    expected = fixture["expected"]
    assert trial.kind == TRIAL_DECRYPT_KIND_MATCH
    assert trial.slot_idx == expected["matched_slot_idx"]
    assert trial.cek is not None
    assert trial.cek.hex() == expected["recovered_cek_hex"]
