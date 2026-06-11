"""Behavioral KAT for the raw-seed identity surface.

Parity twin of the sdk-ts ``identity/seed-identity`` tests. Pins:

  * seed -> keys: the three derived pubkeys against the seed-derive fixtures;
  * seed -> recipient strings: the ``age`` / ``age1pqc`` strings against the
    shared cross-language fixture (the load-bearing byte-parity claim);
  * seed -> sign -> verify: a path-1 signer round-trips through Ed25519 verify
    and produces a ``Signer`` accepted by the publish helpers;
  * seed -> decrypt HYBRID: a closed X-Wing wrap/decrypt round-trip plus a
    wrong-seed negative.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, cast

import pytest

from cardanowall import (
    decrypt_sealed_from_seed,
    derive_keys_from_seed,
    recipient_secret_keys_from_seed,
    recipients_from_seed,
    signer_from_seed,
)
from cardanowall._crypto.sealed_poe import ecies_sealed_poe_wrap
from cardanowall._crypto.sig import verify_ed25519
from cardanowall.client.publish import Signer
from cardanowall.poe_standard import PoeRecord
from cardanowall.recipient import encode_age_x25519_recipient, encode_age_xwing_recipient
from cardanowall.seed_identity import SeedSigner

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "seed-derive"
COSE_FIXTURE = Path(__file__).parent / "fixtures" / "cose" / "sign1-build.json"

SEED_ZERO = bytes(32)
SEED_FF = b"\xff" * 32
SEED_DEADBEEF = bytes.fromhex("deadbeef" * 8)


def _load_vectors(name: str) -> list[dict[str, Any]]:
    data = json.loads((FIXTURES_DIR / name).read_text())
    return cast(list[dict[str, Any]], data["vectors"])


def _seed_derive_vector(name: str) -> dict[str, Any]:
    # Each seed-from-*.json corpus is a single vector for that seed.
    return _load_vectors(f"seed-from-{name}.json")[0]


def _recipients_vector(seed_name: str) -> dict[str, Any]:
    for vector in _load_vectors("recipients.json"):
        if vector["name"] == seed_name:
            return vector
    raise AssertionError(f"no recipients fixture vector named {seed_name!r}")


# ---------------------------------------------------------------------------
# (1) seed -> keys
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("seed_name", ["zero", "ff", "deadbeef"])
def test_derive_keys_from_seed_matches_seed_derive_fixtures(seed_name: str) -> None:
    seed = {"zero": SEED_ZERO, "ff": SEED_FF, "deadbeef": SEED_DEADBEEF}[seed_name]
    vector = _seed_derive_vector(seed_name)
    keys = derive_keys_from_seed(seed)

    assert keys["ed25519"]["secret_key"].hex() == vector["expected_ed25519_secret_hex"]
    assert keys["ed25519"]["public_key"].hex() == vector["expected_ed25519_public_hex"]
    assert keys["x25519"]["secret_key"].hex() == vector["expected_x25519_secret_hex"]
    assert keys["x25519"]["public_key"].hex() == vector["expected_x25519_public_hex"]
    assert (
        keys["mlkem768x25519"]["secret_seed"].hex()
        == vector["expected_mlkem768x25519_secret_seed_hex"]
    )
    assert (
        keys["mlkem768x25519"]["public_key"].hex()
        == vector["expected_mlkem768x25519_public_key_hex"]
    )
    # The X-Wing public key is exactly 1216 bytes; the X25519 keys are 32.
    assert len(keys["mlkem768x25519"]["public_key"]) == 1216
    assert len(keys["x25519"]["public_key"]) == 32
    assert len(keys["ed25519"]["public_key"]) == 32


# ---------------------------------------------------------------------------
# (2) seed -> recipient strings (cross-language byte-parity)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("seed_name", ["zero", "ff", "deadbeef"])
def test_recipients_from_seed_pin_cross_language_strings(seed_name: str) -> None:
    seed = {"zero": SEED_ZERO, "ff": SEED_FF, "deadbeef": SEED_DEADBEEF}[seed_name]
    vector = _recipients_vector(seed_name)
    recipients = recipients_from_seed(seed)

    # Exact match against the strings the @cardanowall/crypto-core codec emits —
    # a sender in either language addresses this identity with the same bytes.
    assert recipients["age"] == vector["age"]
    assert recipients["age"].startswith("age1")
    assert len(recipients["age"]) == 62

    assert recipients["age1pqc"].startswith(vector["age1pqc_prefix"])
    assert recipients["age1pqc"].startswith("age1pqc1")
    assert len(recipients["age1pqc"]) == 1960


def test_recipients_seed_free_codec_matches_helper() -> None:
    # The seed-free codec and the seed helper produce identical strings.
    keys = derive_keys_from_seed(SEED_ZERO)
    helper = recipients_from_seed(SEED_ZERO)
    assert encode_age_x25519_recipient(keys["x25519"]["public_key"]) == helper["age"]
    assert encode_age_xwing_recipient(keys["mlkem768x25519"]["public_key"]) == helper["age1pqc"]


# ---------------------------------------------------------------------------
# (3) seed -> sign -> verify round-trip (path-1)
# ---------------------------------------------------------------------------


def _sample_record() -> PoeRecord:
    from cardanowall._crypto.cbor import decode_canonical_cbor

    corpus = json.loads(COSE_FIXTURE.read_text())
    body_hex = corpus["cardano_poe_vectors"][0]["record_body_cbor_hex"]
    decoded = decode_canonical_cbor(bytes.fromhex(body_hex))
    assert isinstance(decoded, dict)
    return cast(PoeRecord, decoded)


@pytest.mark.parametrize("seed_name", ["zero", "ff", "deadbeef"])
def test_signer_from_seed_round_trips_through_ed25519_verify(seed_name: str) -> None:
    from cardanowall.client import prepare_sig_structure

    seed = {"zero": SEED_ZERO, "ff": SEED_FF, "deadbeef": SEED_DEADBEEF}[seed_name]
    vector = _seed_derive_vector(seed_name)
    signer = signer_from_seed(seed)

    assert signer.signer_pubkey.hex() == vector["expected_ed25519_public_hex"]

    record = _sample_record()
    sig_structure_bytes, _protected = prepare_sig_structure(
        record=record, signer_pubkey=signer.signer_pubkey
    )
    signature = signer.sign(sig_structure_bytes)
    assert len(signature) == 64
    assert verify_ed25519(signer.signer_pubkey, sig_structure_bytes, signature) is True

    # A signature over different bytes must NOT verify (guards against a
    # signer that ignores its message argument).
    tampered = bytes([sig_structure_bytes[0] ^ 0x01]) + sig_structure_bytes[1:]
    assert verify_ed25519(signer.signer_pubkey, tampered, signature) is False


def test_signer_from_seed_satisfies_publish_signer_protocol() -> None:
    signer = signer_from_seed(SEED_ZERO)
    # runtime_checkable Signer protocol — the publish helpers accept this object.
    assert isinstance(signer, Signer)
    assert isinstance(signer, SeedSigner)
    assert isinstance(signer.signer_pubkey, bytes)
    assert len(signer.signer_pubkey) == 32


# ---------------------------------------------------------------------------
# (4) seed -> decrypt HYBRID (mlkem768x25519)
# ---------------------------------------------------------------------------


def test_decrypt_sealed_from_seed_hybrid_round_trip() -> None:
    keys = derive_keys_from_seed(SEED_ZERO)
    xwing_pub = keys["mlkem768x25519"]["public_key"]
    plaintext = b"sealed hybrid payload for the all-zero seed identity"

    hashes = {"sha2-256": hashlib.sha256(plaintext).digest()}
    sealed = ecies_sealed_poe_wrap(
        plaintext=plaintext,
        recipient_public_keys=[xwing_pub],
        hashes=hashes,
        kem="mlkem768x25519",
    )
    assert sealed.envelope.kem == "mlkem768x25519"

    result = decrypt_sealed_from_seed(
        seed=SEED_ZERO, envelope=sealed.envelope, ciphertext=sealed.ciphertext, hashes=hashes
    )
    assert result.matched is True
    assert result.plaintext == plaintext
    assert result.reason is None


def test_decrypt_sealed_from_seed_hybrid_wrong_seed_does_not_match() -> None:
    keys = derive_keys_from_seed(SEED_ZERO)
    xwing_pub = keys["mlkem768x25519"]["public_key"]
    hashes = {"sha2-256": hashlib.sha256(b"only the zero seed can open this").digest()}
    sealed = ecies_sealed_poe_wrap(
        plaintext=b"only the zero seed can open this",
        recipient_public_keys=[xwing_pub],
        hashes=hashes,
        kem="mlkem768x25519",
    )

    result = decrypt_sealed_from_seed(
        seed=SEED_FF, envelope=sealed.envelope, ciphertext=sealed.ciphertext, hashes=hashes
    )
    assert result.matched is False
    assert result.plaintext is None
    assert result.reason == "WRONG_RECIPIENT_KEY"


def test_decrypt_sealed_from_seed_classical_x25519_round_trip() -> None:
    # decrypt_sealed_from_seed routes by envelope.kem; cover the x25519 branch
    # too so the dispatch is exercised on both KEMs.
    keys = derive_keys_from_seed(SEED_DEADBEEF)
    x_pub = keys["x25519"]["public_key"]
    plaintext = b"classical x25519 sealed payload"

    hashes = {"sha2-256": hashlib.sha256(plaintext).digest()}
    sealed = ecies_sealed_poe_wrap(
        plaintext=plaintext,
        recipient_public_keys=[x_pub],
        hashes=hashes,
        kem="x25519",
    )
    assert sealed.envelope.kem == "x25519"

    result = decrypt_sealed_from_seed(
        seed=SEED_DEADBEEF, envelope=sealed.envelope, ciphertext=sealed.ciphertext, hashes=hashes
    )
    assert result.matched is True
    assert result.plaintext == plaintext


# ---------------------------------------------------------------------------
# recipient_secret_keys_from_seed — the per-KEM secret lists
# ---------------------------------------------------------------------------


def test_recipient_secret_keys_from_seed_shape() -> None:
    keys = derive_keys_from_seed(SEED_ZERO)
    bundle = recipient_secret_keys_from_seed(SEED_ZERO)
    assert bundle["x25519"] == [keys["x25519"]["secret_key"]]
    assert bundle["mlkem768x25519"] == [keys["mlkem768x25519"]["secret_seed"]]
    # X25519 private key is 32 bytes; the X-Wing secret IS the 32-byte seed.
    assert len(bundle["x25519"][0]) == 32
    assert len(bundle["mlkem768x25519"][0]) == 32
