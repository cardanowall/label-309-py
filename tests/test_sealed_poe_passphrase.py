"""Behaviour tests for the sealed-PoE passphrase path: blob = commitment(32) ||
STREAM chunks, with the commitment verified in constant time before any chunk
opens, and every decryption failure collapsing to the single generic
TAMPERED_CIPHERTEXT outcome. Fixture KATs replay the pinned passphrase-n1 /
passphrase-negative vectors."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, cast

import pytest

from cardanowall._crypto.sealed_poe import (
    UNWRAP_REASON_TAMPERED_CIPHERTEXT,
    Argon2idParams,
    EciesSealedPoeError,
    PassphraseEnvelope,
    passphrase_sealed_poe_open,
    passphrase_sealed_poe_seal,
)

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "sealed-poe"

# Floor-valued Argon2id params: the construction enforces the registry floors
# (m >= 65536, t >= 3, p >= 1) at both seal and open, so this is the cheapest
# parameter set the public API accepts.
_PARAMS = Argon2idParams(m=65536, t=3, p=1)
_SALT = bytes((0x10 + i) & 0xFF for i in range(16))
_NONCE = bytes((0x20 + i) & 0xFF for i in range(24))


def _hashes(plaintext: bytes) -> dict[str, bytes]:
    return {"sha2-256": hashlib.sha256(plaintext).digest()}


def _seal(plaintext: bytes, passphrase: str = "correct horse battery staple") -> Any:
    return passphrase_sealed_poe_seal(
        plaintext=plaintext,
        passphrase=passphrase,
        hashes=_hashes(plaintext),
        params=_PARAMS,
        salt=_SALT,
        nonce=_NONCE,
    )


def test_roundtrip() -> None:
    plaintext = b"passphrase roundtrip"
    out = _seal(plaintext)
    assert out.envelope.scheme == 1
    assert out.envelope.aead == "chacha20-poly1305-stream64k"
    assert out.envelope.alg == "argon2id"
    # Blob = 32-byte commitment + STREAM (>= 16-byte floor).
    assert len(out.ciphertext) == 32 + len(plaintext) + 16
    res = passphrase_sealed_poe_open(
        envelope=out.envelope,
        ciphertext=out.ciphertext,
        passphrase="correct horse battery staple",
        hashes=_hashes(plaintext),
    )
    assert res.matched is True
    assert res.plaintext == plaintext


def test_normalization_equivalent_passphrases_derive_the_same_key() -> None:
    plaintext = b"normalization equivalence"
    out = _seal(plaintext, passphrase="ｐａｓｓ\u3000ｗｏｒｄ")  # noqa: RUF001
    # NFKC + whitespace collapse: the full-width spelling and the plain ASCII
    # spelling normalize to the same bytes, so either opens the blob.
    res = passphrase_sealed_poe_open(
        envelope=out.envelope,
        ciphertext=out.ciphertext,
        passphrase="pass word",
        hashes=_hashes(plaintext),
    )
    assert res.matched is True


def test_wrong_passphrase_is_the_single_generic_failure() -> None:
    plaintext = b"wrong passphrase probe"
    out = _seal(plaintext)
    res = passphrase_sealed_poe_open(
        envelope=out.envelope,
        ciphertext=out.ciphertext,
        passphrase="incorrect horse",
        hashes=_hashes(plaintext),
    )
    assert res.matched is False
    assert res.reason == UNWRAP_REASON_TAMPERED_CIPHERTEXT


def test_commitment_flip_fails_before_any_chunk() -> None:
    plaintext = b"commitment flip"
    out = _seal(plaintext)
    mutated = bytearray(out.ciphertext)
    mutated[0] ^= 0x01  # inside the 32-byte commitment header
    res = passphrase_sealed_poe_open(
        envelope=out.envelope,
        ciphertext=bytes(mutated),
        passphrase="correct horse battery staple",
        hashes=_hashes(plaintext),
    )
    assert res.matched is False
    assert res.reason == UNWRAP_REASON_TAMPERED_CIPHERTEXT


def test_stream_tamper_after_valid_commitment_fails() -> None:
    plaintext = b"stream tamper"
    out = _seal(plaintext)
    mutated = bytearray(out.ciphertext)
    mutated[-1] ^= 0x01  # final chunk tag
    res = passphrase_sealed_poe_open(
        envelope=out.envelope,
        ciphertext=bytes(mutated),
        passphrase="correct horse battery staple",
        hashes=_hashes(plaintext),
    )
    assert res.matched is False
    assert res.reason == UNWRAP_REASON_TAMPERED_CIPHERTEXT


def test_tampered_salt_and_params_fail_the_commitment() -> None:
    plaintext = b"transcript binding"
    out = _seal(plaintext)
    flipped_salt = PassphraseEnvelope(
        scheme=1,
        aead=out.envelope.aead,
        nonce=out.envelope.nonce,
        alg="argon2id",
        salt=bytes([out.envelope.salt[0] ^ 0x01]) + out.envelope.salt[1:],
        params=out.envelope.params,
    )
    res = passphrase_sealed_poe_open(
        envelope=flipped_salt,
        ciphertext=out.ciphertext,
        passphrase="correct horse battery staple",
        hashes=_hashes(plaintext),
    )
    assert res.matched is False and res.reason == UNWRAP_REASON_TAMPERED_CIPHERTEXT

    bumped_params = PassphraseEnvelope(
        scheme=1,
        aead=out.envelope.aead,
        nonce=out.envelope.nonce,
        alg="argon2id",
        salt=out.envelope.salt,
        params=Argon2idParams(m=_PARAMS.m, t=_PARAMS.t + 1, p=_PARAMS.p),
    )
    res2 = passphrase_sealed_poe_open(
        envelope=bumped_params,
        ciphertext=out.ciphertext,
        passphrase="correct horse battery staple",
        hashes=_hashes(plaintext),
    )
    assert res2.matched is False and res2.reason == UNWRAP_REASON_TAMPERED_CIPHERTEXT


def test_hashes_splice_fails_the_commitment() -> None:
    plaintext = b"hashes splice"
    out = _seal(plaintext)
    res = passphrase_sealed_poe_open(
        envelope=out.envelope,
        ciphertext=out.ciphertext,
        passphrase="correct horse battery staple",
        hashes=_hashes(b"a different claim"),
    )
    assert res.matched is False
    assert res.reason == UNWRAP_REASON_TAMPERED_CIPHERTEXT


def test_blob_below_the_48_byte_floor_is_tampered_ciphertext() -> None:
    plaintext = b"floor"
    out = _seal(plaintext)
    res = passphrase_sealed_poe_open(
        envelope=out.envelope,
        ciphertext=out.ciphertext[:47],
        passphrase="correct horse battery staple",
        hashes=_hashes(plaintext),
    )
    assert res.matched is False
    assert res.reason == UNWRAP_REASON_TAMPERED_CIPHERTEXT


def test_empty_and_whitespace_only_passphrases_are_rejected_typed() -> None:
    plaintext = b"empty passphrase"
    for candidate in ("", "   ", " \t　 "):
        with pytest.raises(EciesSealedPoeError) as exc:
            _seal(plaintext, passphrase=candidate)
        assert exc.value.code == "ENC_PASSPHRASE_EMPTY"
        out = _seal(plaintext)
        with pytest.raises(EciesSealedPoeError) as exc:
            passphrase_sealed_poe_open(
                envelope=out.envelope,
                ciphertext=out.ciphertext,
                passphrase=candidate,
                hashes=_hashes(plaintext),
            )
        assert exc.value.code == "ENC_PASSPHRASE_EMPTY"


def test_envelope_shape_rejections_are_typed() -> None:
    plaintext = b"shape"
    out = _seal(plaintext)

    def open_with(envelope: PassphraseEnvelope) -> None:
        passphrase_sealed_poe_open(
            envelope=envelope,
            ciphertext=out.ciphertext,
            passphrase="correct horse battery staple",
            hashes=_hashes(plaintext),
        )

    base = out.envelope
    cases: list[tuple[PassphraseEnvelope, str]] = [
        (
            PassphraseEnvelope(2, base.aead, base.nonce, base.alg, base.salt, base.params),
            "UNSUPPORTED_ENVELOPE_SCHEME",
        ),
        (
            PassphraseEnvelope(
                1, "xchacha20-poly1305", base.nonce, base.alg, base.salt, base.params
            ),
            "UNSUPPORTED_AEAD_ALG",
        ),
        (
            PassphraseEnvelope(1, base.aead, base.nonce, "scrypt", base.salt, base.params),
            "ENC_PASSPHRASE_ALG_UNSUPPORTED",
        ),
        (
            PassphraseEnvelope(1, base.aead, base.nonce[:23], base.alg, base.salt, base.params),
            "NONCE_LENGTH_MISMATCH",
        ),
        (
            PassphraseEnvelope(1, base.aead, base.nonce, base.alg, b"\x01" * 15, base.params),
            "ENC_PASSPHRASE_SALT_TOO_SHORT",
        ),
        (
            PassphraseEnvelope(1, base.aead, base.nonce, base.alg, b"\x01" * 65, base.params),
            "ENC_PASSPHRASE_SALT_TOO_LONG",
        ),
        (
            # Below the registry floors (m >= 65536, t >= 3): refused at open
            # before any KDF work — a below-floor envelope is categorically
            # outside the construction.
            PassphraseEnvelope(
                1, base.aead, base.nonce, base.alg, base.salt, Argon2idParams(m=8, t=1, p=1)
            ),
            "ENC_PASSPHRASE_ARGON2_PARAMS_TOO_LOW",
        ),
        (
            # Zero is inside the wire uint range but below the floors.
            PassphraseEnvelope(
                1, base.aead, base.nonce, base.alg, base.salt, Argon2idParams(m=65536, t=0, p=1)
            ),
            "ENC_PASSPHRASE_ARGON2_PARAMS_TOO_LOW",
        ),
        (
            # Outside the wire uint range entirely (raw-input error).
            PassphraseEnvelope(
                1,
                base.aead,
                base.nonce,
                base.alg,
                base.salt,
                Argon2idParams(m=65536, t=3, p=1 << 32),
            ),
            "INVALID_PASSPHRASE_PARAMS",
        ),
    ]
    for envelope, expected_code in cases:
        with pytest.raises(EciesSealedPoeError) as exc:
            open_with(envelope)
        assert exc.value.code == expected_code


def test_seal_validates_salt_and_params() -> None:
    plaintext = b"seal validation"
    with pytest.raises(EciesSealedPoeError) as exc:
        passphrase_sealed_poe_seal(
            plaintext=plaintext,
            passphrase="ok passphrase",
            hashes=_hashes(plaintext),
            params=_PARAMS,
            salt=b"\x01" * 15,
        )
    assert exc.value.code == "ENC_PASSPHRASE_SALT_TOO_SHORT"
    with pytest.raises(EciesSealedPoeError) as exc:
        passphrase_sealed_poe_seal(
            plaintext=plaintext,
            passphrase="ok passphrase",
            hashes=_hashes(plaintext),
            params=Argon2idParams(m=1 << 32, t=3, p=1),
            salt=_SALT,
        )
    assert exc.value.code == "INVALID_PASSPHRASE_PARAMS"
    # Below-floor params are a seal-side rejection too: weak-KDF envelopes are
    # unreproducible through the public API.
    with pytest.raises(EciesSealedPoeError) as exc:
        passphrase_sealed_poe_seal(
            plaintext=plaintext,
            passphrase="ok passphrase",
            hashes=_hashes(plaintext),
            params=Argon2idParams(m=8, t=1, p=1),
            salt=_SALT,
        )
    assert exc.value.code == "ENC_PASSPHRASE_ARGON2_PARAMS_TOO_LOW"


def test_empty_hashes_map_is_rejected() -> None:
    with pytest.raises(EciesSealedPoeError) as exc:
        passphrase_sealed_poe_seal(
            plaintext=b"x",
            passphrase="ok passphrase",
            hashes={},
            params=_PARAMS,
            salt=_SALT,
        )
    assert exc.value.code == "ENC_REQUIRES_CONTENT_HASH"


def test_open_error_precedence_is_pinned(monkeypatch: pytest.MonkeyPatch) -> None:
    # Typed caller-input rejections — hash claim, then passphrase
    # normalization, then envelope shape — strictly precede the blob structural
    # floor, and the floor precedes the Argon2id derivation. Each case stacks a
    # later-stage defect under an earlier-stage one and expects the earlier
    # rejection.
    hashes = {"sha2-256": b"\x5a" * 32}
    short_blob = b"\x00" * 47  # one byte below the 48-byte floor
    # U+0378 is unassigned in Unicode 16.0, so the pinned normalization
    # profile refuses the passphrase.
    unnormalizable = "pass͸word"
    below_floor = PassphraseEnvelope(
        scheme=1,
        aead="chacha20-poly1305-stream64k",
        nonce=_NONCE,
        alg="argon2id",
        salt=_SALT,
        params=Argon2idParams(m=8, t=1, p=1),
    )
    valid_envelope = PassphraseEnvelope(
        scheme=1,
        aead="chacha20-poly1305-stream64k",
        nonce=_NONCE,
        alg="argon2id",
        salt=_SALT,
        params=_PARAMS,
    )

    # (1) the hash claim is validated before normalization, envelope, and blob.
    with pytest.raises(EciesSealedPoeError) as exc:
        passphrase_sealed_poe_open(
            envelope=below_floor, ciphertext=short_blob, passphrase=unnormalizable, hashes={}
        )
    assert exc.value.code == "ENC_REQUIRES_CONTENT_HASH"

    # (2) normalization is validated before the envelope and the blob.
    with pytest.raises(EciesSealedPoeError) as exc:
        passphrase_sealed_poe_open(
            envelope=below_floor, ciphertext=short_blob, passphrase=unnormalizable, hashes=hashes
        )
    assert exc.value.code == "ENC_PASSPHRASE_UNNORMALIZABLE"

    # (3) the envelope shape is validated before the blob floor.
    with pytest.raises(EciesSealedPoeError) as exc:
        passphrase_sealed_poe_open(
            envelope=below_floor,
            ciphertext=short_blob,
            passphrase="correct horse battery staple",
            hashes=hashes,
        )
    assert exc.value.code == "ENC_PASSPHRASE_ARGON2_PARAMS_TOO_LOW"

    # (4) a below-floor blob fails generically WITHOUT invoking the KDF.
    import cardanowall._crypto.sealed_poe as sealed_poe_module

    def _kdf_must_not_run(*args: Any, **kwargs: Any) -> bytes:
        raise AssertionError("argon2id_v13 must not run for a blob below the structural floor")

    monkeypatch.setattr(sealed_poe_module, "argon2id_v13", _kdf_must_not_run)
    res = passphrase_sealed_poe_open(
        envelope=valid_envelope,
        ciphertext=short_blob,
        passphrase="correct horse battery staple",
        hashes=hashes,
    )
    assert res.matched is False
    assert res.reason == UNWRAP_REASON_TAMPERED_CIPHERTEXT


# ---------------------------------------------------------------------------
# Fixture KATs (pinned cross-SDK vectors).
# ---------------------------------------------------------------------------


def _load(filename: str) -> dict[str, Any]:
    return cast(dict[str, Any], json.loads((FIXTURES_DIR / filename).read_text()))


def _envelope_from_fixture(env: dict[str, Any]) -> PassphraseEnvelope:
    params = env["passphrase"]["params"]
    return PassphraseEnvelope(
        scheme=int(env["scheme"]),
        aead=str(env["aead"]),
        nonce=bytes.fromhex(str(env["nonce_hex"])),
        alg=str(env["passphrase"]["alg"]),
        salt=bytes.fromhex(str(env["passphrase"]["salt_hex"])),
        params=Argon2idParams(m=int(params["m"]), t=int(params["t"]), p=int(params["p"])),
    )


def _hashes_from_fixture(hashes_hex: dict[str, str]) -> dict[str, bytes]:
    return {alg: bytes.fromhex(h) for alg, h in hashes_hex.items()}


def test_passphrase_n1_kat() -> None:
    vector = _load("passphrase-n1.json")["vector"]
    plaintext = bytes.fromhex(vector["plaintext_hex"])
    hashes = _hashes_from_fixture(vector["hashes"])
    out = passphrase_sealed_poe_seal(
        plaintext=plaintext,
        passphrase=vector["passphrase"],
        hashes=hashes,
        params=Argon2idParams(
            m=vector["params"]["m"], t=vector["params"]["t"], p=vector["params"]["p"]
        ),
        salt=bytes.fromhex(vector["salt_hex"]),
        nonce=bytes.fromhex(vector["nonce_hex"]),
    )
    assert out.ciphertext[:32].hex() == vector["expected_commitment_hex"]
    assert out.ciphertext.hex() == vector["expected_ciphertext_hex"]

    res = passphrase_sealed_poe_open(
        envelope=out.envelope,
        ciphertext=bytes.fromhex(vector["expected_ciphertext_hex"]),
        passphrase=vector["passphrase"],
        hashes=hashes,
    )
    assert res.matched is True
    assert res.plaintext == bytes.fromhex(vector["expected_plaintext_hex"])


def test_passphrase_negative_kats() -> None:
    corpus = _load("passphrase-negative.json")
    for vector in corpus["matched_false_vectors"]:
        res = passphrase_sealed_poe_open(
            envelope=_envelope_from_fixture(vector["envelope"]),
            ciphertext=bytes.fromhex(vector["ciphertext_hex"]),
            passphrase=vector["passphrase"],
            hashes=_hashes_from_fixture(vector["hashes"]),
        )
        assert res.matched is False, vector["name"]
        assert res.reason == vector["expected_reason"], vector["name"]
    for vector in corpus["raise_vectors"]:
        with pytest.raises(EciesSealedPoeError) as exc:
            passphrase_sealed_poe_open(
                envelope=_envelope_from_fixture(vector["envelope"]),
                ciphertext=bytes.fromhex(vector["ciphertext_hex"]),
                passphrase=vector["passphrase"],
                hashes=_hashes_from_fixture(vector["hashes"]),
            )
        assert exc.value.code == vector["expected_error_code"], vector["name"]
