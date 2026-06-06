"""Verifier decrypt path tests.

Covers the sealed-recipient + passphrase paths including the post-unwrap
plaintext-hash recompute and the discriminated-union shape check
(WRONG_DECRYPTION_INPUT_SHAPE).
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any, cast

from cardanowall._crypto.aead import xchacha20_poly1305_encrypt
from cardanowall._crypto.hash import sha256
from cardanowall._crypto.kdf import argon2id_v13, hkdf_sha256
from cardanowall._crypto.kem import x25519_keygen
from cardanowall._crypto.sealed_poe import ecies_sealed_poe_wrap
from cardanowall.poe_standard import PoeRecord
from cardanowall.poe_standard.schema import PassphraseKdf
from cardanowall.verifier import (
    DecryptionPassphrase,
    DecryptionRecipient,
    FetchOutboundOptions,
    FetchOutboundResult,
    VerifyItemDecryption,
    VerifyTxInput,
    VerifyUriCheck,
)
from cardanowall.verifier.decrypt import _ad_content_passphrase, _normalize_passphrase
from cardanowall.verifier.decrypt import try_decryptions as _try_decryptions

_FIXTURES_DIR = Path(__file__).parent / "fixtures" / "sealed-poe"


def _load_fixture(filename: str) -> dict[str, Any]:
    return cast(dict[str, Any], json.loads((_FIXTURES_DIR / filename).read_text()))


async def try_decryptions(
    record: PoeRecord,
    input: VerifyTxInput,
    fetch_fn: object,
) -> tuple[tuple[VerifyItemDecryption, ...], tuple[VerifyUriCheck, ...]]:
    """Test shim adapting the verifier's `try_decryptions` to the
    `(results, uri_checks)` tuple these tests assert on, where `results` are the
    per-item decryption outcomes and `uri_checks` are the ciphertext-fetch URI
    verdicts. The real signature accumulates URI outcomes into a caller-supplied
    list and uses an `allow_uri_fetch` switch; the full pipeline
    (`allow_uri_fetch=True`) is the path under test here."""
    uri_checks: list[VerifyUriCheck] = []
    results = await _try_decryptions(
        record,
        input,
        fetch_fn,  # type: ignore[arg-type]
        uri_checks,
        allow_uri_fetch=True,
    )
    return results, tuple(uri_checks)


async def _no_fetch(url: str, opts: FetchOutboundOptions) -> FetchOutboundResult:
    raise RuntimeError(f"unexpected fetch: {url}")


def _encrypt_passphrase_payload(
    passphrase: str, salt: bytes, m: int, t: int, p: int, nonce: bytes, plaintext: bytes
) -> bytes:
    """Produce a passphrase-path ciphertext: CEK = Argon2id(normalize(pw));
    payload_key = HKDF(CEK, salt=nonce, info=payload-passphrase);
    AAD = canonicalEncode(AD_CONTENT_PASSPHRASE)."""
    cek = argon2id_v13(_normalize_passphrase(passphrase), salt, m, t, p, 32)
    payload_key = hkdf_sha256(
        ikm=cek, salt=nonce, info=b"cardano-poe-payload-passphrase-v1", length=32
    )
    kdf: PassphraseKdf = {
        "alg": "argon2id",
        "salt": salt,
        "params": {"m": m, "t": t, "p": p},
    }
    aad = _ad_content_passphrase(nonce, kdf)
    return xchacha20_poly1305_encrypt(payload_key, nonce, aad, plaintext)


def test_sealed_recipient_decrypts_and_hash_matches() -> None:
    plaintext = b"the secret plaintext"
    kp = x25519_keygen()
    wrap_out = ecies_sealed_poe_wrap(
        plaintext=plaintext,
        recipient_public_keys=[kp["public_key"]],
    )
    record: PoeRecord = cast(
        PoeRecord,
        {
            "v": 1,
            "items": [
                {
                    "hashes": {"sha2-256": sha256(plaintext)},
                    "enc": {
                        "scheme": 1,
                        "aead": "xchacha20-poly1305",
                        "kem": "x25519",
                        "nonce": wrap_out.envelope.nonce,
                        "slots": [{"epk": s.epk, "wrap": s.wrap} for s in wrap_out.envelope.slots],
                        "slots_mac": wrap_out.envelope.slots_mac,
                    },
                }
            ],
        },
    )
    decryption = DecryptionRecipient(item_index=0, recipient_secret_key=kp["secret_key"])
    results, uri_checks = asyncio.run(
        try_decryptions(
            record,
            VerifyTxInput(
                tx_hash="00" * 32,
                decryption=(decryption,),
                ciphertext_bytes={0: wrap_out.ciphertext},
            ),
            _no_fetch,
        )
    )
    assert len(results) == 1
    assert results[0].verdict == "decrypted"
    assert results[0].plaintext_hash_ok is True
    assert results[0].reason is None
    assert uri_checks == ()


def test_sealed_recipient_wrong_key_emits_wrong_recipient_key() -> None:
    plaintext = b"secret"
    target_kp = x25519_keygen()
    wrong_kp = x25519_keygen()
    wrap_out = ecies_sealed_poe_wrap(
        plaintext=plaintext,
        recipient_public_keys=[target_kp["public_key"]],
    )
    record: PoeRecord = cast(
        PoeRecord,
        {
            "v": 1,
            "items": [
                {
                    "hashes": {"sha2-256": sha256(plaintext)},
                    "enc": {
                        "scheme": 1,
                        "aead": "xchacha20-poly1305",
                        "kem": "x25519",
                        "nonce": wrap_out.envelope.nonce,
                        "slots": [{"epk": s.epk, "wrap": s.wrap} for s in wrap_out.envelope.slots],
                        "slots_mac": wrap_out.envelope.slots_mac,
                    },
                }
            ],
        },
    )
    decryption = DecryptionRecipient(item_index=0, recipient_secret_key=wrong_kp["secret_key"])
    results, _ = asyncio.run(
        try_decryptions(
            record,
            VerifyTxInput(
                tx_hash="00" * 32,
                decryption=(decryption,),
                ciphertext_bytes={0: wrap_out.ciphertext},
            ),
            _no_fetch,
        )
    )
    assert results[0].verdict == "wrong-key"
    assert results[0].reason == "WRONG_RECIPIENT_KEY"


def test_sealed_hash_mismatch_emits_uri_integrity_mismatch() -> None:
    plaintext = b"the plaintext"
    kp = x25519_keygen()
    wrap_out = ecies_sealed_poe_wrap(
        plaintext=plaintext,
        recipient_public_keys=[kp["public_key"]],
    )
    # Declare a wrong content hash on record so post-unwrap recompute fails.
    record: PoeRecord = cast(
        PoeRecord,
        {
            "v": 1,
            "items": [
                {
                    "hashes": {"sha2-256": b"\xff" * 32},
                    "enc": {
                        "scheme": 1,
                        "aead": "xchacha20-poly1305",
                        "kem": "x25519",
                        "nonce": wrap_out.envelope.nonce,
                        "slots": [{"epk": s.epk, "wrap": s.wrap} for s in wrap_out.envelope.slots],
                        "slots_mac": wrap_out.envelope.slots_mac,
                    },
                }
            ],
        },
    )
    decryption = DecryptionRecipient(item_index=0, recipient_secret_key=kp["secret_key"])
    results, _ = asyncio.run(
        try_decryptions(
            record,
            VerifyTxInput(
                tx_hash="00" * 32,
                decryption=(decryption,),
                ciphertext_bytes={0: wrap_out.ciphertext},
            ),
            _no_fetch,
        )
    )
    assert results[0].verdict == "decrypted"
    assert results[0].plaintext_hash_ok is False
    assert results[0].reason is None


def test_passphrase_path_decrypts_and_hash_matches() -> None:
    plaintext = b"passphrase-encrypted message"
    passphrase = "correct horse battery staple"  # noqa: S105 — test fixture
    # Cost-minimal Argon2id params for test speed; these are below the
    # producer-side floor (m>=65536, t>=3) but the verifier itself does not
    # enforce floors — the validator does, and we bypass it here.
    salt = b"\x42" * 16
    m, t, p = 8, 1, 1
    nonce = b"\x00" * 24
    ciphertext = _encrypt_passphrase_payload(passphrase, salt, m, t, p, nonce, plaintext)
    record: PoeRecord = cast(
        PoeRecord,
        {
            "v": 1,
            "items": [
                {
                    "hashes": {"sha2-256": sha256(plaintext)},
                    "enc": {
                        "scheme": 1,
                        "aead": "xchacha20-poly1305",
                        "nonce": nonce,
                        "passphrase": {
                            "alg": "argon2id",
                            "salt": salt,
                            "params": {"m": m, "t": t, "p": p},
                        },
                    },
                }
            ],
        },
    )
    decryption = DecryptionPassphrase(item_index=0, passphrase=passphrase)
    results, _ = asyncio.run(
        try_decryptions(
            record,
            VerifyTxInput(
                tx_hash="00" * 32,
                decryption=(decryption,),
                ciphertext_bytes={0: ciphertext},
            ),
            _no_fetch,
        )
    )
    assert results[0].verdict == "decrypted"
    assert results[0].plaintext_hash_ok is True


def test_passphrase_wrong_passphrase_emits_tampered_ciphertext() -> None:
    plaintext = b"secret"
    salt = b"\xaa" * 16
    m, t, p = 8, 1, 1
    nonce = b"\x00" * 24
    ciphertext = _encrypt_passphrase_payload("right", salt, m, t, p, nonce, plaintext)
    record: PoeRecord = cast(
        PoeRecord,
        {
            "v": 1,
            "items": [
                {
                    "hashes": {"sha2-256": sha256(plaintext)},
                    "enc": {
                        "scheme": 1,
                        "aead": "xchacha20-poly1305",
                        "nonce": nonce,
                        "passphrase": {
                            "alg": "argon2id",
                            "salt": salt,
                            "params": {"m": m, "t": t, "p": p},
                        },
                    },
                }
            ],
        },
    )
    decryption = DecryptionPassphrase(item_index=0, passphrase="wrong")  # noqa: S106
    results, _ = asyncio.run(
        try_decryptions(
            record,
            VerifyTxInput(
                tx_hash="00" * 32,
                decryption=(decryption,),
                ciphertext_bytes={0: ciphertext},
            ),
            _no_fetch,
        )
    )
    # The AEAD primitive cannot distinguish wrong passphrase from
    # ciphertext tampering on the passphrase path; spec mandates
    # TAMPERED_CIPHERTEXT for both.
    assert results[0].verdict == "tampered-ciphertext"
    assert results[0].reason == "TAMPERED_CIPHERTEXT"


def test_passphrase_aad_tamper_on_salt_fails() -> None:
    """The passphrase content AAD binds salt + params; altering the on-record
    salt after encryption changes the recomputed AAD and the AEAD open fails."""
    plaintext = b"aad binds salt"
    passphrase = "battery horse staple"  # noqa: S105 — test fixture
    salt = b"\x11" * 16
    m, t, p = 8, 1, 1
    nonce = b"\x00" * 24
    ciphertext = _encrypt_passphrase_payload(passphrase, salt, m, t, p, nonce, plaintext)
    # Record carries a DIFFERENT salt than the one the ciphertext was sealed
    # under. The CEK Argon2id derives differs (so does the AAD), so the open
    # fails — indistinguishable from a tampered ciphertext.
    record: PoeRecord = cast(
        PoeRecord,
        {
            "v": 1,
            "items": [
                {
                    "hashes": {"sha2-256": sha256(plaintext)},
                    "enc": {
                        "scheme": 1,
                        "aead": "xchacha20-poly1305",
                        "nonce": nonce,
                        "passphrase": {
                            "alg": "argon2id",
                            "salt": b"\x22" * 16,
                            "params": {"m": m, "t": t, "p": p},
                        },
                    },
                }
            ],
        },
    )
    decryption = DecryptionPassphrase(item_index=0, passphrase=passphrase)
    results, _ = asyncio.run(
        try_decryptions(
            record,
            VerifyTxInput(
                tx_hash="00" * 32,
                decryption=(decryption,),
                ciphertext_bytes={0: ciphertext},
            ),
            _no_fetch,
        )
    )
    assert results[0].verdict == "tampered-ciphertext"
    assert results[0].reason == "TAMPERED_CIPHERTEXT"


def test_passphrase_aad_tamper_on_params_fails() -> None:
    """Altering a params value after encryption (same salt, kept consistent so
    the CEK is unchanged) changes only the AAD, which the AEAD tag rejects."""
    plaintext = b"aad binds params"
    passphrase = "correct horse"  # noqa: S105 — test fixture
    salt = b"\x33" * 16
    nonce = b"\x00" * 24
    # Seal with params (m=8, t=1, p=1). Build the ciphertext with the real CEK.
    ciphertext = _encrypt_passphrase_payload(passphrase, salt, 8, 1, 1, nonce, plaintext)
    # Present params with t bumped: Argon2id derives a different CEK AND the AAD
    # differs; either way the open fails generically.
    record: PoeRecord = cast(
        PoeRecord,
        {
            "v": 1,
            "items": [
                {
                    "hashes": {"sha2-256": sha256(plaintext)},
                    "enc": {
                        "scheme": 1,
                        "aead": "xchacha20-poly1305",
                        "nonce": nonce,
                        "passphrase": {
                            "alg": "argon2id",
                            "salt": salt,
                            "params": {"m": 8, "t": 2, "p": 1},
                        },
                    },
                }
            ],
        },
    )
    decryption = DecryptionPassphrase(item_index=0, passphrase=passphrase)
    results, _ = asyncio.run(
        try_decryptions(
            record,
            VerifyTxInput(
                tx_hash="00" * 32,
                decryption=(decryption,),
                ciphertext_bytes={0: ciphertext},
            ),
            _no_fetch,
        )
    )
    assert results[0].verdict == "tampered-ciphertext"
    assert results[0].reason == "TAMPERED_CIPHERTEXT"


def test_passphrase_normalization_collapses_whitespace_property_set() -> None:
    """The normalization profile uses the explicit Unicode White_Space set: a
    passphrase typed with assorted whitespace (NEL U+0085, NBSP U+00A0, tabs,
    ideographic space U+3000) decrypts a record sealed under the single-space
    canonical form, because both normalize identically."""
    canonical = "alpha beta gamma"
    # tab + space between alpha/beta, ideographic space U+3000 between
    # beta/gamma, plus leading/trailing runs to trim. All collapse to a
    # single U+0020, so this normalizes to the canonical form.
    typed = "\t alpha \tbeta\u3000gamma \r\n"
    assert _normalize_passphrase(typed) == _normalize_passphrase(canonical)
    assert _normalize_passphrase(canonical) == b"alpha beta gamma"

    plaintext = b"whitespace-normalized passphrase"
    salt = b"\x44" * 16
    nonce = b"\x00" * 24
    ciphertext = _encrypt_passphrase_payload(canonical, salt, 8, 1, 1, nonce, plaintext)
    record: PoeRecord = cast(
        PoeRecord,
        {
            "v": 1,
            "items": [
                {
                    "hashes": {"sha2-256": sha256(plaintext)},
                    "enc": {
                        "scheme": 1,
                        "aead": "xchacha20-poly1305",
                        "nonce": nonce,
                        "passphrase": {
                            "alg": "argon2id",
                            "salt": salt,
                            "params": {"m": 8, "t": 1, "p": 1},
                        },
                    },
                }
            ],
        },
    )
    # Decrypt with the differently-typed-but-equivalent passphrase.
    decryption = DecryptionPassphrase(item_index=0, passphrase=typed)
    results, _ = asyncio.run(
        try_decryptions(
            record,
            VerifyTxInput(
                tx_hash="00" * 32,
                decryption=(decryption,),
                ciphertext_bytes={0: ciphertext},
            ),
            _no_fetch,
        )
    )
    assert results[0].verdict == "decrypted"
    assert results[0].plaintext_hash_ok is True


def test_wrong_decryption_input_shape_for_sealed_with_passphrase() -> None:
    plaintext = b"x"
    kp = x25519_keygen()
    wrap_out = ecies_sealed_poe_wrap(plaintext=plaintext, recipient_public_keys=[kp["public_key"]])
    record: PoeRecord = cast(
        PoeRecord,
        {
            "v": 1,
            "items": [
                {
                    "hashes": {"sha2-256": sha256(plaintext)},
                    "enc": {
                        "scheme": 1,
                        "aead": "xchacha20-poly1305",
                        "kem": "x25519",
                        "nonce": wrap_out.envelope.nonce,
                        "slots": [{"epk": s.epk, "wrap": s.wrap} for s in wrap_out.envelope.slots],
                        "slots_mac": wrap_out.envelope.slots_mac,
                    },
                }
            ],
        },
    )
    decryption = DecryptionPassphrase(item_index=0, passphrase="anything")  # noqa: S106
    results, _ = asyncio.run(
        try_decryptions(
            record,
            VerifyTxInput(
                tx_hash="00" * 32,
                decryption=(decryption,),
                ciphertext_bytes={0: wrap_out.ciphertext},
            ),
            _no_fetch,
        )
    )
    assert results[0].verdict == "wrong-input-shape"
    assert results[0].reason == "WRONG_DECRYPTION_INPUT_SHAPE"


def test_missing_enc_envelope_emits_no_enc_envelope() -> None:
    record: PoeRecord = cast(
        PoeRecord,
        {
            "v": 1,
            "items": [{"hashes": {"sha2-256": b"\x00" * 32}}],
        },
    )
    decryption = DecryptionRecipient(item_index=0, recipient_secret_key=b"\x00" * 32)
    results, _ = asyncio.run(
        try_decryptions(
            record,
            VerifyTxInput(tx_hash="00" * 32, decryption=(decryption,)),
            _no_fetch,
        )
    )
    assert results[0].verdict == "no-enc-envelope"


def test_ciphertext_unavailable_when_no_uri_no_local_bytes() -> None:
    plaintext = b"y"
    kp = x25519_keygen()
    wrap_out = ecies_sealed_poe_wrap(plaintext=plaintext, recipient_public_keys=[kp["public_key"]])
    # `item.uris` absent AND no `ciphertext_bytes` supplied → emit
    # CIPHERTEXT_UNAVAILABLE.
    record: PoeRecord = cast(
        PoeRecord,
        {
            "v": 1,
            "items": [
                {
                    "hashes": {"sha2-256": sha256(plaintext)},
                    "enc": {
                        "scheme": 1,
                        "aead": "xchacha20-poly1305",
                        "kem": "x25519",
                        "nonce": wrap_out.envelope.nonce,
                        "slots": [{"epk": s.epk, "wrap": s.wrap} for s in wrap_out.envelope.slots],
                        "slots_mac": wrap_out.envelope.slots_mac,
                    },
                }
            ],
        },
    )
    decryption = DecryptionRecipient(item_index=0, recipient_secret_key=kp["secret_key"])
    results, _ = asyncio.run(
        try_decryptions(
            record,
            VerifyTxInput(tx_hash="00" * 32, decryption=(decryption,)),
            _no_fetch,
        )
    )
    assert results[0].verdict == "ciphertext-unavailable"
    assert results[0].reason == "CIPHERTEXT_UNAVAILABLE"


def test_uri_target_forbidden_for_out_of_set_scheme() -> None:
    # https:// is out of the v1 fetch set; the structural validator would
    # have rejected this upstream, but the verifier-side defence-in-depth
    # check fires on URI_TARGET_FORBIDDEN.
    plaintext = b"z"
    kp = x25519_keygen()
    wrap_out = ecies_sealed_poe_wrap(plaintext=plaintext, recipient_public_keys=[kp["public_key"]])
    record: PoeRecord = cast(
        PoeRecord,
        {
            "v": 1,
            "items": [
                {
                    "hashes": {"sha2-256": sha256(plaintext)},
                    "uris": [["https://example.com/c"]],
                    "enc": {
                        "scheme": 1,
                        "aead": "xchacha20-poly1305",
                        "kem": "x25519",
                        "nonce": wrap_out.envelope.nonce,
                        "slots": [{"epk": s.epk, "wrap": s.wrap} for s in wrap_out.envelope.slots],
                        "slots_mac": wrap_out.envelope.slots_mac,
                    },
                }
            ],
        },
    )
    decryption = DecryptionRecipient(item_index=0, recipient_secret_key=kp["secret_key"])
    results, _ = asyncio.run(
        try_decryptions(
            record,
            VerifyTxInput(tx_hash="00" * 32, decryption=(decryption,)),
            _no_fetch,
        )
    )
    assert results[0].verdict == "ciphertext-unavailable"
    assert results[0].reason == "URI_TARGET_FORBIDDEN"


def test_passphrase_n1_kat_byte_pins_ciphertext_and_round_trips() -> None:
    """Fixture-consumption gate for the pinned passphrase vector. Reproduce the
    producer path from the recorded passphrase/salt/params/nonce, assert the
    ciphertext byte-for-byte, then round-trip the same ciphertext through the
    public verifier API."""
    vector = _load_fixture("passphrase-n1.json")["vector"]
    passphrase = str(vector["passphrase"])
    salt = bytes.fromhex(str(vector["salt_hex"]))
    m = int(vector["params"]["m"])
    t = int(vector["params"]["t"])
    p = int(vector["params"]["p"])
    nonce = bytes.fromhex(str(vector["nonce_hex"]))
    plaintext = bytes.fromhex(str(vector["plaintext_hex"]))

    # Producer recompute: CEK = Argon2id(normalize(pw)); payload_key = HKDF(CEK,
    # salt=nonce, info=payload-passphrase); AAD = canonicalEncode(AD_CONTENT_PASSPHRASE).
    cek = argon2id_v13(_normalize_passphrase(passphrase), salt, m, t, p, 32)
    payload_key = hkdf_sha256(
        ikm=cek, salt=nonce, info=b"cardano-poe-payload-passphrase-v1", length=32
    )
    kdf: PassphraseKdf = {"alg": "argon2id", "salt": salt, "params": {"m": m, "t": t, "p": p}}
    aad = _ad_content_passphrase(nonce, kdf)
    ciphertext = xchacha20_poly1305_encrypt(payload_key, nonce, aad, plaintext)
    assert ciphertext.hex() == vector["expected_ciphertext_hex"]

    # Round-trip the pinned ciphertext through the public verifier.
    record: PoeRecord = cast(
        PoeRecord,
        {
            "v": 1,
            "items": [
                {
                    "hashes": {"sha2-256": sha256(plaintext)},
                    "enc": {
                        "scheme": 1,
                        "aead": "xchacha20-poly1305",
                        "nonce": nonce,
                        "passphrase": {
                            "alg": "argon2id",
                            "salt": salt,
                            "params": {"m": m, "t": t, "p": p},
                        },
                    },
                }
            ],
        },
    )
    results, _ = asyncio.run(
        try_decryptions(
            record,
            VerifyTxInput(
                tx_hash="00" * 32,
                decryption=(DecryptionPassphrase(item_index=0, passphrase=passphrase),),
                ciphertext_bytes={0: ciphertext},
            ),
            _no_fetch,
        )
    )
    assert results[0].verdict == "decrypted"
    assert results[0].plaintext_hash_ok is True
    assert bytes.fromhex(str(vector["expected_plaintext_hex"])) == plaintext


def test_cross_path_confusion_refused_before_aead() -> None:
    """Fixture-consumption gate for the cross-path vectors: a slots-shaped record
    decrypted with a passphrase input, and a passphrase-shaped record decrypted
    with a recipient key, must both be refused as WRONG_DECRYPTION_INPUT_SHAPE
    before any AEAD open."""
    corpus = _load_fixture("construction-negative.json")
    for vector in corpus["cross_path_vectors"]:
        slots_env = vector["slots_envelope"]
        pass_env = vector["passphrase_envelope"]

        # (a) slots-shaped record + passphrase request -> wrong-input-shape.
        slots_record: PoeRecord = cast(
            PoeRecord,
            {
                "v": 1,
                "items": [
                    {
                        "hashes": {"sha2-256": b"\x00" * 32},
                        "enc": {
                            "scheme": int(slots_env["scheme"]),
                            "aead": str(slots_env["aead"]),
                            "kem": str(slots_env["kem"]),
                            "nonce": bytes.fromhex(str(slots_env["nonce_hex"])),
                            "slots": [
                                {
                                    "epk": bytes.fromhex(str(s["epk_hex"])),
                                    "wrap": bytes.fromhex(str(s["wrap_hex"])),
                                }
                                for s in slots_env["slots"]
                            ],
                            "slots_mac": bytes.fromhex(str(slots_env["slots_mac_hex"])),
                        },
                    }
                ],
            },
        )
        results, _ = asyncio.run(
            try_decryptions(
                slots_record,
                VerifyTxInput(
                    tx_hash="00" * 32,
                    decryption=(
                        DecryptionPassphrase(item_index=0, passphrase="anything"),  # noqa: S106
                    ),
                    ciphertext_bytes={0: b"\x00" * 16},
                ),
                _no_fetch,
            )
        )
        assert results[0].verdict == "wrong-input-shape", vector["name"]
        assert results[0].reason == "WRONG_DECRYPTION_INPUT_SHAPE", vector["name"]

        # (b) passphrase-shaped record + recipient key -> wrong-input-shape.
        pass_record: PoeRecord = cast(
            PoeRecord,
            {
                "v": 1,
                "items": [
                    {
                        "hashes": {"sha2-256": b"\x00" * 32},
                        "enc": {
                            "scheme": int(pass_env["scheme"]),
                            "aead": str(pass_env["aead"]),
                            "nonce": bytes.fromhex(str(pass_env["nonce_hex"])),
                            "passphrase": {
                                "alg": str(pass_env["passphrase"]["alg"]),
                                "salt": bytes.fromhex(str(pass_env["passphrase"]["salt_hex"])),
                                "params": {
                                    "m": int(pass_env["passphrase"]["params"]["m"]),
                                    "t": int(pass_env["passphrase"]["params"]["t"]),
                                    "p": int(pass_env["passphrase"]["params"]["p"]),
                                },
                            },
                        },
                    }
                ],
            },
        )
        results, _ = asyncio.run(
            try_decryptions(
                pass_record,
                VerifyTxInput(
                    tx_hash="00" * 32,
                    decryption=(
                        DecryptionRecipient(item_index=0, recipient_secret_key=b"\x11" * 32),
                    ),
                    ciphertext_bytes={0: b"\x00" * 16},
                ),
                _no_fetch,
            )
        )
        assert results[0].verdict == "wrong-input-shape", vector["name"]
        assert results[0].reason == "WRONG_DECRYPTION_INPUT_SHAPE", vector["name"]


# ---------------------------------------------------------------------------
# A4 — pre-KDF passphrase length cap (4096 UTF-8 bytes), enforced before
# normalization / Argon2id.
# ---------------------------------------------------------------------------


def _passphrase_record(salt: bytes, m: int, t: int, p: int, nonce: bytes, plaintext: bytes) -> (
    PoeRecord
):
    return cast(
        PoeRecord,
        {
            "v": 1,
            "items": [
                {
                    "hashes": {"sha2-256": sha256(plaintext)},
                    "enc": {
                        "scheme": 1,
                        "aead": "xchacha20-poly1305",
                        "nonce": nonce,
                        "passphrase": {
                            "alg": "argon2id",
                            "salt": salt,
                            "params": {"m": m, "t": t, "p": p},
                        },
                    },
                }
            ],
        },
    )


def _run_passphrase(record: PoeRecord, ciphertext: bytes, passphrase: str) -> Any:
    results, _ = asyncio.run(
        try_decryptions(
            record,
            VerifyTxInput(
                tx_hash="00" * 32,
                decryption=(DecryptionPassphrase(item_index=0, passphrase=passphrase),),
                ciphertext_bytes={0: ciphertext},
            ),
            _no_fetch,
        )
    )
    return results[0]


def test_passphrase_cap_constant_is_4096_bytes() -> None:
    from cardanowall.verifier.decrypt import MAX_PASSPHRASE_INPUT_BYTES

    assert MAX_PASSPHRASE_INPUT_BYTES == 4096


def test_passphrase_over_byte_cap_is_rejected_kdf_failed() -> None:
    from cardanowall.verifier.decrypt import MAX_PASSPHRASE_INPUT_BYTES

    plaintext = b"cap test"
    salt = b"\x42" * 16
    m, t, p = 8, 1, 1
    nonce = b"\x00" * 24
    oversized = "a" * (MAX_PASSPHRASE_INPUT_BYTES + 1)  # 4097 ASCII bytes
    ciphertext = _encrypt_passphrase_payload(oversized, salt, m, t, p, nonce, plaintext)
    result = _run_passphrase(
        _passphrase_record(salt, m, t, p, nonce, plaintext), ciphertext, oversized
    )
    assert result.verdict == "kdf-failed"
    assert "KDF_DERIVATION_FAILED" in (result.reason or "")


def test_passphrase_exactly_at_cap_is_accepted() -> None:
    from cardanowall.verifier.decrypt import MAX_PASSPHRASE_INPUT_BYTES

    plaintext = b"cap test"
    salt = b"\x42" * 16
    m, t, p = 8, 1, 1
    nonce = b"\x00" * 24
    at_cap = "a" * MAX_PASSPHRASE_INPUT_BYTES  # 4096 ASCII bytes
    ciphertext = _encrypt_passphrase_payload(at_cap, salt, m, t, p, nonce, plaintext)
    result = _run_passphrase(
        _passphrase_record(salt, m, t, p, nonce, plaintext), ciphertext, at_cap
    )
    assert result.verdict == "decrypted"
    assert result.plaintext_hash_ok is True


def test_passphrase_cap_measures_bytes_not_code_points() -> None:
    from cardanowall.verifier.decrypt import MAX_PASSPHRASE_INPUT_BYTES

    # U+1F680 (rocket) is 4 UTF-8 bytes per code point. 1025 of them = 4100 bytes
    # but only 1025 code points — under any char-count limit, over the byte cap.
    plaintext = b"cap test"
    salt = b"\x42" * 16
    m, t, p = 8, 1, 1
    nonce = b"\x00" * 24
    multibyte_over_cap = "\U0001f680" * 1025
    assert len(multibyte_over_cap) < MAX_PASSPHRASE_INPUT_BYTES
    assert len(multibyte_over_cap.encode("utf-8")) > MAX_PASSPHRASE_INPUT_BYTES
    ciphertext = _encrypt_passphrase_payload(
        multibyte_over_cap, salt, m, t, p, nonce, plaintext
    )
    result = _run_passphrase(
        _passphrase_record(salt, m, t, p, nonce, plaintext), ciphertext, multibyte_over_cap
    )
    assert result.verdict == "kdf-failed"
    assert "KDF_DERIVATION_FAILED" in (result.reason or "")
