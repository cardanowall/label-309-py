"""Verifier decrypt path tests.

Covers the sealed-recipient + passphrase paths including the post-unwrap
plaintext-hash recompute and the discriminated-union shape check
(WRONG_DECRYPTION_INPUT_SHAPE).
"""

from __future__ import annotations

import asyncio
import re
import unicodedata
from typing import cast

from cardanowall._crypto.aead import xchacha20_poly1305_encrypt
from cardanowall._crypto.hash import sha256
from cardanowall._crypto.kdf import argon2id_v13
from cardanowall._crypto.kem import x25519_keygen
from cardanowall._crypto.sealed_poe import ecies_sealed_poe_wrap
from cardanowall.poe_standard import PoeRecord
from cardanowall.verifier import (
    DecryptionPassphrase,
    DecryptionRecipient,
    FetchOutboundOptions,
    FetchOutboundResult,
    VerifyItemDecryption,
    VerifyTxInput,
    VerifyUriCheck,
)
from cardanowall.verifier.decrypt import try_decryptions as _try_decryptions


async def try_decryptions(
    record: PoeRecord,
    input: VerifyTxInput,
    fetch_fn: object,
) -> tuple[tuple[VerifyItemDecryption, ...], tuple[VerifyUriCheck, ...]]:
    """Test shim adapting the verifier's `try_decryptions` to the legacy
    `(results, uri_checks)` tuple these tests assert on. The real signature
    accumulates URI outcomes into a caller-supplied list and uses an
    `allow_uri_fetch` switch; the full pipeline (`allow_uri_fetch=True`) is the
    path under test here."""
    uri_checks: list[VerifyUriCheck] = []
    results = await _try_decryptions(
        record,
        input,
        fetch_fn,  # type: ignore[arg-type]
        uri_checks,
        allow_uri_fetch=True,
    )
    return results, tuple(uri_checks)


def _normalise(passphrase: str) -> bytes:
    nfkc = unicodedata.normalize("NFKC", passphrase)
    return re.sub(r"\s+", " ", nfkc).strip().encode("utf-8")


async def _no_fetch(url: str, opts: FetchOutboundOptions) -> FetchOutboundResult:
    raise RuntimeError(f"unexpected fetch: {url}")


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
    kek = argon2id_v13(_normalise(passphrase), salt, m, t, p, 32)
    nonce = b"\x00" * 24
    ciphertext = xchacha20_poly1305_encrypt(kek, nonce, b"", plaintext)
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
    kek = argon2id_v13(_normalise("right"), salt, m, t, p, 32)
    nonce = b"\x00" * 24
    ciphertext = xchacha20_poly1305_encrypt(kek, nonce, b"", plaintext)
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
