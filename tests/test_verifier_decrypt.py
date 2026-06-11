"""Recipient-verifier decryption tests (``decrypt_item``).

Covers the two on-wire key paths (slots trial-decrypt, passphrase
commitment-then-STREAM), the keyring dispatch (every applicable credential
attempted independently; the wrong-shape rejection), the post-decryption
plaintext-hash recheck, the blob-availability end-states, and the failure
attribution split (header failures bind to on-chain data; blob failures hold
only an attributable blob against the record).
"""

from __future__ import annotations

import asyncio
from typing import cast

from cardanowall._crypto.hash import sha256
from cardanowall._crypto.kem import x25519_keygen
from cardanowall._crypto.sealed_poe import (
    Argon2idParams,
    ecies_sealed_poe_wrap,
    passphrase_sealed_poe_seal,
)
from cardanowall.poe_standard import Item
from cardanowall.verifier import (
    DecryptionPassphrase,
    DecryptionRecipient,
    FetchOutboundOptions,
    FetchOutboundResult,
)
from cardanowall.verifier.decrypt import ItemDecryptionResult, decrypt_item
from cardanowall.verifier.fetch import ContentFetchContext
from cardanowall.verifier.types import Decryption, IssueSink

# The construction's minimum acceptable work factors (the wire floor), so the
# suite pays one real Argon2id derivation per attempt without test-only
# bypasses.
_ARGON2_PARAMS = Argon2idParams(m=65536, t=3, p=1)
_SALT = b"\x5a" * 32
_NONCE = b"\x6b" * 24


async def _no_fetch(url: str, opts: FetchOutboundOptions) -> FetchOutboundResult:
    raise AssertionError(f"unexpected fetch: {url}")


def _ctx(sink: IssueSink) -> ContentFetchContext:
    return ContentFetchContext(
        fetch_fn=_no_fetch, arweave_gateways=(), ipfs_gateways=(), issues=sink
    )


def _run(
    item: Item,
    credentials: tuple[Decryption, ...],
    *,
    ciphertext: bytes | None,
    sink: IssueSink,
) -> ItemDecryptionResult:
    return asyncio.run(
        decrypt_item(
            item=item,
            item_index=0,
            credentials=credentials,
            ctx=_ctx(sink),
            fetch_content=True,
            out_of_band_ciphertext=ciphertext,
        )
    )


def _sealed_item(
    plaintext: bytes, recipient_pub: bytes, *, hashes: dict[str, bytes] | None = None
) -> tuple[Item, bytes]:
    committed = hashes if hashes is not None else {"sha2-256": sha256(plaintext)}
    out = ecies_sealed_poe_wrap(
        plaintext=plaintext, recipient_public_keys=[recipient_pub], hashes=committed
    )
    item: Item = cast(
        Item,
        {
            "hashes": committed,
            "enc": {
                "scheme": 1,
                "aead": out.envelope.aead,
                "kem": "x25519",
                "nonce": out.envelope.nonce,
                "slots": [{"epk": s.epk, "wrap": s.wrap} for s in out.envelope.slots],
                "slots_mac": out.envelope.slots_mac,
            },
        },
    )
    return item, out.ciphertext


def _passphrase_item(plaintext: bytes, passphrase: str) -> tuple[Item, bytes]:
    committed = {"sha2-256": sha256(plaintext)}
    out = passphrase_sealed_poe_seal(
        plaintext=plaintext,
        passphrase=passphrase,
        hashes=committed,
        params=_ARGON2_PARAMS,
        salt=_SALT,
        nonce=_NONCE,
    )
    item: Item = cast(
        Item,
        {
            "hashes": committed,
            "enc": {
                "scheme": 1,
                "aead": out.envelope.aead,
                "nonce": out.envelope.nonce,
                "passphrase": {
                    "alg": out.envelope.alg,
                    "salt": out.envelope.salt,
                    "params": {
                        "m": out.envelope.params.m,
                        "t": out.envelope.params.t,
                        "p": out.envelope.params.p,
                    },
                },
            },
        },
    )
    return item, out.ciphertext


# ---- Slots path ---------------------------------------------------------------


def test_sealed_recipient_decrypts_and_recheck_passes() -> None:
    kp = x25519_keygen()
    item, ciphertext = _sealed_item(b"the secret plaintext", kp["public_key"])
    sink = IssueSink()
    result = _run(
        item,
        (DecryptionRecipient(recipient_secret_key=kp["secret_key"]),),
        ciphertext=ciphertext,
        sink=sink,
    )
    assert result.content_check == "checked"
    assert result.decryption.decrypted is True
    assert result.decryption.plaintext_hash_ok is True
    assert sink.issues == []


def test_wrong_recipient_key_is_terminal_header_outcome() -> None:
    kp = x25519_keygen()
    other = x25519_keygen()
    item, ciphertext = _sealed_item(b"sealed for someone else", kp["public_key"])
    sink = IssueSink()
    result = _run(
        item,
        (DecryptionRecipient(recipient_secret_key=other["secret_key"]),),
        ciphertext=ciphertext,
        sink=sink,
    )
    assert result.content_check == "not_checked"
    assert result.decryption.decrypted is False
    assert result.decryption.code == "WRONG_RECIPIENT_KEY"
    issue = next(i for i in sink.issues if i.code == "WRONG_RECIPIENT_KEY")
    assert issue.severity == "error"
    assert issue.path == ("items", 0, "enc")


def test_keyring_attempts_every_recipient_key() -> None:
    # The second key in the keyring is the recipient: the run still opens.
    kp = x25519_keygen()
    wrong = x25519_keygen()
    item, ciphertext = _sealed_item(b"multi-key keyring", kp["public_key"])
    sink = IssueSink()
    result = _run(
        item,
        (
            DecryptionRecipient(recipient_secret_key=wrong["secret_key"]),
            DecryptionRecipient(recipient_secret_key=kp["secret_key"]),
        ),
        ciphertext=ciphertext,
        sink=sink,
    )
    assert result.decryption.decrypted is True
    assert result.content_check == "checked"


def test_plaintext_hash_recheck_failure_is_record_attributable() -> None:
    # The producer sealed plaintext that does NOT match the item's hash
    # commitment. Decryption succeeds (the envelope binds the committed map),
    # the recheck fails, and the AEAD itself attributes the decrypted bytes —
    # URI_INTEGRITY_MISMATCH, contentCheck mismatched.
    kp = x25519_keygen()
    wrong_commitment = {"sha2-256": sha256(b"a different plaintext")}
    item, ciphertext = _sealed_item(
        b"what was actually sealed", kp["public_key"], hashes=wrong_commitment
    )
    sink = IssueSink()
    result = _run(
        item,
        (DecryptionRecipient(recipient_secret_key=kp["secret_key"]),),
        ciphertext=ciphertext,
        sink=sink,
    )
    assert result.content_check == "mismatched"
    assert result.decryption.decrypted is True
    assert result.decryption.plaintext_hash_ok is False
    assert result.decryption.code == "URI_INTEGRITY_MISMATCH"
    issue = next(i for i in sink.issues if i.code == "URI_INTEGRITY_MISMATCH")
    assert issue.severity == "error"
    assert issue.path == ("items", 0)


def test_tampered_ciphertext_on_attributable_blob_condemns_the_record() -> None:
    kp = x25519_keygen()
    item, ciphertext = _sealed_item(b"to be tampered", kp["public_key"])
    tampered = ciphertext[:-1] + bytes([ciphertext[-1] ^ 0xFF])
    sink = IssueSink()
    result = _run(
        item,
        (DecryptionRecipient(recipient_secret_key=kp["secret_key"]),),
        ciphertext=tampered,  # out-of-band bytes are attributable by definition
        sink=sink,
    )
    assert result.content_check == "mismatched"
    assert result.decryption.code == "TAMPERED_CIPHERTEXT"
    issue = next(i for i in sink.issues if i.code == "TAMPERED_CIPHERTEXT")
    assert issue.severity == "error"
    assert issue.path == ("items", 0, "enc")


# ---- Passphrase path ------------------------------------------------------------


def test_passphrase_path_decrypts_and_recheck_passes() -> None:
    item, blob = _passphrase_item(b"passphrase-sealed plaintext", "correct horse")
    sink = IssueSink()
    result = _run(
        item, (DecryptionPassphrase(passphrase="correct horse"),), ciphertext=blob, sink=sink
    )
    assert result.content_check == "checked"
    assert result.decryption.decrypted is True
    assert result.decryption.plaintext_hash_ok is True
    assert sink.issues == []


def test_wrong_passphrase_is_indistinguishable_tampered_ciphertext() -> None:
    item, blob = _passphrase_item(b"passphrase-sealed plaintext", "correct horse")
    sink = IssueSink()
    result = _run(
        item, (DecryptionPassphrase(passphrase="wrong horse"),), ciphertext=blob, sink=sink
    )
    # A wrong passphrase and a tampered envelope are indistinguishable by
    # design; over an attributable blob the failure is record-condemning.
    assert result.content_check == "mismatched"
    assert result.decryption.decrypted is False
    assert result.decryption.code == "TAMPERED_CIPHERTEXT"


def test_keyring_attempts_every_passphrase() -> None:
    item, blob = _passphrase_item(b"second passphrase wins", "the right one")
    sink = IssueSink()
    result = _run(
        item,
        (
            DecryptionPassphrase(passphrase="not this one"),
            DecryptionPassphrase(passphrase="the right one"),
        ),
        ciphertext=blob,
        sink=sink,
    )
    assert result.decryption.decrypted is True
    assert result.content_check == "checked"


def test_empty_passphrase_surfaces_typed_input_failure() -> None:
    item, blob = _passphrase_item(b"plaintext", "real passphrase")
    sink = IssueSink()
    result = _run(item, (DecryptionPassphrase(passphrase=""),), ciphertext=blob, sink=sink)
    assert result.content_check == "not_checked"
    assert result.decryption.code == "ENC_PASSPHRASE_EMPTY"
    assert any(i.code == "ENC_PASSPHRASE_EMPTY" for i in sink.issues)


# ---- Keyring shape and availability ---------------------------------------------


def test_wrong_shape_keyring_for_slots_item() -> None:
    kp = x25519_keygen()
    item, ciphertext = _sealed_item(b"slots item", kp["public_key"])
    sink = IssueSink()
    result = _run(
        item, (DecryptionPassphrase(passphrase="a passphrase"),), ciphertext=ciphertext, sink=sink
    )
    assert result.content_check == "not_checked"
    assert result.decryption.code == "WRONG_DECRYPTION_INPUT_SHAPE"
    issue = next(i for i in sink.issues if i.code == "WRONG_DECRYPTION_INPUT_SHAPE")
    assert issue.severity == "error"
    assert issue.path == ("items", 0, "enc")


def test_wrong_shape_keyring_for_passphrase_item() -> None:
    kp = x25519_keygen()
    item, blob = _passphrase_item(b"passphrase item", "secret")
    sink = IssueSink()
    result = _run(
        item,
        (DecryptionRecipient(recipient_secret_key=kp["secret_key"]),),
        ciphertext=blob,
        sink=sink,
    )
    assert result.decryption.code == "WRONG_DECRYPTION_INPUT_SHAPE"


def test_no_blob_obtainable_is_ciphertext_unavailable() -> None:
    kp = x25519_keygen()
    item, _ = _sealed_item(b"unreachable ciphertext", kp["public_key"])
    sink = IssueSink()
    result = _run(
        item,
        (DecryptionRecipient(recipient_secret_key=kp["secret_key"]),),
        ciphertext=None,  # no out-of-band bytes and the item carries no uris
        sink=sink,
    )
    assert result.content_check == "not_checked"
    assert result.decryption.decrypted is False
    assert result.decryption.code == "CIPHERTEXT_UNAVAILABLE"
    issue = next(i for i in sink.issues if i.code == "CIPHERTEXT_UNAVAILABLE")
    assert issue.severity == "error"
    assert issue.path == ("items", 0)
