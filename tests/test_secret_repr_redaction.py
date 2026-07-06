"""Regression: secret-bearing types never surface their secret via ``repr`` /
``str``.

A ``repr`` in a log line, error chain, or traceback must never leak a recipient
private key, a passphrase, a content-encryption key, or recovered plaintext. The
crypto keyring / result types (:class:`RecipientKeyBundle`, :class:`UnwrapResult`,
:class:`TrialDecryptOnlyResult`) and the verifier decryption credentials
(:class:`DecryptionRecipient`, :class:`DecryptionPassphrase`) each hand-write a
redacting ``__repr__`` that shows only non-secret metadata behind a
``<redacted>`` placeholder.
"""

from __future__ import annotations

from cardanowall._crypto.sealed_poe import (
    RecipientKeyBundle,
    TrialDecryptOnlyResult,
    UnwrapResult,
)
from cardanowall.verifier.types import DecryptionPassphrase, DecryptionRecipient

# Distinctive secret markers: a byte pattern (checked as hex AND as its raw
# bytes-repr escape form) and a passphrase string that would be obvious in a log.
_SECRET_KEY = bytes.fromhex("deadbeef") * 8  # 32 bytes
_SECRET_KEY_HEX = _SECRET_KEY.hex()
_SECRET_PLAINTEXT = b"TOPSECRET-recovered-plaintext-should-never-appear"
_SECRET_PASSPHRASE = "hunter2-passphrase-should-never-appear"


def _forms(value: object) -> list[str]:
    """Every string projection a stray log/format call could produce."""
    return [repr(value), str(value), f"{value}", f"{value!r}", format(value)]


def _assert_absent(value: object, *secrets: str | bytes) -> None:
    for text in _forms(value):
        for secret in secrets:
            needle = secret if isinstance(secret, str) else repr(secret)
            assert needle not in text, f"secret leaked in {text!r}"
            if isinstance(secret, bytes):
                # Also reject the raw byte escape sequence (e.g. "\\xde\\xad").
                assert secret.hex() not in text


def test_recipient_key_bundle_repr_redacts_the_keys() -> None:
    bundle = RecipientKeyBundle(
        x25519_private_keys=[_SECRET_KEY],
        mlkem768x25519_secret_seeds=[_SECRET_KEY, _SECRET_KEY],
    )
    _assert_absent(bundle, _SECRET_KEY, _SECRET_KEY_HEX)
    # Non-secret metadata (the counts) is still shown.
    assert "1 key(s)" in repr(bundle)
    assert "2 seed(s)" in repr(bundle)
    assert "<redacted" in repr(bundle)


def test_unwrap_result_repr_redacts_the_plaintext() -> None:
    matched = UnwrapResult(matched=True, plaintext=_SECRET_PLAINTEXT, reason=None)
    _assert_absent(matched, _SECRET_PLAINTEXT)
    # The byte length is non-secret and useful; matched flag is preserved.
    assert f"{len(_SECRET_PLAINTEXT)} byte(s)" in repr(matched)
    assert "matched=True" in repr(matched)
    # A no-match result carries a non-secret reason discriminator.
    no_match = UnwrapResult(matched=False, plaintext=None, reason="WRONG_RECIPIENT_KEY")
    assert "WRONG_RECIPIENT_KEY" in repr(no_match)


def test_trial_decrypt_result_repr_redacts_the_cek() -> None:
    result = TrialDecryptOnlyResult(kind="match", slot_idx=2, cek=_SECRET_KEY)
    _assert_absent(result, _SECRET_KEY, _SECRET_KEY_HEX)
    # The accepted-slot index and match kind are non-secret.
    assert "slot_idx=2" in repr(result)
    assert "kind='match'" in repr(result)
    assert "cek=<redacted>" in repr(result)


def test_decryption_recipient_repr_redacts_the_private_key() -> None:
    credential = DecryptionRecipient(recipient_secret_key=_SECRET_KEY)
    _assert_absent(credential, _SECRET_KEY, _SECRET_KEY_HEX)
    assert "<redacted>" in repr(credential)


def test_decryption_passphrase_repr_redacts_the_passphrase() -> None:
    credential = DecryptionPassphrase(passphrase=_SECRET_PASSPHRASE)
    _assert_absent(credential, _SECRET_PASSPHRASE)
    assert "<redacted>" in repr(credential)
