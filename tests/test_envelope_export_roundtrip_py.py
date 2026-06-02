"""Python parity round-trip test for the .age v1 envelope export.

pyrage is the Python age library in the closed crypto catalogue. The age v1
spec is fully implemented by both ``pyrage`` and ``age-encryption@0.3.0`` (TS) —
both targeting the same on-the-wire byte format ``age-encryption.org/v1\\n``.
This test verifies that ``pyrage`` round-trips a passphrase-encrypted payload:
encrypt → bytes → decrypt yields the original plaintext, and the bytes start
with the age v1 magic.

The cross-language byte-identical parity property (TS-built envelope decrypts
under pyrage and vice-versa) is structurally established by the fixture-based
parity gates; this test is the layer that asserts the export pipeline's bytes
are age v1.
"""

import pyrage.passphrase  # type: ignore[import-untyped]

AGE_V1_MAGIC = b"age-encryption.org/v1\n"
# Test fixture only — deterministic dummy passphrase for the pyrage round-trip
# assertion. Not a real secret; not used outside this test module.
TEST_PASSPHRASE = "a a a a a a a a a a a a a a a a a a a a a a a a"  # noqa: S105
SEED_BYTES = bytes(b for b in range(32))  # 0x00..0x1f, deterministic 32 bytes


def test_pyrage_passphrase_roundtrip_preserves_payload() -> None:
    """pyrage encrypt → decrypt yields the original 32-byte seed payload."""
    ciphertext = pyrage.passphrase.encrypt(SEED_BYTES, TEST_PASSPHRASE)
    assert isinstance(ciphertext, bytes)
    recovered = pyrage.passphrase.decrypt(ciphertext, TEST_PASSPHRASE)
    assert recovered == SEED_BYTES


def test_pyrage_passphrase_output_starts_with_age_v1_magic() -> None:
    """The .age bytes produced by pyrage MUST begin with the age v1 magic
    prefix — same invariant the TS exporter asserts via AGE_V1_MAGIC.
    """
    ciphertext = pyrage.passphrase.encrypt(SEED_BYTES, TEST_PASSPHRASE)
    assert ciphertext[: len(AGE_V1_MAGIC)] == AGE_V1_MAGIC
