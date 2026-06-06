from __future__ import annotations

from typing import Final, TypedDict

from .kdf import hkdf_sha256
from .kem import x25519_public_key
from .mlkem768x25519 import xwing_keygen
from .sig import get_public_key_ed25519

# HKDF info constants for the long-term identity keypairs. The literal
# byte sequences are part of the protocol; every conformant implementation
# MUST hash against these exact ASCII bytes.
INFO_ED25519: Final[bytes] = b"cardano-poe-ed25519-v1"
INFO_X25519: Final[bytes] = b"cardano-poe-x25519-v1"
# INFO_MLKEM768X25519 labels the HKDF expansion that produces the 32-byte
# X-Wing root seed for the post-quantum hybrid KEM keypair. Like the others,
# the exact ASCII bytes are part of the derivation and MUST match across
# implementations.
INFO_MLKEM768X25519: Final[bytes] = b"cardano-poe-mlkem768x25519-v1"

if len(INFO_ED25519) != 22:
    raise RuntimeError("INFO_ED25519 byte-length invariant violated (expected 22)")
if len(INFO_X25519) != 21:
    raise RuntimeError("INFO_X25519 byte-length invariant violated (expected 21)")
if len(INFO_MLKEM768X25519) != 29:
    raise RuntimeError("INFO_MLKEM768X25519 byte-length invariant violated (expected 29)")

_EMPTY_SALT: Final[bytes] = b""
_SEED_LENGTH: Final[int] = 32
_DERIVED_LENGTH: Final[int] = 32


class DerivedEd25519KeyPair(TypedDict):
    secret_key: bytes
    public_key: bytes


class DerivedX25519KeyPair(TypedDict):
    secret_key: bytes
    public_key: bytes


class DerivedMlKem768X25519KeyPair(TypedDict):
    secret_seed: bytes
    public_key: bytes


class SeedDeriveError(Exception):
    INVALID_SEED_LENGTH = "INVALID_SEED_LENGTH"

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code: str = code


def _assert_seed_length(seed: bytes) -> None:
    if len(seed) != _SEED_LENGTH:
        raise SeedDeriveError(
            SeedDeriveError.INVALID_SEED_LENGTH,
            f"seed must be exactly 32 bytes, got {len(seed)}",
        )


def derive_ed25519_keypair_from_seed(seed: bytes) -> DerivedEd25519KeyPair:
    _assert_seed_length(seed)
    secret_key = hkdf_sha256(
        ikm=seed,
        salt=_EMPTY_SALT,
        info=INFO_ED25519,
        length=_DERIVED_LENGTH,
    )
    public_key = get_public_key_ed25519(secret_key)
    return DerivedEd25519KeyPair(secret_key=secret_key, public_key=public_key)


def derive_x25519_keypair_from_seed(seed: bytes) -> DerivedX25519KeyPair:
    _assert_seed_length(seed)
    secret_key = hkdf_sha256(
        ikm=seed,
        salt=_EMPTY_SALT,
        info=INFO_X25519,
        length=_DERIVED_LENGTH,
    )
    public_key = x25519_public_key(secret_key)
    return DerivedX25519KeyPair(secret_key=secret_key, public_key=public_key)


def derive_mlkem768x25519_keypair_from_seed(seed: bytes) -> DerivedMlKem768X25519KeyPair:
    _assert_seed_length(seed)
    # The HKDF output IS the X-Wing root seed: the secret key is the seed
    # itself, so the returned secret_seed equals this 32-byte derived value.
    xwing_seed = hkdf_sha256(
        ikm=seed,
        salt=_EMPTY_SALT,
        info=INFO_MLKEM768X25519,
        length=_DERIVED_LENGTH,
    )
    public_key, secret_seed = xwing_keygen(xwing_seed)
    return DerivedMlKem768X25519KeyPair(secret_seed=secret_seed, public_key=public_key)
