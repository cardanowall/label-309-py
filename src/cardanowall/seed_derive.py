"""Public seed-derivation surface (parity twin of ``@cardanowall/sdk-ts``).

Re-exports the deterministic identity-key derivation primitives so a developer
holding a 32-byte seed can derive every keypair without an account envelope. The
three derivations are content-addressed by fixed HKDF info labels and are
byte-identical to the TypeScript ``deriveEd25519KeypairFromSeed`` /
``deriveX25519KeypairFromSeed`` / ``deriveMlKem768X25519KeypairFromSeed``.
"""

from __future__ import annotations

from ._crypto.seed_derive import (
    DerivedEd25519KeyPair,
    DerivedMlKem768X25519KeyPair,
    DerivedX25519KeyPair,
    SeedDeriveError,
    derive_ed25519_keypair_from_seed,
    derive_mlkem768x25519_keypair_from_seed,
    derive_x25519_keypair_from_seed,
)

__all__ = [
    "DerivedEd25519KeyPair",
    "DerivedMlKem768X25519KeyPair",
    "DerivedX25519KeyPair",
    "SeedDeriveError",
    "derive_ed25519_keypair_from_seed",
    "derive_mlkem768x25519_keypair_from_seed",
    "derive_x25519_keypair_from_seed",
]
