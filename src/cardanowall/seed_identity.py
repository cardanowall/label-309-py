"""Raw-seed identity surface (parity twin of ``@cardanowall/sdk-ts`` identity).

A developer holding a 32-byte seed can, from the public SDK and with no account
envelope:

  1. derive every identity keypair (:func:`derive_keys_from_seed`);
  2. obtain their own age recipient strings (:func:`recipients_from_seed`);
  3. get a path-1 :class:`~cardanowall.client.Signer` for the publish helpers
     (:func:`signer_from_seed`);
  4. build the per-KEM recipient secret lists the unwrap dispatch consumes
     (:func:`recipient_secret_keys_from_seed`) and decrypt a sealed PoE
     (:func:`decrypt_sealed_from_seed`);
  5. compose 3 + 4 with the gateway-agnostic client to sign and publish, or to
     receive and read, entirely from the seed.

The seed is the only secret this module touches. Callers are responsible for
sourcing it securely; the SDK never persists or logs it.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import TypedDict

from ._crypto.sealed_poe import KEM_X25519 as _KEM_X25519
from ._crypto.sealed_poe import SealedEnvelope, UnwrapResult, ecies_sealed_poe_unwrap
from ._crypto.seed_derive import (
    DerivedEd25519KeyPair,
    DerivedMlKem768X25519KeyPair,
    DerivedX25519KeyPair,
    derive_ed25519_keypair_from_seed,
    derive_mlkem768x25519_keypair_from_seed,
    derive_x25519_keypair_from_seed,
)
from ._crypto.sig import sign_ed25519
from .recipient import encode_age_x25519_recipient, encode_age_xwing_recipient


class SeedKeys(TypedDict):
    """The three identity keypairs derived from one 32-byte seed."""

    ed25519: DerivedEd25519KeyPair
    x25519: DerivedX25519KeyPair
    mlkem768x25519: DerivedMlKem768X25519KeyPair


def derive_keys_from_seed(seed: bytes) -> SeedKeys:
    """Derive the Ed25519 (sign), X25519 (classic KEM), and X-Wing (PQ KEM)
    keypairs from a 32-byte seed."""
    return SeedKeys(
        ed25519=derive_ed25519_keypair_from_seed(seed),
        x25519=derive_x25519_keypair_from_seed(seed),
        mlkem768x25519=derive_mlkem768x25519_keypair_from_seed(seed),
    )


class SeedRecipients(TypedDict):
    """The recipient strings other senders use to address this identity."""

    age: str
    age1pqc: str


def recipients_from_seed(seed: bytes) -> SeedRecipients:
    """Return both age recipient strings for the identity derived from ``seed``.

    ``age`` is the classical X25519 recipient ("age1..."); ``age1pqc`` is the
    X-Wing hybrid recipient ("age1pqc...") for the ML-KEM-768 + X25519 KEM.
    """
    keys = derive_keys_from_seed(seed)
    return SeedRecipients(
        age=encode_age_x25519_recipient(keys["x25519"]["public_key"]),
        age1pqc=encode_age_xwing_recipient(keys["mlkem768x25519"]["public_key"]),
    )


@dataclass(frozen=True)
class SeedSigner:
    """An in-memory path-1 signer built from a seed.

    Satisfies the :class:`~cardanowall.client.Signer` protocol, so it can be
    passed straight to ``client.poe.publish_content(signer=...)`` and the other
    publish helpers. Holds the derived 32-byte Ed25519 secret key; the publish
    path itself only reads :attr:`signer_pubkey` (public) and the 64-byte
    signature this returns.
    """

    signer_pubkey: bytes
    _secret_key: bytes

    def sign(self, sig_structure_bytes: bytes, /) -> bytes:
        # `sign_ed25519` takes the 32-byte secret key as the noble-compatible
        # seed and returns a 64-byte raw Ed25519 signature over the canonical
        # Label 309 Sig_structure bytes the publish helpers pass in.
        return sign_ed25519(self._secret_key, sig_structure_bytes)


def signer_from_seed(seed: bytes) -> SeedSigner:
    """Build a path-1 :class:`SeedSigner` from a 32-byte seed."""
    pair = derive_ed25519_keypair_from_seed(seed)
    return SeedSigner(signer_pubkey=pair["public_key"], _secret_key=pair["secret_key"])


def recipient_secret_keys_from_seed(seed: bytes) -> dict[str, list[bytes]]:
    """The per-KEM recipient secret lists the unwrap dispatch consumes.

    Mirrors the TypeScript ``RecipientKeyBundle``: an X25519 private-key chain
    and an X-Wing secret-seed list. Both are one-element for a single active
    identity. Keyed by the envelope-level ``kem`` discriminator
    (``"x25519"`` / ``"mlkem768x25519"``) so a caller can select the matching
    list for a given envelope.
    """
    keys = derive_keys_from_seed(seed)
    return {
        "x25519": [keys["x25519"]["secret_key"]],
        "mlkem768x25519": [keys["mlkem768x25519"]["secret_seed"]],
    }


def decrypt_sealed_from_seed(
    *, seed: bytes, envelope: SealedEnvelope, ciphertext: bytes, hashes: Mapping[str, bytes]
) -> UnwrapResult:
    """Decrypt a sealed PoE (envelope + ciphertext) from the seed.

    Derives the recipient keys, selects the single secret matching
    ``envelope.kem`` (the X25519 secret key for the classical path, the X-Wing
    secret seed for the hybrid path), and runs the single-priv unwrap.
    ``hashes`` is the item's content-hash map — the slots transcript binds its
    digest, so the on-chain MAC match confirms the envelope was sealed for this
    item's hash claim. Never throws on an authentication failure -- returns the
    discriminated :class:`~cardanowall._crypto.sealed_poe.UnwrapResult`
    (``matched`` / ``plaintext`` / ``reason``).
    """
    keys = derive_keys_from_seed(seed)
    secret = (
        keys["x25519"]["secret_key"]
        if envelope.kem == _KEM_X25519
        else keys["mlkem768x25519"]["secret_seed"]
    )
    return ecies_sealed_poe_unwrap(
        envelope=envelope, ciphertext=ciphertext, hashes=hashes, recipient_secret_key=secret
    )


__all__ = [
    "SeedKeys",
    "SeedRecipients",
    "SeedSigner",
    "decrypt_sealed_from_seed",
    "derive_keys_from_seed",
    "recipient_secret_keys_from_seed",
    "recipients_from_seed",
    "signer_from_seed",
]
