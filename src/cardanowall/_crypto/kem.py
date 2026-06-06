from __future__ import annotations

import hmac
from typing import Final, TypedDict

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

_X25519_SHARED_SECRET_LENGTH: Final[int] = 32
_X25519_ALL_ZERO_SHARED: Final[bytes] = b"\x00" * _X25519_SHARED_SECRET_LENGTH


class X25519LowOrderPointError(Exception):
    # RFC 7748 §6.1 contributory-behaviour rejection: a small-order (low-order)
    # Montgomery `u` coordinate makes the X25519 shared secret all-zero, which
    # PyCA `cryptography` refuses with `ValueError: Error computing shared key.`
    # Surfacing it as a *typed* error lets callers distinguish a structurally
    # valid-but-malicious peer public key (attacker-supplied wire data —
    # trial-decrypt MUST treat the slot as a non-match, not crash) from genuine
    # caller misuse such as a wrong-length key (raised by from_public_bytes,
    # which we deliberately let propagate as the original ValueError).
    code = "X25519_LOW_ORDER_POINT"

    def __init__(self) -> None:
        super().__init__("x25519 ECDH rejected: peer public key is a small-order point")


class X25519KeyPair(TypedDict):
    secret_key: bytes
    public_key: bytes


def x25519_keygen() -> X25519KeyPair:
    priv = X25519PrivateKey.generate()
    secret_key = priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_key = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return X25519KeyPair(secret_key=secret_key, public_key=public_key)


def x25519_public_key(secret_key: bytes) -> bytes:
    priv = X25519PrivateKey.from_private_bytes(secret_key)
    return priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def x25519_ecdh(secret_key: bytes, their_public_key: bytes) -> bytes:
    priv = X25519PrivateKey.from_private_bytes(secret_key)
    # A wrong-length key raises here (caller misuse) — let it propagate as-is.
    pub = X25519PublicKey.from_public_bytes(their_public_key)
    try:
        shared = priv.exchange(pub)
    except ValueError as e:
        # `exchange` only fails when the peer public key is a small-order point
        # (all-zero shared secret). Translate that — and only that — into our
        # typed error so trial-decrypt can treat the slot as a non-match.
        raise X25519LowOrderPointError() from e
    # Reject the all-zero shared secret directly (RFC 7748 §6.1 contributory
    # check) rather than relying on the backend to do it transitively. The
    # comparison is constant-time so the rejection leaks no timing on the
    # shared-secret bytes; a peer public key that drives the shared secret to
    # zero is treated identically to a small-order point.
    if hmac.compare_digest(shared, _X25519_ALL_ZERO_SHARED):
        raise X25519LowOrderPointError()
    return shared
