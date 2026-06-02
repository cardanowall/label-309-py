from __future__ import annotations

from nacl.encoding import RawEncoder
from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey, VerifyKey


def sign_ed25519(seed: bytes, message: bytes) -> bytes:
    return SigningKey(seed).sign(message).signature


def verify_ed25519(public_key: bytes, message: bytes, signature: bytes) -> bool:
    try:
        VerifyKey(public_key).verify(message, signature)
        return True
    except BadSignatureError:
        return False


def get_public_key_ed25519(seed: bytes) -> bytes:
    return SigningKey(seed).verify_key.encode(encoder=RawEncoder)
