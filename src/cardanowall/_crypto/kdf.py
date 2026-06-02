from __future__ import annotations

import hashlib
from typing import Final

from argon2 import low_level
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

PBKDF2_SHA256_ITERATIONS_FLOOR: Final[int] = 600_000
PBKDF2_SHA256_OUT_BYTES: Final[int] = 32


def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info,
    ).derive(ikm)


def argon2id_v13(
    password: bytes,
    salt: bytes,
    mem_size_kb: int,
    iterations: int,
    parallelism: int,
    out_bytes: int,
) -> bytes:
    return low_level.hash_secret_raw(
        secret=password,
        salt=salt,
        time_cost=iterations,
        memory_cost=mem_size_kb,
        parallelism=parallelism,
        hash_len=out_bytes,
        type=low_level.Type.ID,
    )


def pbkdf2_sha256(
    password: bytes,
    salt: bytes,
    iterations: int,
    out_bytes: int = PBKDF2_SHA256_OUT_BYTES,
) -> bytes:
    if iterations < PBKDF2_SHA256_ITERATIONS_FLOOR:
        raise ValueError(
            f"pbkdf2-sha-256 iterations {iterations} below floor {PBKDF2_SHA256_ITERATIONS_FLOOR}"
        )
    return hashlib.pbkdf2_hmac("sha256", password, salt, iterations, out_bytes)
