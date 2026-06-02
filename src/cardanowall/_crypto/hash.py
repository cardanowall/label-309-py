from __future__ import annotations

import hashlib
from collections.abc import Iterable
from typing import TypedDict


class DualHashOutput(TypedDict):
    sha256: bytes
    blake2b256: bytes


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def blake2b_256(data: bytes) -> bytes:
    return hashlib.blake2b(data, digest_size=32).digest()


def dual_hash(data: bytes) -> DualHashOutput:
    return {
        "sha256": sha256(data),
        "blake2b256": blake2b_256(data),
    }


def dual_hash_stream(chunks: Iterable[bytes]) -> DualHashOutput:
    sha = hashlib.sha256()
    blake = hashlib.blake2b(digest_size=32)
    for chunk in chunks:
        sha.update(chunk)
        blake.update(chunk)
    return {
        "sha256": sha.digest(),
        "blake2b256": blake.digest(),
    }
