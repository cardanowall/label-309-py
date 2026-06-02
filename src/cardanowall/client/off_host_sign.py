"""CIP-309 v1 off-host signing helper — Python parity twin.

Wire-format invariants enforced by this module:
    - Sig_structure carries the 25-byte UTF-8 domain prefix
      `cardano-poe-record-sig-v1` with `external_aad = h''` (RFC 9052 §4.4).
    - COSE_Sign1 (RFC 9052 §4.2) has a detached payload: COSE_Sign1[2] =
      CBOR null. CIP-8 `hashed = true` mode places the literal text key
      `"hashed"` in the unprotected header.
    - Path-1 `kid-as-public-key` convention: 32-byte raw Ed25519 pubkey in
      protected header label 4; path-1 / path-2 are mutually exclusive on
      the wire.
    - chunked-bytes-array: per-chunk size in [1, 64].

Use cases (the four integration shapes this surface is intended for):
    1. AWS KMS `Sign` over the returned Sig_structure bytes — wrap KMS as
       `(bytes) -> bytes` (sync) or `Callable[[bytes], Awaitable[bytes]]` (async).
    2. Google Cloud HSM — same shape.
    3. YubiHSM — local hardware-backed signer.
    4. Air-gapped offline signer — transport Sig_structure bytes off-machine,
       transport the 64-byte signature back.

This module is PATH-1 ONLY. The CIP-30 wallet path (path-2) is handled
separately; adding `cose_key` here would violate path-1 / path-2 mutual
exclusion.

Hashed-mode (`prepare_sig_structure_hashed` / `assemble_cose_sign1_hashed`)
is DISCOURAGED for software off-host signers — use only for hardware
co-signers with screen / buffer constraints. The verifier substitutes
`Sig_structure[3]` with `Blake2b-224(to_sign)` before strict Ed25519
verification when it detects the unprotected `"hashed": True` flag.

Privacy contract: the SDK never sees, stores, logs, or transmits any byte
string containing the integrator's Ed25519 private signing key. The
integrator's signer handles the seed; this module touches only the 32-byte
public key and the 64-byte signature (both public data).

TypeScript parity twin: the off-host signing helper in ``@cardanowall/sdk-ts``
(camelCase function names). Byte-identical outputs are enforced by the
shared `sign1-build.json` KAT corpus.
"""

from __future__ import annotations

import hashlib
from typing import cast

from cardanowall._crypto.cbor import CanonicalCborValue, encode_canonical_cbor
from cardanowall._crypto.cose_sign1 import (
    CARDANO_POE_SIG_DOMAIN_PREFIX,
    build_cip309_sig_structure,
    build_sig_structure,
    encode_cose_sign1,
)
from cardanowall.poe_standard import (
    PoeRecord,
    SigEntry,
    chunk_bytes,
    encode_record_body_for_signing,
)

_ED25519_PUBLIC_KEY_LENGTH = 32
_ED25519_SIGNATURE_LENGTH = 64
_BLAKE2B_224_DIGEST_SIZE = 28


class OffHostSignError(Exception):
    """Raised when the off-host signing helper receives malformed input.

    `code` discriminator values:
        - "INVALID_PUBKEY_LENGTH" — `signer_pubkey` is not 32 bytes.
        - "INVALID_SIGNATURE_LENGTH" — `signature` is not 64 bytes.
    """

    INVALID_PUBKEY_LENGTH = "INVALID_PUBKEY_LENGTH"
    INVALID_SIGNATURE_LENGTH = "INVALID_SIGNATURE_LENGTH"

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code: str = code


def _encode_path1_protected_header(signer_pubkey: bytes) -> bytes:
    """Canonical-CBOR of `{1: -8, 4: <signer_pubkey>}` — always 38 bytes.

    Layout: `a2 01 27 04 58 20 || <32-byte pubkey>`.
    """
    protected_header: dict[int | str, object] = {1: -8, 4: signer_pubkey}
    return encode_canonical_cbor(cast(CanonicalCborValue, protected_header))


def build_to_sign(record: PoeRecord) -> bytes:
    """Return `utf8("cardano-poe-record-sig-v1") || canonical_cbor(record_body_minus_sigs)`.

    First 25 bytes are the byte-pinned domain prefix; bytes 25.. are the
    canonical CBOR of the record body with `sigs` removed.
    """
    return CARDANO_POE_SIG_DOMAIN_PREFIX + encode_record_body_for_signing(record)


def prepare_sig_structure(
    *,
    record: PoeRecord,
    signer_pubkey: bytes,
) -> tuple[bytes, bytes]:
    """Return `(sig_structure_bytes, protected_header_bytes)`.

    `sig_structure_bytes` is the full canonical-CBOR `Sig_structure =
    [ "Signature1", protected_bytes, h'', to_sign ]` that the off-host signer
    feeds verbatim to Ed25519. `protected_header_bytes` is the canonical
    encoding of the path-1 protected header (always 38 bytes for
    `{1: -8, 4: <pub>}`).
    """
    if len(signer_pubkey) != _ED25519_PUBLIC_KEY_LENGTH:
        raise OffHostSignError(
            OffHostSignError.INVALID_PUBKEY_LENGTH,
            f"signer_pubkey must be 32 bytes (Ed25519 raw public key), got {len(signer_pubkey)}",
        )
    protected_header_bytes = _encode_path1_protected_header(signer_pubkey)
    record_body_cbor = encode_record_body_for_signing(record)
    sig_structure_bytes = build_cip309_sig_structure(
        body_protected_bytes=protected_header_bytes,
        record_body_cbor=record_body_cbor,
    )
    return sig_structure_bytes, protected_header_bytes


def assemble_cose_sign1(
    *,
    record: PoeRecord,
    signer_pubkey: bytes,
    signature: bytes,
) -> tuple[bytes, SigEntry]:
    """Assemble the COSE_Sign1 and chunked `sigs[i]` entry.

    Returns `(cose_sign1_bytes, sig_entry)`. `sig_entry` is `{"cose_sign1":
    chunks}` (path-1 only — no `cose_key` sidecar).
    """
    if len(signer_pubkey) != _ED25519_PUBLIC_KEY_LENGTH:
        raise OffHostSignError(
            OffHostSignError.INVALID_PUBKEY_LENGTH,
            f"signer_pubkey must be 32 bytes (Ed25519 raw public key), got {len(signer_pubkey)}",
        )
    if len(signature) != _ED25519_SIGNATURE_LENGTH:
        raise OffHostSignError(
            OffHostSignError.INVALID_SIGNATURE_LENGTH,
            f"signature must be 64 bytes (Ed25519 raw signature), got {len(signature)}",
        )
    protected_header: dict[int | str, object] = {1: -8, 4: signer_pubkey}
    cose_sign1_bytes = encode_cose_sign1(
        protected_header=protected_header,
        unprotected_header={},
        payload=None,
        signature=signature,
    )
    chunks = chunk_bytes(cose_sign1_bytes)
    sig_entry: SigEntry = cast(SigEntry, {"cose_sign1": chunks})
    return cose_sign1_bytes, sig_entry


def prepare_sig_structure_hashed(
    *,
    record: PoeRecord,
    signer_pubkey: bytes,
) -> tuple[bytes, bytes, bytes]:
    """Return `(sig_structure_bytes, protected_header_bytes, to_sign_hash_bytes)`.

    Substitutes `Sig_structure[3]` with `Blake2b-224(to_sign)`. The hash
    covers the ENTIRE `to_sign` payload (including the 25-byte domain
    prefix) — keeping the domain separator inside the hash boundary
    preserves cross-protocol replay protection even in hashed mode.

    DISCOURAGED for software off-host signers; use only for hardware
    co-signers with screen / buffer constraints.
    """
    if len(signer_pubkey) != _ED25519_PUBLIC_KEY_LENGTH:
        raise OffHostSignError(
            OffHostSignError.INVALID_PUBKEY_LENGTH,
            f"signer_pubkey must be 32 bytes (Ed25519 raw public key), got {len(signer_pubkey)}",
        )
    protected_header_bytes = _encode_path1_protected_header(signer_pubkey)
    to_sign = build_to_sign(record)
    to_sign_hash_bytes = hashlib.blake2b(to_sign, digest_size=_BLAKE2B_224_DIGEST_SIZE).digest()
    sig_structure_bytes = build_sig_structure(
        context="Signature1",
        body_protected_bytes=protected_header_bytes,
        external_aad=b"",
        payload=to_sign_hash_bytes,
    )
    return sig_structure_bytes, protected_header_bytes, to_sign_hash_bytes


def assemble_cose_sign1_hashed(
    *,
    record: PoeRecord,
    signer_pubkey: bytes,
    signature: bytes,
) -> tuple[bytes, SigEntry]:
    """Assemble a hashed-mode COSE_Sign1.

    The unprotected header carries `"hashed": True`, signalling to the
    verifier that the Blake2b-224 substitution applies.
    """
    if len(signer_pubkey) != _ED25519_PUBLIC_KEY_LENGTH:
        raise OffHostSignError(
            OffHostSignError.INVALID_PUBKEY_LENGTH,
            f"signer_pubkey must be 32 bytes (Ed25519 raw public key), got {len(signer_pubkey)}",
        )
    if len(signature) != _ED25519_SIGNATURE_LENGTH:
        raise OffHostSignError(
            OffHostSignError.INVALID_SIGNATURE_LENGTH,
            f"signature must be 64 bytes (Ed25519 raw signature), got {len(signature)}",
        )
    protected_header: dict[int | str, object] = {1: -8, 4: signer_pubkey}
    unprotected_header: dict[int | str, object] = {"hashed": True}
    cose_sign1_bytes = encode_cose_sign1(
        protected_header=protected_header,
        unprotected_header=unprotected_header,
        payload=None,
        signature=signature,
    )
    chunks = chunk_bytes(cose_sign1_bytes)
    sig_entry: SigEntry = cast(SigEntry, {"cose_sign1": chunks})
    return cose_sign1_bytes, sig_entry


__all__ = [
    "OffHostSignError",
    "assemble_cose_sign1",
    "assemble_cose_sign1_hashed",
    "build_to_sign",
    "prepare_sig_structure",
    "prepare_sig_structure_hashed",
]
