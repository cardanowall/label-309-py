from __future__ import annotations

import hashlib
import hmac
from collections.abc import Sequence
from typing import Final, cast

from cardanowall._crypto.cbor import CanonicalCborValue, encode_canonical_cbor
from cardanowall._crypto.cose_key import parse_cose_key_ed25519
from cardanowall._crypto.cose_sign1 import (
    CoseSign1Decoded,
    CoseVerifyError,
    build_sig_structure,
    decode_cose_sign1,
)
from cardanowall._crypto.sig import verify_ed25519
from cardanowall.poe_standard import PoeRecord, bytes_chunk_array_concat

from .types import (
    SigFailureReason,
    SignatureVerdict,
    SignerType,
    VerifyRecordSignature,
    VerifyTxInput,
)

# The 25-byte UTF-8 domain prefix MUST be prepended to the payload
# (`Sig_structure[3] = to_sign`), NOT placed in `external_aad`. CIP-30
# wallets sign with `external_aad = h''`; embedding the prefix in `to_sign`
# preserves cross-protocol replay protection while keeping wallet-produced
# signatures byte-identical to verifier-side recomputation.
CARDANO_POE_SIG_DOMAIN_PREFIX: Final[bytes] = b"cardano-poe-record-sig-v1"

if len(CARDANO_POE_SIG_DOMAIN_PREFIX) != 25:
    raise RuntimeError("CARDANO_POE_SIG_DOMAIN_PREFIX byte-length invariant violated (expected 25)")

# `Sig_structure[2]` (external_aad) is ALWAYS the empty byte string in
# conformant v1 records.
_EMPTY_EXTERNAL_AAD: Final[bytes] = b""

# `sigs` is excluded from the signed payload — the to-be-signed bytes are
# the record body MINUS the `sigs` field (a signature cannot cover itself).
# `crit` IS included so a critical-extension downgrade does not slip past
# the signer.
_RECORD_SIG_STRIP_KEYS: Final[frozenset[str]] = frozenset({"sigs"})

# Mainnet stake-address network header byte per CIP-19. v1 binds the
# wallet path to stake addresses only; a 29-byte CIP-19 stake address is
# `network_header_byte || Blake2b-224(stake_vkey)`.
_CIP19_STAKE_NETWORK_HEADER_MAINNET: Final[int] = 0xE1
_CIP19_STAKE_ADDRESS_LENGTH: Final[int] = 29
_BLAKE2B_224_DIGEST_LENGTH: Final[int] = 28


def _record_to_dict_minus_sigs(record: PoeRecord) -> dict[str, object]:
    # `PoeRecord` is a TypedDict — at runtime it is a plain dict, so a shallow
    # copy filtered by `_RECORD_SIG_STRIP_KEYS` is sufficient. We rely on
    # producer-side construction to keep field values immutable; the nested
    # `items` / `merkle` / `enc` shapes are passed through as-is into the
    # canonical-CBOR encoder.
    return {k: v for k, v in record.items() if k not in _RECORD_SIG_STRIP_KEYS}


def _blake2b_224(data: bytes) -> bytes:
    # Wallet stake-address binding uses Blake2b-224 (28-byte digest).
    # hashlib.blake2b supports a configurable digest_size.
    return hashlib.blake2b(data, digest_size=_BLAKE2B_224_DIGEST_LENGTH).digest()


# Map each per-entry failure reason to its 4-state verdict, byte-identical to
# the TypeScript twin: a public hash-only PoE stays `valid` on `unsupported`;
# `unresolved` is its own verdict; every other failure collapses to `invalid`.
def _verdict_for_reason(reason: SigFailureReason) -> SignatureVerdict:
    if reason == "SIGNATURE_UNSUPPORTED":
        return "unsupported"
    if reason == "SIGNER_KEY_UNRESOLVED":
        return "unresolved"
    return "invalid"


async def verify_record_signatures(
    record: PoeRecord, input: VerifyTxInput
) -> tuple[VerifyRecordSignature, ...]:
    # to_sign = domain_prefix || canonical_cbor(record_body_without_sigs).
    record_body = encode_canonical_cbor(
        cast(CanonicalCborValue, _record_to_dict_minus_sigs(record))
    )
    to_sign = CARDANO_POE_SIG_DOMAIN_PREFIX + record_body
    out: list[VerifyRecordSignature] = []
    sigs = record.get("sigs") or ()
    for i, sig_entry in enumerate(sigs):
        sig_chunks = sig_entry["cose_sign1"]
        signer_key_chunks = sig_entry.get("cose_key")
        out.append(
            await _verify_one(
                index=i,
                sig_chunks=sig_chunks,
                signer_key_chunks=signer_key_chunks,
                to_sign=to_sign,
            )
        )
    return tuple(out)


async def _verify_one(
    *,
    index: int,
    sig_chunks: Sequence[bytes],
    signer_key_chunks: Sequence[bytes] | None,
    to_sign: bytes,
) -> VerifyRecordSignature:
    try:
        cose = decode_cose_sign1(bytes_chunk_array_concat(list(sig_chunks)))
    except CoseVerifyError:
        return VerifyRecordSignature(
            index=index, verdict="invalid", reason="MALFORMED_SIG_COSE_SIGN1"
        )
    # RFC 9052 §4.1: detached form MUST encode payload as nil; a zero-length
    # byte string is NOT equivalent and MUST be rejected.
    if cose["payload"] is not None:
        return VerifyRecordSignature(
            index=index, verdict="invalid", reason="MALFORMED_SIG_COSE_SIGN1"
        )
    alg = cose["protected_header"].get(1)
    if not isinstance(alg, int) or isinstance(alg, bool) or alg != -8:
        # SIGNATURE_UNSUPPORTED is info severity; the caller decides whether the
        # per-entry failure escalates the verdict based on the record's role
        # (public hash-only PoE remains 'valid').
        return VerifyRecordSignature(
            index=index, verdict="unsupported", reason="SIGNATURE_UNSUPPORTED"
        )
    resolved = _resolve_signer_key(cose, signer_key_chunks)
    if resolved is None:
        return VerifyRecordSignature(
            index=index, verdict="unresolved", reason="SIGNER_KEY_UNRESOLVED"
        )
    signer_pub, signer_type = resolved
    if len(signer_pub) != 32:
        return VerifyRecordSignature(
            index=index, verdict="unresolved", reason="SIGNER_KEY_UNRESOLVED"
        )
    signer_pub_hex = signer_pub.hex()

    # Sig_structure = ["Signature1", protected_bytes, h'', to_sign].
    # CIP-8 `hashed = true` mode: when the unprotected header carries
    # `"hashed": True`, substitute `Sig_structure[3]` with `Blake2b-224(to_sign)`
    # (28-byte digest of the FULL `to_sign` payload including the domain prefix).
    if cose["unprotected_header"].get("hashed") is True:
        sig_payload = _blake2b_224(to_sign)
    else:
        sig_payload = to_sign
    sig_struct = build_sig_structure(
        context="Signature1",
        body_protected_bytes=cose["protected_bytes"],
        external_aad=_EMPTY_EXTERNAL_AAD,
        payload=sig_payload,
    )
    if not verify_ed25519(signer_pub, sig_struct, cose["signature"]):
        return VerifyRecordSignature(
            index=index,
            verdict="invalid",
            signer_pub=signer_pub_hex,
            signer_type=signer_type,
            reason="SIGNATURE_INVALID",
        )

    # Path-2-only wallet address binding check. The Ed25519 signature proves
    # only "this pubkey signed the record body"; the address claim is
    # independently unverified.
    if signer_type == "wallet-inline-key":
        address_claim = cose["protected_header"].get("address")
        if not _wallet_address_binds_pubkey(address_claim, signer_pub):
            return VerifyRecordSignature(
                index=index,
                verdict="invalid",
                signer_pub=signer_pub_hex,
                signer_type=signer_type,
                reason="WALLET_ADDRESS_MISMATCH",
            )

    return VerifyRecordSignature(
        index=index,
        verdict="valid",
        signer_pub=signer_pub_hex,
        signer_type=signer_type,
    )


def _wallet_address_binds_pubkey(address_claim: object, pubkey: bytes) -> bool:
    """Wallet `address` ↔ `cose_key` binding.

    Recompute `address_derived = 0xE1 || Blake2b-224(pubkey)` and compare
    byte-equal under `hmac.compare_digest` against the protected-header
    `address` claim. v1 binds to mainnet stake addresses only — a non-29-byte
    `address` or a non-bytes value MUST fail this check.
    """
    if not isinstance(address_claim, bytes):
        return False
    if len(address_claim) != _CIP19_STAKE_ADDRESS_LENGTH:
        return False
    address_derived = bytes([_CIP19_STAKE_NETWORK_HEADER_MAINNET]) + _blake2b_224(pubkey)
    return hmac.compare_digest(address_derived, address_claim)


def _resolve_signer_key(
    cose: CoseSign1Decoded,
    signer_key_chunks: Sequence[bytes] | None,
) -> tuple[bytes, SignerType] | None:
    """Returns `(pub, signer_type)` on success, None on failure.

    Path 1 / path 2 are mutually exclusive at the wire level; the structural
    validator rejects records carrying both (`SIG_ENTRY_KID_COSE_KEY_CONFLICT`).
    The resolution below is a one-of-N selection, not a tie-breaker:

    1. Protected-header `kid` (label 4) if exactly 32 bytes AND no `cose_key`
       blob is present → `in-signature-kid` (raw Ed25519 pubkey).
    2. `sigs[i].cose_key` chunked-bytes COSE_Key blob → `wallet-inline-key`.

    An unprotected-header `kid` is NEVER used as a raw key directly — it sits
    outside the COSE integrity envelope, so an attacker could rewrite it.
    """
    protected_kid = cose["protected_header"].get(4)
    if (
        isinstance(protected_kid, bytes)
        and len(protected_kid) == 32
        and signer_key_chunks is None
    ):
        return protected_kid, "in-signature-kid"
    if signer_key_chunks is not None:
        side_channel_pub = parse_cose_key_ed25519(bytes_chunk_array_concat(list(signer_key_chunks)))
        if side_channel_pub is not None:
            return side_channel_pub, "wallet-inline-key"
    return None


__all__ = ["CARDANO_POE_SIG_DOMAIN_PREFIX", "verify_record_signatures"]
