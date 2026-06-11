"""Label 309 record-level signature verifier.

One verification per ``record.sigs[i]``. v1 has NO per-item signature slot —
the only signature surface is the record-level array. Two on-wire signer-key
paths (mutually exclusive on the wire, enforced by the structural validator
as ``SIG_ENTRY_KID_COSE_KEY_CONFLICT``):

  Path 1 — protected-header ``kid`` is exactly 32 bytes (raw Ed25519 pubkey).
  Path 2 — ``sigs[i].cose_key`` is a single ``cbor<COSE_Key>`` byte string
           carrying the wallet's public key. The protected header carries a
           29-byte CIP-19 stake address at label ``"address"``; the verifier
           recomputes ``expected_network_header || Blake2b-224(pub)`` —
           deriving the network byte from the CONTAINING TRANSACTION's
           network, never echoing the byte found in the record — and rejects
           on any of the 29 bytes (``WALLET_ADDRESS_MISMATCH``).

The producer's protected-header bytes are used VERBATIM as
``Sig_structure[1]`` — never re-encoded or re-canonicalised (RFC 9052 §4.4) —
and the signing body is the canonical de-chunked record body with ``sigs``
removed; both rules are enforced by ``cose_sign1_label309_verify`` in the
crypto layer. Ed25519 verification is strict per RFC 8032 §5.1.7 (canonical
R/S, low-order rejection, no cofactor multiplication).

Record signatures are OPTIONAL: a public hash-only PoE remains valid even
when every signature entry is unverifiable (``SIGNATURE_UNSUPPORTED``, info).
Every ``unsupported`` per-signature verdict puts ``SIGNATURE_UNSUPPORTED``
(info) at ``("sigs", i)`` EXACTLY ONCE: the structural validator contributes
the same issue for UNREGISTERED algorithms, while a registered-but-
unimplemented algorithm is only detected here, so this pass emits
idempotently against the sink. Error-class failures (``SIGNATURE_INVALID``,
``SIGNER_KEY_UNRESOLVED``, ``WALLET_ADDRESS_MISMATCH``,
``MALFORMED_SIG_COSE_SIGN1``) raise issues into the run's sink and fail the
record.
"""

from __future__ import annotations

import hashlib
from typing import Final

from cardanowall._crypto.compare_ct import compare_ct
from cardanowall._crypto.cose_key import parse_cose_key_ed25519
from cardanowall._crypto.cose_sign1 import (
    CARDANO_POE_SIG_DOMAIN_PREFIX,
    CoseSign1Decoded,
    CoseVerifyError,
    cose_sign1_label309_verify,
    decode_cose_sign1,
)
from cardanowall.poe_standard import PoeRecord, SigEntry, encode_record_body_for_signing

from .types import (
    IssueSink,
    NetworkId,
    SigFailureReason,
    SignerType,
    VerifyRecordSignature,
)

# v1 wallet-path constraint: stake (reward) addresses only. The 29-byte
# CIP-19 layout is `network_header_byte || Blake2b-224(stake_vk)`; stake
# network bytes: mainnet = 0xe1, testnet = 0xe0 (preprod and preview share
# the testnet header). The expected byte is derived from the network of the
# transaction CONTAINING the record — never echoed from the byte found in the
# record — so a signature produced for one network and replayed under another
# is rejected.
_CARDANO_MAINNET_STAKE_NETWORK_BYTE: Final[int] = 0xE1
_CARDANO_TESTNET_STAKE_NETWORK_BYTE: Final[int] = 0xE0
_CARDANO_STAKE_ADDRESS_LENGTH: Final[int] = 29
_ED25519_PUBLIC_KEY_LENGTH: Final[int] = 32
_BLAKE2B_224_LENGTH: Final[int] = 28


def verify_record_signatures(
    record: PoeRecord,
    *,
    network: NetworkId = "cardano:mainnet",
    sink: IssueSink | None = None,
) -> tuple[VerifyRecordSignature, ...]:
    """Verify every ``sigs[]`` entry against the canonical record body.

    ``network`` names the network of the transaction CONTAINING the record
    (as established by the verifier's explorer configuration). When ``sink``
    is supplied, every ``invalid`` / ``unresolved`` entry also raises its
    error-severity issue at ``("sigs", i)``.
    """
    # The signed payload is canonical-CBOR(record_body), where record_body =
    # record minus `sigs`. The encoder helper keeps the wire shape and key
    # sort in lockstep with producer-side signing.
    record_body_cbor = encode_record_body_for_signing(record)
    out: list[VerifyRecordSignature] = []
    for i, entry in enumerate(record.get("sigs") or ()):
        result = _verify_one_sig(i, entry, record_body_cbor, network)
        out.append(result)
        if sink is not None and result.verdict in ("invalid", "unresolved"):
            sink.add(
                result.reason or "SIGNATURE_INVALID",
                ("sigs", i),
                _signature_failure_message(result.reason),
            )
        elif sink is not None and result.verdict == "unsupported":
            # An unsupported entry MUST surface as exactly one
            # SIGNATURE_UNSUPPORTED (info) at ("sigs", i). The idempotent add
            # covers both ways an entry gets here: an UNREGISTERED algorithm
            # (the structural validator already contributed the identical
            # issue) and a registered algorithm this verifier does not
            # implement (only this pass detects it).
            sink.add_once(
                "SIGNATURE_UNSUPPORTED",
                ("sigs", i),
                "the COSE_Sign1 signature algorithm is not implemented by this "
                "verifier; the entry is unsupported, not invalid",
            )
    return tuple(out)


def _signature_failure_message(reason: SigFailureReason | None) -> str:
    if reason == "MALFORMED_SIG_COSE_SIGN1":
        return "the cose_sign1 blob is not a verifiable detached COSE_Sign1"
    if reason == "SIGNER_KEY_UNRESOLVED":
        return "neither key-resolution path yielded a 32-byte Ed25519 public key"
    if reason == "WALLET_ADDRESS_MISMATCH":
        return (
            "the wallet-path protected-header address does not equal the recomputed "
            "network_header || Blake2b-224(pubkey)"
        )
    return "strict Ed25519 verification failed against the resolved public key"


def _verify_one_sig(
    index: int,
    entry: SigEntry,
    record_body_cbor: bytes,
    network: NetworkId,
) -> VerifyRecordSignature:
    cose_bytes = entry["cose_sign1"]
    try:
        cose = decode_cose_sign1(cose_bytes)
    except CoseVerifyError:
        return VerifyRecordSignature(
            index=index, verdict="invalid", reason="MALFORMED_SIG_COSE_SIGN1"
        )

    # Resolve the signer's 32-byte Ed25519 pubkey (path 1 vs path 2).
    resolved = _resolve_signer_key(cose, entry)
    if resolved is None:
        return VerifyRecordSignature(
            index=index, verdict="unresolved", reason="SIGNER_KEY_UNRESOLVED"
        )
    pub, signer_type = resolved
    signer_pub_hex = pub.hex()

    # Strict Ed25519 verify; Sig_structure[1] is the producer's protected
    # bytes verbatim, and the CIP-8 hashed mode is handled inside the helper.
    verify_result = cose_sign1_label309_verify(
        message=cose_bytes,
        detached_record_body_cbor=record_body_cbor,
        expected_signer_key=pub,
    )
    if not verify_result["ok"]:
        reason = _map_verify_error(verify_result["error"]["code"])
        if reason == "SIGNATURE_UNSUPPORTED":
            return VerifyRecordSignature(
                index=index,
                verdict="unsupported",
                signer_pub=signer_pub_hex,
                signer_type=signer_type,
                reason=reason,
            )
        return VerifyRecordSignature(
            index=index,
            verdict="invalid",
            signer_pub=signer_pub_hex,
            signer_type=signer_type,
            reason=reason,
        )

    # Path-2 wallet `address` ↔ `cose_key` binding. Path-1 entries skip this
    # check entirely. The Ed25519 signature proves only "this pubkey signed
    # the record body"; the address claim is independently verified, and it
    # is REQUIRED on the wallet path — an address-less wallet signature gives
    # the verifier nothing to bind and fails the same check.
    if signer_type == "wallet-inline-key" and not _wallet_address_binds_pubkey(cose, pub, network):
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


def _resolve_signer_key(cose: CoseSign1Decoded, entry: SigEntry) -> tuple[bytes, SignerType] | None:
    """Returns ``(pub, signer_type)`` on success, ``None`` on failure.

    Path 1 — protected-header label 4 (``kid``) as the 32-byte raw Ed25519
    pubkey, taken only when no ``cose_key`` blob is present (the validator
    rejects records carrying both). Unprotected-header ``kid`` values are
    NEVER consulted: they sit outside the COSE integrity envelope and an
    attacker could rewrite them.

    Path 2 — a single ``cbor<COSE_Key>`` byte string carrying the wallet
    pubkey.
    """
    protected_kid = cose["protected_header"].get(4)
    signer_key_bytes = entry.get("cose_key")
    if (
        isinstance(protected_kid, bytes)
        and len(protected_kid) == _ED25519_PUBLIC_KEY_LENGTH
        and signer_key_bytes is None
    ):
        return protected_kid, "in-signature-kid"
    if signer_key_bytes is not None:
        pub = parse_cose_key_ed25519(signer_key_bytes)
        if pub is not None and len(pub) == _ED25519_PUBLIC_KEY_LENGTH:
            return pub, "wallet-inline-key"
    return None


def _map_verify_error(code: str) -> SigFailureReason:
    if code in ("MALFORMED_SIG_COSE", "MALFORMED_SIG_COSE_SIGN1"):
        return "MALFORMED_SIG_COSE_SIGN1"
    if code == CoseVerifyError.UNSUPPORTED_SIG_ALG:
        return "SIGNATURE_UNSUPPORTED"
    if code == CoseVerifyError.KID_UNRESOLVED:
        return "SIGNER_KEY_UNRESOLVED"
    return "SIGNATURE_INVALID"


def _blake2b_224(data: bytes) -> bytes:
    return hashlib.blake2b(data, digest_size=_BLAKE2B_224_LENGTH).digest()


# Recompute the 29-byte stake address from the resolved Ed25519 pubkey and
# compare it byte-exact (constant-time) to the path-2 protected-header
# `address` field. The wallet path binds to stake (reward) addresses only in
# v1 — base/enterprise/pointer/payment addresses fail the equality check
# against the recomputed 29-byte stake address.
def _wallet_address_binds_pubkey(cose: CoseSign1Decoded, pub: bytes, network: NetworkId) -> bool:
    network_byte = (
        _CARDANO_MAINNET_STAKE_NETWORK_BYTE
        if network == "cardano:mainnet"
        else _CARDANO_TESTNET_STAKE_NETWORK_BYTE
    )
    raw_address = cose["protected_header"].get("address")
    if not isinstance(raw_address, bytes):
        return False
    if len(raw_address) != _CARDANO_STAKE_ADDRESS_LENGTH:
        return False
    derived = bytes([network_byte]) + _blake2b_224(pub)
    return compare_ct(derived, raw_address)


__all__ = ["CARDANO_POE_SIG_DOMAIN_PREFIX", "verify_record_signatures"]
