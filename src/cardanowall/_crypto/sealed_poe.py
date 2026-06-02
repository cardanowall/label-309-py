# Multi-recipient sealed-PoE wrap (age-style ECIES + AEAD-bound slots).
# Wire-field names: scheme, aead, kem, nonce, slots, slots_mac.
#
# Two KEM branches share one envelope shape, discriminated on the envelope-level
# `kem` field:
#
#   • kem == "x25519"          — classical age-style ECIES. Per-slot epk(32) + wrap(48).
#   • kem == "mlkem768x25519"  — X-Wing hybrid (ML-KEM-768 + X25519). Per-slot the
#                                1120-byte X-Wing enc carried as a chunked byte-string
#                                array (`kem_ct`) + wrap(48). No per-slot epk.
#
# `SealedSlot` is a single dataclass with optional fields; a slot is classical
# when `epk` is present and hybrid when `kem_ct` is present (the reassembled
# 1120-byte enc, held flat in memory and chunked only at CBOR-serialization time).

from __future__ import annotations

import hashlib
import hmac as stdlib_hmac
import secrets
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Final

from .aead import (
    AeadVerificationError,
    chacha20_poly1305_decrypt,
    chacha20_poly1305_encrypt,
    xchacha20_poly1305_decrypt,
    xchacha20_poly1305_encrypt,
)
from .cbor import CanonicalCborValue, encode_canonical_cbor
from .compare_ct import compare_ct
from .kdf import hkdf_sha256
from .kem import X25519LowOrderPointError, x25519_ecdh, x25519_public_key
from .mlkem768x25519 import xwing_decapsulate, xwing_encapsulate

# HKDF info strings are fixed protocol labels. The byte-length invariants
# below pin the SCREAMING_SNAKE constants to the on-wire ASCII literals every
# conformant verifier hashes against.
CARDANO_POE_HKDF_INFO_KEK: Final[bytes] = b"cardano-poe-kek-v1"
# Hybrid (X-Wing) per-slot KEK label. Distinct from the classical label so a KEK
# derived under one KEM can never collide with the other. Reused verbatim as the
# per-slot wrap AEAD AAD, exactly as the classical path reuses its own label.
CARDANO_POE_HKDF_INFO_KEK_MLKEM768X25519: Final[bytes] = b"cardano-poe-kek-mlkem768x25519-v1"
CARDANO_POE_HKDF_INFO_SLOTS_MAC: Final[bytes] = b"cardano-poe-slots-mac-v1"

UNWRAP_REASON_WRONG_RECIPIENT_KEY: Final[str] = "WRONG_RECIPIENT_KEY"
UNWRAP_REASON_TAMPERED_HEADER: Final[str] = "TAMPERED_HEADER"
UNWRAP_REASON_TAMPERED_CIPHERTEXT: Final[str] = "TAMPERED_CIPHERTEXT"

KEM_X25519: Final[str] = "x25519"
KEM_MLKEM768X25519: Final[str] = "mlkem768x25519"

_ZERO_NONCE_12: Final[bytes] = b"\x00" * 12
_EMPTY_SALT: Final[bytes] = b""
_X25519_PUBLIC_KEY_LENGTH: Final[int] = 32
_X25519_SECRET_KEY_LENGTH: Final[int] = 32
_CEK_LENGTH: Final[int] = 32
_NONCE_LENGTH: Final[int] = 24
_WRAP_LENGTH: Final[int] = 48
_SLOTS_MAC_LENGTH: Final[int] = 32

# X-Wing (ML-KEM-768 + X25519) component sizes, per draft-connolly-cfrg-xwing-kem
# / FIPS 203 / RFC 7748.
_MLKEM768X25519_PUBLIC_KEY_LENGTH: Final[int] = 1216
_MLKEM768X25519_ENC_LENGTH: Final[int] = 1120
_MLKEM768X25519_ESEED_LENGTH: Final[int] = 64

# Cardano ledger CDDL caps every `transaction_metadatum` byte string at 64
# bytes, so any value larger than 64 bytes is carried as an array of <= 64-byte
# chunks. This is the identical split rule the record encoder applies to chunked
# COSE bytes.
_CHUNK_MAX_BYTES: Final[int] = 64

if len(CARDANO_POE_HKDF_INFO_KEK) != 18:
    raise RuntimeError("CARDANO_POE_HKDF_INFO_KEK byte-length invariant violated (expected 18)")
if len(CARDANO_POE_HKDF_INFO_KEK_MLKEM768X25519) != 33:
    raise RuntimeError(
        "CARDANO_POE_HKDF_INFO_KEK_MLKEM768X25519 byte-length invariant violated (expected 33)"
    )
if len(CARDANO_POE_HKDF_INFO_SLOTS_MAC) != 24:
    raise RuntimeError(
        "CARDANO_POE_HKDF_INFO_SLOTS_MAC byte-length invariant violated (expected 24)"
    )
if len(_ZERO_NONCE_12) != 12:
    raise RuntimeError("_ZERO_NONCE_12 byte-length invariant violated (expected 12)")


class EciesSealedPoeError(Exception):
    # Sealed-PoE error taxonomy (wire-shape + partitioning-oracle pre-checks).
    ENC_SLOTS_EMPTY = "ENC_SLOTS_EMPTY"
    ENC_SLOTS_MAC_INVALID_LENGTH = "ENC_SLOTS_MAC_INVALID_LENGTH"
    KEM_EPK_LENGTH_MISMATCH = "KEM_EPK_LENGTH_MISMATCH"
    KEM_CT_LENGTH_MISMATCH = "KEM_CT_LENGTH_MISMATCH"
    INVALID_CEK_LENGTH = "INVALID_CEK_LENGTH"
    NONCE_LENGTH_MISMATCH = "NONCE_LENGTH_MISMATCH"
    INVALID_EPHEMERAL_SECRET_LENGTH = "INVALID_EPHEMERAL_SECRET_LENGTH"  # noqa: S105
    EPHEMERAL_SECRETS_COUNT_MISMATCH = "EPHEMERAL_SECRETS_COUNT_MISMATCH"
    UNSUPPORTED_ENC_VERSION = "UNSUPPORTED_ENC_VERSION"
    UNSUPPORTED_AEAD_ALG = "UNSUPPORTED_AEAD_ALG"
    UNSUPPORTED_KEM_ALG = "UNSUPPORTED_KEM_ALG"
    INVALID_RECIPIENT_KEY = "INVALID_RECIPIENT_KEY"
    WRAP_LENGTH_MISMATCH = "WRAP_LENGTH_MISMATCH"

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code: str = code


# Per-slot wire shape, discriminated on field presence (the `kem` identifier is
# hoisted to envelope scope — every slot shares it):
#   • x25519:         { epk: bstr(32), wrap: bstr(48) }      → epk set, kem_ct None
#   • mlkem768x25519: { kem_ct: [bstr.size(1..64)], wrap }   → kem_ct set, epk None
#
# `kem_ct` here is the reassembled flat 1120-byte X-Wing enc held in memory; it
# is chunked into <= 64-byte byte strings only at CBOR-serialization time.
@dataclass(frozen=True)
class SealedSlot:
    wrap: bytes
    epk: bytes | None = None
    kem_ct: bytes | None = None


# Sealed envelope wire shape.
@dataclass(frozen=True)
class SealedEnvelope:
    scheme: int  # MUST be 1
    aead: str
    kem: str
    nonce: bytes
    slots: tuple[SealedSlot, ...]
    slots_mac: bytes


@dataclass(frozen=True)
class SealedPoeOutput:
    envelope: SealedEnvelope
    ciphertext: bytes


@dataclass(frozen=True)
class UnwrapResult:
    matched: bool
    plaintext: bytes | None
    reason: str | None


# Trial-decrypt-only result discriminator. Mirrors the TS
# TrialDecryptOnlyResult union exactly: 'match' carries (slot_idx, cek);
# 'no_aead_pass' / 'aead_pass_no_mac_match' are pure flags.
TRIAL_DECRYPT_KIND_MATCH: Final[str] = "match"
TRIAL_DECRYPT_KIND_NO_AEAD_PASS: Final[str] = "no_aead_pass"  # noqa: S105
TRIAL_DECRYPT_KIND_AEAD_PASS_NO_MAC_MATCH: Final[str] = "aead_pass_no_mac_match"  # noqa: S105


@dataclass(frozen=True)
class TrialDecryptOnlyResult:
    kind: str
    slot_idx: int | None
    cek: bytes | None


# Split a logical byte string into <= 64-byte chunks. Used for the X-Wing
# `enc` -> `kem_ct` wire form. Byte-identical to the record encoder's chunking.
def _chunk_kem_ct(value: bytes) -> list[bytes]:
    if len(value) == 0:
        raise ValueError("chunk_kem_ct: refusing to chunk an empty byte string")
    return [value[i : i + _CHUNK_MAX_BYTES] for i in range(0, len(value), _CHUNK_MAX_BYTES)]


# Inverse of _chunk_kem_ct: concatenate the chunked `kem_ct` back into the flat
# X-Wing `enc`. Performs NO length validation — the caller gates the reassembled
# length against _MLKEM768X25519_ENC_LENGTH before any decapsulation.
def _join_kem_ct(chunks: Sequence[bytes]) -> bytes:
    return b"".join(chunks)


# Anonymity invariant: wire ordering MUST NOT encode "primary recipient
# first". CSPRNG-seeded Fisher-Yates uniformly permutes the slot array so
# trial-decrypt order leaks no recipient identity. The slot-set HMAC is
# computed AFTER this shuffle, binding the on-wire order.
def _csprng_shuffle(items: list[SealedSlot]) -> list[SealedSlot]:
    rng = secrets.SystemRandom()
    out = list(items)
    for i in range(len(out) - 1, 0, -1):
        j = rng.randrange(i + 1)
        out[i], out[j] = out[j], out[i]
    return out


# KEM-driven slot serialization for the slots_mac input. Single source of truth
# shared by wrap (compute) and unwrap/trial-decrypt (verify), so the producer
# and verifier cannot diverge on the bytes the MAC commits to:
#
#   • x25519:         each slot → { epk: bstr, wrap: bstr }
#   • mlkem768x25519: each slot → { kem_ct: [bstr, ...], wrap: bstr }
#
# The hybrid form uses the SAME chunked-array shape as the wire encoder, so the
# MAC commits to the ciphertext exactly as it appears on-chain. Canonical-CBOR
# (`canonical=True`) sorts map keys length-first, placing `wrap` (4-byte key)
# before `kem_ct` (6-byte key) regardless of dict insertion order.
def _slots_to_cbor_input(slots: Sequence[SealedSlot], kem: str) -> bytes:
    value: list[CanonicalCborValue] = []
    if kem == KEM_X25519:
        for s in slots:
            x_entry: dict[str | int, CanonicalCborValue] = {
                "epk": s.epk if s.epk is not None else b"",
                "wrap": s.wrap,
            }
            value.append(x_entry)
    else:
        for s in slots:
            chunks: list[CanonicalCborValue] = list(
                _chunk_kem_ct(s.kem_ct if s.kem_ct is not None else b"")
            )
            h_entry: dict[str | int, CanonicalCborValue] = {
                "kem_ct": chunks,
                "wrap": s.wrap,
            }
            value.append(h_entry)
    return encode_canonical_cbor(value)


def _compute_slots_mac(cek: bytes, slots: Sequence[SealedSlot], kem: str) -> bytes:
    hmac_key = hkdf_sha256(
        ikm=cek,
        salt=_EMPTY_SALT,
        info=CARDANO_POE_HKDF_INFO_SLOTS_MAC,
        length=32,
    )
    slots_cbor = _slots_to_cbor_input(slots, kem)
    slots_mac = stdlib_hmac.new(hmac_key, slots_cbor, hashlib.sha256).digest()
    if len(slots_mac) != _SLOTS_MAC_LENGTH:
        raise RuntimeError(
            f"internal: slots_mac length={len(slots_mac)}, expected {_SLOTS_MAC_LENGTH}"
        )
    return slots_mac


# Wrap the CEK for one classical recipient: age-style ECIES stanza.
def _wrap_slot_x25519(
    pub_r: bytes, priv_eph: bytes | None, cek: bytes, slot_idx: int
) -> SealedSlot:
    eph = priv_eph if priv_eph is not None else secrets.token_bytes(_X25519_SECRET_KEY_LENGTH)
    if len(eph) != _X25519_SECRET_KEY_LENGTH:
        raise EciesSealedPoeError(
            EciesSealedPoeError.INVALID_EPHEMERAL_SECRET_LENGTH,
            f"ephemeral_secrets[{slot_idx}] MUST be exactly "
            f"{_X25519_SECRET_KEY_LENGTH} bytes, got {len(eph)}",
        )
    epk = x25519_public_key(eph)
    shared = x25519_ecdh(eph, pub_r)
    # Age v1 stanza salt is `epk || pub_R`.
    kek = hkdf_sha256(
        ikm=shared,
        salt=epk + pub_r,
        info=CARDANO_POE_HKDF_INFO_KEK,
        length=32,
    )
    # Per-slot wrap AAD MUST be the 18-byte ASCII literal of the KEK info string
    # (never empty AAD).
    wrap = chacha20_poly1305_encrypt(kek, _ZERO_NONCE_12, CARDANO_POE_HKDF_INFO_KEK, cek)
    if len(wrap) != _WRAP_LENGTH:
        raise RuntimeError(f"internal: wrap length={len(wrap)}, expected {_WRAP_LENGTH}")
    return SealedSlot(epk=epk, wrap=wrap)


# Wrap the CEK for one hybrid recipient: X-Wing encapsulation → HKDF → AEAD.
# The KEK info label doubles as the wrap AEAD AAD, mirroring the classical path.
# NOTE: the hybrid HKDF salt is EMPTY (the X-Wing combiner already binds epk +
# recipient pk), unlike the classical path whose salt is `epk || pub_R`.
def _wrap_slot_mlkem768x25519(pub_r: bytes, eseed: bytes | None, cek: bytes) -> SealedSlot:
    enc, ss = xwing_encapsulate(pub_r, eseed)
    if len(enc) != _MLKEM768X25519_ENC_LENGTH:
        raise RuntimeError(
            f"internal: enc length={len(enc)}, expected {_MLKEM768X25519_ENC_LENGTH}"
        )
    kek = hkdf_sha256(
        ikm=ss,
        salt=_EMPTY_SALT,
        info=CARDANO_POE_HKDF_INFO_KEK_MLKEM768X25519,
        length=32,
    )
    wrap = chacha20_poly1305_encrypt(
        kek, _ZERO_NONCE_12, CARDANO_POE_HKDF_INFO_KEK_MLKEM768X25519, cek
    )
    if len(wrap) != _WRAP_LENGTH:
        raise RuntimeError(f"internal: wrap length={len(wrap)}, expected {_WRAP_LENGTH}")
    # kem_ct held flat in memory; chunked only at CBOR-serialization time.
    return SealedSlot(kem_ct=enc, wrap=wrap)


def ecies_sealed_poe_wrap(
    *,
    plaintext: bytes,
    recipient_public_keys: Sequence[bytes],
    # KEM branch selector. Defaults to 'x25519' for the classical path. The
    # recipient public-key length is validated against the chosen KEM.
    kem: str = KEM_X25519,
    # Test-only deterministic overrides — production callers MUST NOT pass these.
    cek: bytes | None = None,
    nonce: bytes | None = None,
    # Deterministic X25519 ephemeral scalars (32 bytes each) — x25519 branch only.
    ephemeral_secrets: Sequence[bytes] | None = None,
    # Deterministic X-Wing encapsulation randomness (64 bytes each) — hybrid
    # branch only. One per recipient, parallel to recipient_public_keys.
    eseeds: Sequence[bytes] | None = None,
    skip_shuffle: bool = False,
) -> SealedPoeOutput:
    n = len(recipient_public_keys)

    # No fixed upper bound on slot count; the producer SDK polices the
    # per-record byte budget. Only the lower bound is enforced here.
    if n < 1:
        raise EciesSealedPoeError(
            EciesSealedPoeError.ENC_SLOTS_EMPTY,
            f"recipient_public_keys length={n} must be >= 1",
        )

    expected_pub_len = (
        _X25519_PUBLIC_KEY_LENGTH if kem == KEM_X25519 else _MLKEM768X25519_PUBLIC_KEY_LENGTH
    )
    for i, pub in enumerate(recipient_public_keys):
        if len(pub) != expected_pub_len:
            raise EciesSealedPoeError(
                EciesSealedPoeError.KEM_EPK_LENGTH_MISMATCH,
                f"recipient_public_keys[{i}] MUST be exactly {expected_pub_len} bytes "
                f"for kem='{kem}'",
            )

    if kem == KEM_X25519:
        if eseeds is not None:
            raise EciesSealedPoeError(
                EciesSealedPoeError.EPHEMERAL_SECRETS_COUNT_MISMATCH,
                "eseeds is an X-Wing (mlkem768x25519) override and MUST NOT be supplied "
                "for kem='x25519'",
            )
        if ephemeral_secrets is not None and len(ephemeral_secrets) != n:
            raise EciesSealedPoeError(
                EciesSealedPoeError.EPHEMERAL_SECRETS_COUNT_MISMATCH,
                f"ephemeral_secrets length={len(ephemeral_secrets)} must match "
                f"recipient_public_keys length={n}",
            )
    elif kem == KEM_MLKEM768X25519:
        if ephemeral_secrets is not None:
            raise EciesSealedPoeError(
                EciesSealedPoeError.EPHEMERAL_SECRETS_COUNT_MISMATCH,
                "ephemeral_secrets is an X25519 override and MUST NOT be supplied "
                "for kem='mlkem768x25519'",
            )
        if eseeds is not None:
            if len(eseeds) != n:
                raise EciesSealedPoeError(
                    EciesSealedPoeError.EPHEMERAL_SECRETS_COUNT_MISMATCH,
                    f"eseeds length={len(eseeds)} must match "
                    f"recipient_public_keys length={n}",
                )
            for i, eseed in enumerate(eseeds):
                if len(eseed) != _MLKEM768X25519_ESEED_LENGTH:
                    raise EciesSealedPoeError(
                        EciesSealedPoeError.INVALID_EPHEMERAL_SECRET_LENGTH,
                        f"eseeds[{i}] MUST be exactly "
                        f"{_MLKEM768X25519_ESEED_LENGTH} bytes, got {len(eseed)}",
                    )
    else:
        raise EciesSealedPoeError(
            EciesSealedPoeError.UNSUPPORTED_KEM_ALG,
            f"kem={kem!r} unsupported (expected 'x25519' or 'mlkem768x25519')",
        )

    cek = cek if cek is not None else secrets.token_bytes(_CEK_LENGTH)
    nonce = nonce if nonce is not None else secrets.token_bytes(_NONCE_LENGTH)
    if len(cek) != _CEK_LENGTH:
        raise EciesSealedPoeError(
            EciesSealedPoeError.INVALID_CEK_LENGTH,
            f"cek MUST be exactly {_CEK_LENGTH} bytes, got {len(cek)}",
        )
    if len(nonce) != _NONCE_LENGTH:
        raise EciesSealedPoeError(
            EciesSealedPoeError.NONCE_LENGTH_MISMATCH,
            f"nonce MUST be exactly {_NONCE_LENGTH} bytes, got {len(nonce)}",
        )

    slots: list[SealedSlot] = []
    if kem == KEM_X25519:
        for i, pub_r in enumerate(recipient_public_keys):
            priv_eph = ephemeral_secrets[i] if ephemeral_secrets is not None else None
            slots.append(_wrap_slot_x25519(pub_r, priv_eph, cek, i))
    else:
        for i, pub_r in enumerate(recipient_public_keys):
            eseed_i = eseeds[i] if eseeds is not None else None
            slots.append(_wrap_slot_mlkem768x25519(pub_r, eseed_i, cek))

    # Anonymity invariant: post-wrap CSPRNG shuffle so wire ordering encodes
    # no recipient identity.
    if not skip_shuffle:
        slots = _csprng_shuffle(slots)

    # Slot-set MAC binds canonical-CBOR(slots) to the CEK.
    slots_mac = _compute_slots_mac(cek, slots, kem)

    # Content AEAD AAD is `nonce || slots_mac` (24 + 32 = 56 B).
    ad_content = nonce + slots_mac
    ciphertext = xchacha20_poly1305_encrypt(cek, nonce, ad_content, plaintext)

    envelope = SealedEnvelope(
        scheme=1,
        aead="xchacha20-poly1305",
        kem=kem,
        nonce=nonce,
        slots=tuple(slots),
        slots_mac=slots_mac,
    )
    return SealedPoeOutput(envelope=envelope, ciphertext=ciphertext)


# Classical (x25519) per-slot recovery body. Returns the candidate CEK on the
# first AEAD-tag success; None otherwise. `live_slot` distinguishes the
# real-work path (attempt the AEAD unwrap) from the constant-time-N dummy path
# (do the ECDH + HKDF but skip the AEAD, since a CEK is already in hand).
def _try_x25519_slot(
    slot: SealedSlot, recipient_secret_key: bytes, pub_r_local: bytes, live_slot: bool
) -> bytes | None:
    epk = slot.epk if slot.epk is not None else b""
    # A slot's `epk` is attacker-influenceable wire data. A small-order
    # Montgomery point makes the X25519 shared secret all-zero, which the KEM
    # rejects per RFC 7748 §6.1. Such a slot can never have been produced by a
    # conformant wrap for THIS recipient, so it is a non-match — handled here
    # identically to an AEAD-tag failure (skip the slot, keep iterating so the
    # constant-time-N loop shape is preserved). Only the contributory-check
    # rejection is swallowed.
    if live_slot:
        try:
            shared = x25519_ecdh(recipient_secret_key, epk)
            kek = hkdf_sha256(
                ikm=shared,
                salt=epk + pub_r_local,
                info=CARDANO_POE_HKDF_INFO_KEK,
                length=32,
            )
            return chacha20_poly1305_decrypt(
                kek, _ZERO_NONCE_12, CARDANO_POE_HKDF_INFO_KEK, slot.wrap
            )
        except (AeadVerificationError, X25519LowOrderPointError):
            return None
    # Constant-time-N dummy path: mirror the real-work ECDH + HKDF, still
    # tolerating a low-order epk in a later slot so it cannot turn a successful
    # unwrap into a throw.
    try:
        shared = x25519_ecdh(recipient_secret_key, epk)
        hkdf_sha256(
            ikm=shared,
            salt=epk + pub_r_local,
            info=CARDANO_POE_HKDF_INFO_KEK,
            length=32,
        )
    except X25519LowOrderPointError:
        pass
    return None


# Hybrid (mlkem768x25519) per-slot recovery body. X-Wing decapsulate NEVER
# throws on attacker wire data (ML-KEM implicit rejection yields a pseudorandom
# shared secret), so there is no try/except around it: a wrong shared secret
# simply yields a KEK that fails the AEAD tag. The dummy (constant-time-N) path
# runs a FULL decapsulate + HKDF so matching and non-matching slots cost the
# same X-Wing work.
def _try_mlkem768x25519_slot(
    slot: SealedSlot, recipient_secret_key: bytes, live_slot: bool
) -> bytes | None:
    # kem_ct length was validated to reassemble to _MLKEM768X25519_ENC_LENGTH in
    # _assert_envelope_structure, so this join + decapsulate is constant-work.
    enc = slot.kem_ct if slot.kem_ct is not None else b""
    ss = xwing_decapsulate(recipient_secret_key, enc)
    kek = hkdf_sha256(
        ikm=ss,
        salt=_EMPTY_SALT,
        info=CARDANO_POE_HKDF_INFO_KEK_MLKEM768X25519,
        length=32,
    )
    if not live_slot:
        # Dummy path: full decapsulate + HKDF already done above; skip only the
        # AEAD attempt (a CEK is already in hand).
        return None
    try:
        return chacha20_poly1305_decrypt(
            kek, _ZERO_NONCE_12, CARDANO_POE_HKDF_INFO_KEK_MLKEM768X25519, slot.wrap
        )
    except AeadVerificationError:
        return None


# Per-priv inner trial-decrypt loop with slot-index reporting, KEM-driven.
# Enters every slot when constant_time_n; the dummy path keeps per-iteration
# cost uniform regardless of which slot matched.
def _try_recipient_unwrap_with_idx(
    envelope: SealedEnvelope,
    recipient_secret_key: bytes,
    constant_time_n: bool,
    _slots_attempted_out: list[int] | None,
) -> tuple[bytes, int] | None:
    cek: bytes | None = None
    matched_slot_idx = -1
    if envelope.kem == KEM_X25519:
        pub_r_local = x25519_public_key(recipient_secret_key)
        for i, slot in enumerate(envelope.slots):
            if _slots_attempted_out is not None:
                if not _slots_attempted_out:
                    _slots_attempted_out.append(i + 1)
                else:
                    _slots_attempted_out[0] = i + 1
            candidate = _try_x25519_slot(slot, recipient_secret_key, pub_r_local, cek is None)
            if cek is None and candidate is not None:
                cek = candidate
                matched_slot_idx = i
            if cek is not None and not constant_time_n:
                break
    else:
        for i, slot in enumerate(envelope.slots):
            if _slots_attempted_out is not None:
                if not _slots_attempted_out:
                    _slots_attempted_out.append(i + 1)
                else:
                    _slots_attempted_out[0] = i + 1
            candidate = _try_mlkem768x25519_slot(slot, recipient_secret_key, cek is None)
            if cek is None and candidate is not None:
                cek = candidate
                matched_slot_idx = i
            if cek is not None and not constant_time_n:
                break
    if cek is None:
        return None
    return (cek, matched_slot_idx)


# Back-compat wrapper preserved for callers that only care about the CEK
# (single-priv path inside `ecies_sealed_poe_unwrap`).
def _try_recipient_unwrap(
    envelope: SealedEnvelope,
    recipient_secret_key: bytes,
    constant_time_n: bool,
    _slots_attempted_out: list[int] | None,
) -> bytes | None:
    candidate = _try_recipient_unwrap_with_idx(
        envelope, recipient_secret_key, constant_time_n, _slots_attempted_out
    )
    return None if candidate is None else candidate[0]


# Partitioning-oracle defence: every wire length MUST be validated before any
# KEM/AEAD primitive is invoked, so malformed records cannot probe per-slot
# failure ordering. Shared between unwrap (single- and multi-priv) and
# trial-decrypt to guarantee byte-identical pre-trial behaviour. For the hybrid
# branch this includes reassembling each slot's `kem_ct` and asserting the flat
# enc length BEFORE any decapsulation.
def _assert_envelope_structure(
    envelope: SealedEnvelope,
    multi_priv_keys: Sequence[bytes] | None,
    single_priv_key: bytes | None,
) -> None:
    if envelope.scheme != 1:
        raise EciesSealedPoeError(
            EciesSealedPoeError.UNSUPPORTED_ENC_VERSION,
            f"envelope.scheme={envelope.scheme} unsupported (expected 1)",
        )
    if envelope.aead != "xchacha20-poly1305":
        raise EciesSealedPoeError(
            EciesSealedPoeError.UNSUPPORTED_AEAD_ALG,
            f"envelope.aead={envelope.aead!r} unsupported (expected 'xchacha20-poly1305')",
        )
    if envelope.kem not in (KEM_X25519, KEM_MLKEM768X25519):
        raise EciesSealedPoeError(
            EciesSealedPoeError.UNSUPPORTED_KEM_ALG,
            f"envelope.kem={envelope.kem!r} unsupported "
            "(expected 'x25519' or 'mlkem768x25519')",
        )

    # Envelope-level length pre-checks in this exact order.
    n = len(envelope.slots)
    if n < 1:
        raise EciesSealedPoeError(
            EciesSealedPoeError.ENC_SLOTS_EMPTY,
            f"envelope.slots length={n} must be >= 1",
        )
    if len(envelope.nonce) != _NONCE_LENGTH:
        raise EciesSealedPoeError(
            EciesSealedPoeError.NONCE_LENGTH_MISMATCH,
            f"envelope.nonce MUST be exactly {_NONCE_LENGTH} bytes, got {len(envelope.nonce)}",
        )
    if len(envelope.slots_mac) != _SLOTS_MAC_LENGTH:
        raise EciesSealedPoeError(
            EciesSealedPoeError.ENC_SLOTS_MAC_INVALID_LENGTH,
            f"envelope.slots_mac MUST be exactly {_SLOTS_MAC_LENGTH} bytes, "
            f"got {len(envelope.slots_mac)}",
        )

    # Per-slot length pre-checks — KEM-driven. ALL slots are validated here,
    # before any decapsulation, so the trial-decrypt loop never observes a
    # malformed slot (partitioning-oracle-safe ordering).
    if envelope.kem == KEM_X25519:
        for i, slot in enumerate(envelope.slots):
            epk_len = len(slot.epk) if slot.epk is not None else 0
            if epk_len != _X25519_PUBLIC_KEY_LENGTH:
                raise EciesSealedPoeError(
                    EciesSealedPoeError.KEM_EPK_LENGTH_MISMATCH,
                    f"envelope.slots[{i}].epk MUST be exactly "
                    f"{_X25519_PUBLIC_KEY_LENGTH} bytes, got {epk_len}",
                )
            if len(slot.wrap) != _WRAP_LENGTH:
                raise EciesSealedPoeError(
                    EciesSealedPoeError.WRAP_LENGTH_MISMATCH,
                    f"envelope.slots[{i}].wrap MUST be exactly "
                    f"{_WRAP_LENGTH} bytes, got {len(slot.wrap)}",
                )
    else:
        for i, slot in enumerate(envelope.slots):
            enc_len = len(slot.kem_ct) if slot.kem_ct is not None else 0
            if enc_len != _MLKEM768X25519_ENC_LENGTH:
                raise EciesSealedPoeError(
                    EciesSealedPoeError.KEM_CT_LENGTH_MISMATCH,
                    f"envelope.slots[{i}].kem_ct MUST reassemble to exactly "
                    f"{_MLKEM768X25519_ENC_LENGTH} bytes, got {enc_len}",
                )
            if len(slot.wrap) != _WRAP_LENGTH:
                raise EciesSealedPoeError(
                    EciesSealedPoeError.WRAP_LENGTH_MISMATCH,
                    f"envelope.slots[{i}].wrap MUST be exactly "
                    f"{_WRAP_LENGTH} bytes, got {len(slot.wrap)}",
                )

    if multi_priv_keys is not None:
        for k, priv in enumerate(multi_priv_keys):
            if len(priv) != _X25519_SECRET_KEY_LENGTH:
                raise EciesSealedPoeError(
                    EciesSealedPoeError.INVALID_RECIPIENT_KEY,
                    f"recipient_secret_keys[{k}] MUST be exactly "
                    f"{_X25519_SECRET_KEY_LENGTH} bytes, got {len(priv)}",
                )
    elif single_priv_key is not None:
        if len(single_priv_key) != _X25519_SECRET_KEY_LENGTH:
            raise EciesSealedPoeError(
                EciesSealedPoeError.INVALID_RECIPIENT_KEY,
                f"recipient_secret_key MUST be exactly "
                f"{_X25519_SECRET_KEY_LENGTH} bytes, got {len(single_priv_key)}",
            )


# Slot-set MAC bytes, KEM-driven so the hybrid kem_ct is committed exactly as it
# appears on-wire. Constant across the multi-priv outer loop (depends only on
# envelope.slots), so callers compute it once.
def _slots_mac_cbor_bytes(envelope: SealedEnvelope) -> bytes:
    return _slots_to_cbor_input(envelope.slots, envelope.kem)


# Multi-recipient sealed-PoE unwrap (trial-decrypt + slots_mac binding +
# partitioning-oracle length pre-checks).
#
# Two forms (mutually exclusive — exactly one MUST be supplied):
#   • Single-priv form: `recipient_secret_key=<32 bytes>` — back-compat for the
#     standalone-verifier path.
#   • Multi-priv form: `recipient_secret_keys=Sequence[bytes]` — for the
#     browser-side trial-decrypt agent of a rotated identity holding
#     `[current_priv, ...archived_privs]`. Caller supplies the order; the
#     iterator runs outer-loop = privkey x inner-loop = slot, short-circuiting on
#     the first cross-priv match that passes slots_mac verification.
#
# Both KEM branches share this control flow; only the per-slot recovery body
# (X25519 ECDH vs X-Wing decapsulate) differs.
def ecies_sealed_poe_unwrap(
    *,
    envelope: SealedEnvelope,
    ciphertext: bytes,
    recipient_secret_key: bytes | None = None,
    recipient_secret_keys: Sequence[bytes] | None = None,
    constant_time_n: bool = True,
    # Test-only instrumentation for constant-time-N verification.
    # Single-priv path: list is treated as a one-element accumulator overwriting
    # index 0 each slot iteration. Multi-priv path: each outer-loop iteration
    # appends the final inner-loop count for that priv to the list (list length
    # == number of outer iterations entered).
    _slots_attempted_out: list[int] | None = None,
    # Test-only multi-priv outer-loop iteration counter. Appended to (or index 0
    # overwritten) once per outer iteration with k + 1.
    _privs_attempted_out: list[int] | None = None,
) -> UnwrapResult:
    # Exactly-one-of validation for the discriminated form.
    has_single = recipient_secret_key is not None
    has_multi = recipient_secret_keys is not None
    if has_single == has_multi:
        raise EciesSealedPoeError(
            EciesSealedPoeError.INVALID_RECIPIENT_KEY,
            "exactly one of recipient_secret_key / recipient_secret_keys MUST be supplied",
        )
    if has_multi:
        assert recipient_secret_keys is not None  # noqa: S101
        if len(recipient_secret_keys) == 0:
            raise EciesSealedPoeError(
                EciesSealedPoeError.INVALID_RECIPIENT_KEY,
                "recipient_secret_keys MUST be a non-empty sequence, got length=0",
            )

    # Partitioning-oracle pre-checks; per-priv length validation happens inside
    # `_assert_envelope_structure`.
    if has_multi:
        _assert_envelope_structure(envelope, recipient_secret_keys, None)
    else:
        _assert_envelope_structure(envelope, None, recipient_secret_key)

    matched_cek: bytes | None = None
    any_candidate_recovered = False

    if has_single:
        assert recipient_secret_key is not None  # noqa: S101
        cek = _try_recipient_unwrap(
            envelope, recipient_secret_key, constant_time_n, _slots_attempted_out
        )
        if cek is None:
            return UnwrapResult(
                matched=False, plaintext=None, reason=UNWRAP_REASON_WRONG_RECIPIENT_KEY
            )
        slots_cbor = _slots_mac_cbor_bytes(envelope)
        hmac_key = hkdf_sha256(
            ikm=cek,
            salt=_EMPTY_SALT,
            info=CARDANO_POE_HKDF_INFO_SLOTS_MAC,
            length=32,
        )
        slots_mac_calc = stdlib_hmac.new(hmac_key, slots_cbor, hashlib.sha256).digest()
        if not compare_ct(slots_mac_calc, envelope.slots_mac):
            return UnwrapResult(matched=False, plaintext=None, reason=UNWRAP_REASON_TAMPERED_HEADER)
        matched_cek = cek
    else:
        # The slots-CBOR is constant across the outer loop (depends only on
        # envelope.slots) — compute once before the loop to keep per-priv cost
        # identical to the single-priv path.
        slots_cbor = _slots_mac_cbor_bytes(envelope)
        assert recipient_secret_keys is not None  # noqa: S101
        for k, priv in enumerate(recipient_secret_keys):
            if _privs_attempted_out is not None:
                if not _privs_attempted_out:
                    _privs_attempted_out.append(k + 1)
                else:
                    _privs_attempted_out[0] = k + 1
            inner_counter: list[int] | None = [] if _slots_attempted_out is not None else None
            cek = _try_recipient_unwrap(envelope, priv, constant_time_n, inner_counter)
            if _slots_attempted_out is not None and inner_counter is not None:
                _slots_attempted_out.append(inner_counter[0] if inner_counter else 0)
            if cek is None:
                continue
            hmac_key = hkdf_sha256(
                ikm=cek,
                salt=_EMPTY_SALT,
                info=CARDANO_POE_HKDF_INFO_SLOTS_MAC,
                length=32,
            )
            slots_mac_calc = stdlib_hmac.new(hmac_key, slots_cbor, hashlib.sha256).digest()
            # The outer cross-priv loop short-circuits on the first priv whose
            # recovered CEK also passes slots_mac. This intentionally leaks
            # "which priv matched" → "how many key rotations the recipient has
            # performed". Making the outer loop constant-work would cost a FULL
            # KEM decapsulation (an X25519 ECDH, or — for the hybrid branch — a
            # full X-Wing ML-KEM-768 + X25519 decapsulation) for EVERY archived
            # priv on EVERY record, which for the hybrid case is the dominant
            # cost; the benefit (hiding a count the user already knows) does not
            # justify it. The inner per-slot loop IS held constant-work.
            if compare_ct(slots_mac_calc, envelope.slots_mac):
                matched_cek = cek
                break
            any_candidate_recovered = True
        if matched_cek is None:
            reason = (
                UNWRAP_REASON_TAMPERED_HEADER
                if any_candidate_recovered
                else UNWRAP_REASON_WRONG_RECIPIENT_KEY
            )
            return UnwrapResult(matched=False, plaintext=None, reason=reason)

    # Content AEAD AAD is `nonce || slots_mac`.
    ad_content = envelope.nonce + envelope.slots_mac
    try:
        plaintext = xchacha20_poly1305_decrypt(matched_cek, envelope.nonce, ad_content, ciphertext)
    except AeadVerificationError:
        return UnwrapResult(matched=False, plaintext=None, reason=UNWRAP_REASON_TAMPERED_CIPHERTEXT)
    return UnwrapResult(matched=True, plaintext=plaintext, reason=None)


# Trial-decrypt half of the sealed-PoE unwrap algorithm: recovers the CEK +
# slot index without touching the content AEAD. Used by the browser-side inbox
# scan agent where the on-chain envelope is available but the Arweave-pinned
# ciphertext is fetched lazily only at user-driven Decrypt time.
#
# constant_time_n defaults to True (MANDATORY for browser agents).
# Cross-priv variable-time short-circuit is preserved — it leaks
# "which priv matched" → "how many rotations", a documented weak ordering
# signal.
def ecies_sealed_poe_trial_decrypt(
    *,
    envelope: SealedEnvelope,
    recipient_secret_keys: Sequence[bytes],
    constant_time_n: bool = True,
    _slots_attempted_out: list[int] | None = None,
    _privs_attempted_out: list[int] | None = None,
) -> TrialDecryptOnlyResult:
    if len(recipient_secret_keys) == 0:
        raise EciesSealedPoeError(
            EciesSealedPoeError.INVALID_RECIPIENT_KEY,
            "recipient_secret_keys MUST be a non-empty sequence, got length=0",
        )
    _assert_envelope_structure(envelope, recipient_secret_keys, None)

    slots_cbor = _slots_mac_cbor_bytes(envelope)
    any_candidate_recovered = False
    for k, priv in enumerate(recipient_secret_keys):
        if _privs_attempted_out is not None:
            if not _privs_attempted_out:
                _privs_attempted_out.append(k + 1)
            else:
                _privs_attempted_out[0] = k + 1
        inner_counter: list[int] | None = [] if _slots_attempted_out is not None else None
        candidate = _try_recipient_unwrap_with_idx(envelope, priv, constant_time_n, inner_counter)
        if _slots_attempted_out is not None and inner_counter is not None:
            _slots_attempted_out.append(inner_counter[0] if inner_counter else 0)
        if candidate is None:
            continue
        cek, slot_idx = candidate
        hmac_key = hkdf_sha256(
            ikm=cek,
            salt=_EMPTY_SALT,
            info=CARDANO_POE_HKDF_INFO_SLOTS_MAC,
            length=32,
        )
        slots_mac_calc = stdlib_hmac.new(hmac_key, slots_cbor, hashlib.sha256).digest()
        if compare_ct(slots_mac_calc, envelope.slots_mac):
            return TrialDecryptOnlyResult(kind=TRIAL_DECRYPT_KIND_MATCH, slot_idx=slot_idx, cek=cek)
        any_candidate_recovered = True
    return TrialDecryptOnlyResult(
        kind=(
            TRIAL_DECRYPT_KIND_AEAD_PASS_NO_MAC_MATCH
            if any_candidate_recovered
            else TRIAL_DECRYPT_KIND_NO_AEAD_PASS
        ),
        slot_idx=None,
        cek=None,
    )
