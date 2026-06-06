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
from .mlkem768x25519 import xwing_decapsulate, xwing_encapsulate, xwing_keygen

# HKDF info strings, SHA-256 transcript/salt prefixes, and the X-Wing KEK salt
# prefix are fixed protocol labels: exact ASCII, no terminator, no length
# prefix. Each is an internal building block of enc.scheme 1 — never serialised
# on the wire and never registry-selectable. The byte-length invariants below
# pin the SCREAMING_SNAKE constants to the literals every conformant verifier
# hashes against.
CARDANO_POE_HKDF_INFO_KEK: Final[bytes] = b"cardano-poe-kek-v1"
# Hybrid (X-Wing) per-slot KEK label. Distinct from the classical label so a KEK
# derived under one KEM can never collide with the other. Reused verbatim as the
# per-slot wrap AEAD AAD, exactly as the classical path reuses its own label.
CARDANO_POE_HKDF_INFO_KEK_MLKEM768X25519: Final[bytes] = b"cardano-poe-kek-mlkem768x25519-v1"
CARDANO_POE_HKDF_INFO_SLOTS_MAC: Final[bytes] = b"cardano-poe-slots-mac-v1"
# SHA-256 prefix over the slots transcript; the resulting slots_hash is the
# constant-across-the-loop message the CEK-keyed HMAC signs.
CARDANO_POE_HASH_PREFIX_SLOTS_TRANSCRIPT: Final[bytes] = b"cardano-poe-slots-transcript-v1"
# HKDF info for the slots-path content payload_key (derived from the CEK; the
# content is never encrypted under the CEK directly).
CARDANO_POE_HKDF_INFO_PAYLOAD: Final[bytes] = b"cardano-poe-payload-v1"
# HKDF info for the passphrase-path content payload_key.
CARDANO_POE_HKDF_INFO_PAYLOAD_PASSPHRASE: Final[bytes] = b"cardano-poe-payload-passphrase-v1"
# SHA-256 prefix binding the reassembled hybrid kem_ct and the recipient X-Wing
# public key into the per-slot KEK salt, mirroring the classical salt's two
# bindings (slot-unique value + recipient public key) through a fixed-length
# digest because the hybrid inputs are oversized.
CARDANO_POE_HASH_PREFIX_XWING_KEK_SALT: Final[bytes] = b"cardano-poe-xwing-kek-salt-v1"

# Passphrase normalization profile identifier. A scheme-1-fixed constant fed
# into the passphrase content AAD to pin the exact NFKC + whitespace-collapse +
# trim + UTF-8 profile the CEK was derived under; never serialised on the wire.
CARDANO_POE_PW_NORM_PROFILE: Final[str] = "cardano-poe-pw-norm-v1"

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

# Verifier-side resource bounds a public parser MUST enforce BEFORE invoking any
# KEM/AEAD primitive, so a malformed envelope cannot drive unbounded work. Both
# are deployment-pinned reference constants (not wire fields); deployments MAY
# tighten them. They sit far above the ~16 KiB Cardano transaction-metadata
# ceiling that bounds honest records, so a conformant record never trips them.
#   • MAX_SLOTS — the maximum slot count; an envelope with more slots is rejected.
#   • MAX_DECODED_ENVELOPE_BYTES — a backstop on the decoded envelope's aggregate
#     byte size (nonce + slots_mac + per-slot wire fields).
MAX_SLOTS: Final[int] = 1024
MAX_DECODED_ENVELOPE_BYTES: Final[int] = 65536

# XChaCha20-Poly1305 is used as a single-shot AEAD over the whole plaintext. Its
# 32-bit internal block counter caps one (key, nonce) invocation at 2^32 64-byte
# ChaCha20 blocks; the encrypted plaintext maximum is one block short of that
# (the Poly1305 tag occupies the final block's keystream), giving exactly
# 2^38 - 64 plaintext bytes. Both producer and verifier MUST reject a payload at
# or above this bound before invoking the AEAD, rather than risk a
# counter-overflow keystream collision. The ciphertext carries an extra 16-byte
# tag, so the ciphertext bound is MAX_SEALED_PLAINTEXT + 16. This constant is
# identical across every SDK.
MAX_SEALED_PLAINTEXT: Final[int] = (1 << 38) - 64
_MAX_SEALED_CIPHERTEXT: Final[int] = MAX_SEALED_PLAINTEXT + 16

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
if len(CARDANO_POE_HASH_PREFIX_SLOTS_TRANSCRIPT) != 31:
    raise RuntimeError(
        "CARDANO_POE_HASH_PREFIX_SLOTS_TRANSCRIPT byte-length invariant violated (expected 31)"
    )
if len(CARDANO_POE_HKDF_INFO_PAYLOAD) != 22:
    raise RuntimeError("CARDANO_POE_HKDF_INFO_PAYLOAD byte-length invariant violated (expected 22)")
if len(CARDANO_POE_HKDF_INFO_PAYLOAD_PASSPHRASE) != 33:
    raise RuntimeError(
        "CARDANO_POE_HKDF_INFO_PAYLOAD_PASSPHRASE byte-length invariant violated (expected 33)"
    )
if len(CARDANO_POE_HASH_PREFIX_XWING_KEK_SALT) != 29:
    raise RuntimeError(
        "CARDANO_POE_HASH_PREFIX_XWING_KEK_SALT byte-length invariant violated (expected 29)"
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
    # A payload at or above the XChaCha20-Poly1305 single-shot keystream bound;
    # enforced on both encrypt and decrypt before the AEAD primitive runs.
    PAYLOAD_TOO_LARGE = "PAYLOAD_TOO_LARGE"
    # Two slots carry identical per-slot KEM material (duplicate `epk` for
    # x25519, or duplicate reassembled `kem_ct` for the hybrid path). The
    # zero-nonce per-slot wrap is sound only under per-slot KEK uniqueness;
    # repeated KEM material can repeat the (KEK, nonce) pair, so such an envelope
    # is rejected before any decapsulation.
    ENC_SLOTS_DUPLICATE_KEM_MATERIAL = "ENC_SLOTS_DUPLICATE_KEM_MATERIAL"
    # Resource bounds tripped before any KEM/AEAD primitive: more than MAX_SLOTS
    # slots, or a decoded envelope larger than MAX_DECODED_ENVELOPE_BYTES.
    ENC_SLOTS_TOO_MANY = "ENC_SLOTS_TOO_MANY"
    ENC_ENVELOPE_TOO_LARGE = "ENC_ENVELOPE_TOO_LARGE"

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


# KEM-driven canonicalised slot structure — the value bound under the `slots`
# key of SLOTS_TRANSCRIPT. Single source of truth shared by wrap (compute) and
# unwrap/trial-decrypt (verify), so the producer and verifier cannot diverge on
# the bytes the transcript commits to:
#
#   • x25519:         each slot → { epk: bstr, wrap: bstr }
#   • mlkem768x25519: each slot → { kem_ct: [bstr, ...], wrap: bstr }
#
# The hybrid form re-chunks `kem_ct` into its canonical <= 64-byte sequence
# (full 64-byte chunks then a final remainder), so the transcript depends on the
# kem_ct BYTES, not on whatever chunk boundaries arrived on the wire. A record
# re-chunked in transit still verifies; any byte flip in kem_ct still changes
# the transcript. Canonical-CBOR sorts map keys length-first at encode time,
# placing `wrap` (4-byte key) before `kem_ct` (6-byte key) regardless of dict
# insertion order.
def _canonicalize_slots(slots: Sequence[SealedSlot], kem: str) -> list[CanonicalCborValue]:
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
    return value


# SLOTS_TRANSCRIPT is a closed six-key map binding the slot set together with the
# cross-KEM header fields that fix how the slots are interpreted. It is hashed
# once to a 32-byte slots_hash that the CEK-keyed HMAC then signs. A relay that
# flips scheme / aead / kem / nonce while leaving slot shapes valid produces a
# different slots_hash, so the MAC fails. canonicalEncode determines map key
# order via the RFC 8949 §4.2.1 sort; the key set here is a set, never an
# ordering.
def _slots_transcript(nonce: bytes, slots: Sequence[SealedSlot], kem: str) -> bytes:
    transcript: dict[str | int, CanonicalCborValue] = {
        "scheme": 1,
        "path": "slots",
        "aead": "xchacha20-poly1305",
        "kem": kem,
        "nonce": nonce,
        "slots": _canonicalize_slots(slots, kem),
    }
    return encode_canonical_cbor(transcript)


def _compute_slots_hash(nonce: bytes, slots: Sequence[SealedSlot], kem: str) -> bytes:
    return hashlib.sha256(
        CARDANO_POE_HASH_PREFIX_SLOTS_TRANSCRIPT + _slots_transcript(nonce, slots, kem)
    ).digest()


def _slots_mac_from_hash(cek: bytes, slots_hash: bytes) -> bytes:
    hmac_key = hkdf_sha256(
        ikm=cek,
        salt=_EMPTY_SALT,
        info=CARDANO_POE_HKDF_INFO_SLOTS_MAC,
        length=32,
    )
    slots_mac = stdlib_hmac.new(hmac_key, slots_hash, hashlib.sha256).digest()
    if len(slots_mac) != _SLOTS_MAC_LENGTH:
        raise RuntimeError(
            f"internal: slots_mac length={len(slots_mac)}, expected {_SLOTS_MAC_LENGTH}"
        )
    return slots_mac


# Slots-path content AAD: a closed seven-key map re-binding the slots-path header
# plus both the slots transcript hash and the CEK-keyed MAC, so a relay cannot
# pair an honest ciphertext with a substituted slot set. Serialised by
# canonicalEncode; key order is the §4.2.1 sort.
def _ad_content_slots(nonce: bytes, kem: str, slots_hash: bytes, slots_mac: bytes) -> bytes:
    ad: dict[str | int, CanonicalCborValue] = {
        "scheme": 1,
        "path": "slots",
        "aead": "xchacha20-poly1305",
        "kem": kem,
        "nonce": nonce,
        "slots_hash": slots_hash,
        "slots_mac": slots_mac,
    }
    return encode_canonical_cbor(ad)


def _slots_payload_key(cek: bytes, nonce: bytes) -> bytes:
    return hkdf_sha256(
        ikm=cek,
        salt=nonce,
        info=CARDANO_POE_HKDF_INFO_PAYLOAD,
        length=32,
    )


def _enforce_max_plaintext(plaintext_len: int) -> None:
    if plaintext_len >= MAX_SEALED_PLAINTEXT:
        raise EciesSealedPoeError(
            EciesSealedPoeError.PAYLOAD_TOO_LARGE,
            f"plaintext length={plaintext_len} is at or above the "
            f"XChaCha20-Poly1305 single-shot bound {MAX_SEALED_PLAINTEXT}",
        )


def _enforce_max_ciphertext(ciphertext_len: int) -> None:
    if ciphertext_len >= _MAX_SEALED_CIPHERTEXT:
        raise EciesSealedPoeError(
            EciesSealedPoeError.PAYLOAD_TOO_LARGE,
            f"ciphertext length={ciphertext_len} is at or above the "
            f"XChaCha20-Poly1305 single-shot bound {_MAX_SEALED_CIPHERTEXT}",
        )


# Per-slot KEK-uniqueness gate. The zero-nonce wrap is sound only when every
# slot's KEK is unique; the KEK is a deterministic function of the slot's KEM
# material (the x25519 `epk` and recipient public key, or the reassembled hybrid
# `kem_ct` and recipient public key), so two slots carrying identical KEM
# material against the same recipient repeat the (KEK, nonce) pair. We reject an
# envelope with duplicate per-slot KEM material — duplicate `epk` for x25519,
# duplicate reassembled `kem_ct` for the hybrid path — on both the producer side
# (before committing to the wire) and the verifier side (before any
# decapsulation).
def _assert_unique_slot_kem_material(slots: Sequence[SealedSlot], kem: str) -> None:
    seen: set[bytes] = set()
    for i, s in enumerate(slots):
        material = s.epk if kem == KEM_X25519 else s.kem_ct
        if material is None:
            material = b""
        if material in seen:
            field = "epk" if kem == KEM_X25519 else "kem_ct"
            raise EciesSealedPoeError(
                EciesSealedPoeError.ENC_SLOTS_DUPLICATE_KEM_MATERIAL,
                f"slots[{i}].{field} duplicates an earlier slot; per-slot KEK "
                "uniqueness is violated",
            )
        seen.add(material)


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


# Hybrid (X-Wing) per-slot KEK salt: SHA-256(label || kem_ct || pub_R). The
# reassembled 1120-byte X-Wing ciphertext anchors the KEK to a slot-unique
# value and the 1216-byte recipient public key binds it to the specific
# recipient — the same two bindings the classical `epk || pub_R` salt provides,
# expressed through a fixed-length digest because the hybrid inputs are
# oversized. Computed outside the KEM, over the slot's own wire bytes, so it
# holds X-Wing as a black-box KEM.
def _xwing_kek_salt(kem_ct: bytes, pub_r: bytes) -> bytes:
    return hashlib.sha256(CARDANO_POE_HASH_PREFIX_XWING_KEK_SALT + kem_ct + pub_r).digest()


# Wrap the CEK for one hybrid recipient: X-Wing encapsulation → HKDF → AEAD.
# The KEK info label doubles as the wrap AEAD AAD, mirroring the classical path.
# The HKDF salt binds the reassembled kem_ct and the recipient public key (see
# `_xwing_kek_salt`), so both KEMs uniformly anchor the KEK to a slot-unique
# value and to the specific recipient.
def _wrap_slot_mlkem768x25519(pub_r: bytes, eseed: bytes | None, cek: bytes) -> SealedSlot:
    enc, ss = xwing_encapsulate(pub_r, eseed)
    if len(enc) != _MLKEM768X25519_ENC_LENGTH:
        raise RuntimeError(
            f"internal: enc length={len(enc)}, expected {_MLKEM768X25519_ENC_LENGTH}"
        )
    kek = hkdf_sha256(
        ikm=ss,
        salt=_xwing_kek_salt(enc, pub_r),
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

    # Reject before any keystream is drawn: a payload at or above the
    # single-shot bound cannot be safely encrypted.
    _enforce_max_plaintext(len(plaintext))

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
                    f"eseeds length={len(eseeds)} must match recipient_public_keys length={n}",
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

    # Per-slot KEK uniqueness is the safety condition for the zero-nonce wrap.
    # Duplicate per-slot KEM material (a repeated x25519 epk, or a repeated
    # reassembled hybrid kem_ct) would repeat the (KEK, nonce) pair, so reject
    # it at the producer before committing anything to the wire.
    _assert_unique_slot_kem_material(slots, kem)

    # Anonymity invariant: post-wrap CSPRNG shuffle so wire ordering encodes
    # no recipient identity.
    if not skip_shuffle:
        slots = _csprng_shuffle(slots)

    # Slot-set MAC binds the slots transcript hash (header fields + slot bytes)
    # to the CEK; the transcript is hashed once and signed with a CEK-keyed
    # HMAC.
    slots_hash = _compute_slots_hash(nonce, slots, kem)
    slots_mac = _slots_mac_from_hash(cek, slots_hash)

    # Content is encrypted under a payload_key derived from the CEK (never the
    # CEK directly), with a structured AAD that re-binds the slots-path header
    # plus both slots_hash and slots_mac.
    payload_key = _slots_payload_key(cek, nonce)
    ad_content = _ad_content_slots(nonce, kem, slots_hash, slots_mac)
    ciphertext = xchacha20_poly1305_encrypt(payload_key, nonce, ad_content, plaintext)

    envelope = SealedEnvelope(
        scheme=1,
        aead="xchacha20-poly1305",
        kem=kem,
        nonce=nonce,
        slots=tuple(slots),
        slots_mac=slots_mac,
    )
    return SealedPoeOutput(envelope=envelope, ciphertext=ciphertext)


# All-zero IKM for the dummy KEK an invalid-ECDH slot derives so it pays the same
# HKDF work as a live slot (see `_try_x25519_slot`).
_ZERO_IKM_32: Final[bytes] = b"\x00" * 32


# Classical (x25519) per-slot recovery body. Returns the candidate CEK on an
# AEAD-tag success; None otherwise. The AEAD is attempted on EVERY slot (no
# match-position-dependent skip), so a per-priv scan recovers a candidate CEK
# from each slot the recipient is addressed in — which is what the inner loop's
# CEK-conflict detection needs. Attempting the AEAD on every slot also makes the
# per-slot timing more uniform, not less: every slot pays the identical
# ECDH + HKDF + AEAD-open cost regardless of where the match lands.
#
# Acceptance is `kem_ok AND open_ok`. `kem_ok` is the X25519 validity bit: a
# small-order `epk` drives the shared secret to all-zero, which RFC 7748 §6.1
# rejects. PyCA `cryptography` (and our explicit compare_digest guard) signal
# this by RAISING X25519LowOrderPointError, so a fully branchless ct-select over
# the shared secret is not expressible against this library API. The next-best,
# equivalent form is taken: on the all-zero rejection the slot derives a DUMMY
# KEK from `ikm=0^32` (same salt/info) so it performs the identical HKDF work,
# then returns a non-match WITHOUT attempting the AEAD — so an invalid-ECDH slot
# can never be accepted regardless of the wrap outcome (`kem_ok=false` ⟹ the AEAD
# is never reached), while the failed path still costs the same per-slot KEK
# derivation as a live one.
def _try_x25519_slot(
    slot: SealedSlot, recipient_secret_key: bytes, pub_r_local: bytes
) -> bytes | None:
    epk = slot.epk if slot.epk is not None else b""
    salt = epk + pub_r_local
    try:
        shared = x25519_ecdh(recipient_secret_key, epk)
    except X25519LowOrderPointError:
        # kem_ok = false. Derive the dummy KEK so the failed slot pays the same
        # HKDF cost a live slot would, then short-circuit to a non-match: the
        # AEAD is never attempted, so this slot can never be accepted.
        hkdf_sha256(ikm=_ZERO_IKM_32, salt=salt, info=CARDANO_POE_HKDF_INFO_KEK, length=32)
        return None
    # kem_ok = true. Derive the real KEK and attempt the wrap AEAD.
    kek = hkdf_sha256(ikm=shared, salt=salt, info=CARDANO_POE_HKDF_INFO_KEK, length=32)
    try:
        return chacha20_poly1305_decrypt(kek, _ZERO_NONCE_12, CARDANO_POE_HKDF_INFO_KEK, slot.wrap)
    except AeadVerificationError:
        return None


# Hybrid (mlkem768x25519) per-slot recovery body. X-Wing decapsulate NEVER
# throws on attacker wire data (ML-KEM implicit rejection yields a pseudorandom
# shared secret), so there is no try/except around it: a wrong shared secret
# simply yields a KEK that fails the AEAD tag. As in the classical body, the
# AEAD is attempted on EVERY slot (full decapsulate + HKDF + AEAD-open) so
# matching and non-matching slots cost the same X-Wing work and a per-priv scan
# recovers a candidate CEK from every slot the recipient is addressed in.
# `pub_r_local` is the recipient's own 1216-byte X-Wing public key, recomputed
# from the held seed — the same value the producer bound into the KEK salt.
def _try_mlkem768x25519_slot(
    slot: SealedSlot, recipient_secret_key: bytes, pub_r_local: bytes
) -> bytes | None:
    # kem_ct length was validated to reassemble to _MLKEM768X25519_ENC_LENGTH in
    # _assert_envelope_structure, so this join + decapsulate is constant-work.
    enc = slot.kem_ct if slot.kem_ct is not None else b""
    ss = xwing_decapsulate(recipient_secret_key, enc)
    kek = hkdf_sha256(
        ikm=ss,
        salt=_xwing_kek_salt(enc, pub_r_local),
        info=CARDANO_POE_HKDF_INFO_KEK_MLKEM768X25519,
        length=32,
    )
    try:
        return chacha20_poly1305_decrypt(
            kek, _ZERO_NONCE_12, CARDANO_POE_HKDF_INFO_KEK_MLKEM768X25519, slot.wrap
        )
    except AeadVerificationError:
        return None


@dataclass(frozen=True)
class _InnerUnwrapResult:
    # The recovered CEK, the slot it came from, and a defence-in-depth conflict
    # flag. A producer may legitimately address the same recipient (or wrap the
    # same CEK) in several slots, so multiple matching slots are PERMITTED and
    # the first match's CEK is selected. But two matching slots recovering
    # DIFFERENT CEKs (both opening their per-slot wrap AEAD) is a commitment
    # collision the §G4 assumption rules out; `cek_conflict` flags it so the
    # caller can fail closed. The compare is constant-time; the inner loop visits
    # every slot (constant-time-N), so the flag does not leak match position.
    cek: bytes
    slot_idx: int
    cek_conflict: bool


# Per-priv inner trial-decrypt loop with slot-index reporting and CEK-conflict
# detection, KEM-driven. Enters every slot when constant_time_n; every slot
# attempts the wrap AEAD, so a recipient addressed in multiple slots recovers a
# candidate CEK from each. The first match's CEK is selected; any later match
# recovering a CEK that differs (constant-time compare) from the selected one
# sets `cek_conflict`. This follows the spec loop shape:
#
#   first        = ok AND NOT found
#   cek_conflict = cek_conflict OR (ok AND found AND NOT ct_eq(cand, selected))
#   selected_CEK = first ? cand : selected
#   found        = found OR ok
#
# No early break is taken when constant_time_n, so the conflict scan is constant
# across the whole slot set.
def _try_recipient_unwrap_with_idx(
    envelope: SealedEnvelope,
    recipient_secret_key: bytes,
    constant_time_n: bool,
    _slots_attempted_out: list[int] | None,
) -> _InnerUnwrapResult | None:
    cek: bytes | None = None
    matched_slot_idx = -1
    cek_conflict = False

    def record_match(candidate: bytes | None, i: int) -> None:
        nonlocal cek, matched_slot_idx, cek_conflict
        if candidate is None:
            return
        if cek is None:
            # first = ok AND NOT found.
            cek = candidate
            matched_slot_idx = i
        elif not compare_ct(candidate, cek):
            # ok AND found AND NOT ct_eq(cand, selected) — a later matching slot
            # whose recovered CEK differs from the already-selected one. Fail
            # closed.
            cek_conflict = True

    if envelope.kem == KEM_X25519:
        pub_r_local = x25519_public_key(recipient_secret_key)
        for i, slot in enumerate(envelope.slots):
            if _slots_attempted_out is not None:
                if not _slots_attempted_out:
                    _slots_attempted_out.append(i + 1)
                else:
                    _slots_attempted_out[0] = i + 1
            record_match(_try_x25519_slot(slot, recipient_secret_key, pub_r_local), i)
            if cek is not None and not constant_time_n:
                break
    else:
        # The recipient's own X-Wing public key, recomputed once from the seed,
        # is the `pub_R` term the producer bound into every slot's KEK salt.
        pub_r_local, _seed = xwing_keygen(recipient_secret_key)
        for i, slot in enumerate(envelope.slots):
            if _slots_attempted_out is not None:
                if not _slots_attempted_out:
                    _slots_attempted_out.append(i + 1)
                else:
                    _slots_attempted_out[0] = i + 1
            record_match(_try_mlkem768x25519_slot(slot, recipient_secret_key, pub_r_local), i)
            if cek is not None and not constant_time_n:
                break
    if cek is None:
        return None
    return _InnerUnwrapResult(cek=cek, slot_idx=matched_slot_idx, cek_conflict=cek_conflict)


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
            f"envelope.kem={envelope.kem!r} unsupported (expected 'x25519' or 'mlkem768x25519')",
        )

    # Envelope-level length pre-checks in this exact order.
    n = len(envelope.slots)
    if n < 1:
        raise EciesSealedPoeError(
            EciesSealedPoeError.ENC_SLOTS_EMPTY,
            f"envelope.slots length={n} must be >= 1",
        )
    # Resource bound: reject an envelope with more than MAX_SLOTS slots before any
    # KEM/AEAD primitive runs, so a malformed record cannot drive unbounded
    # per-slot work. Checked before the per-slot length loop below.
    if n > MAX_SLOTS:
        raise EciesSealedPoeError(
            EciesSealedPoeError.ENC_SLOTS_TOO_MANY,
            f"envelope.slots length={n} exceeds MAX_SLOTS={MAX_SLOTS}",
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

    # Decoded-envelope byte backstop. Every per-slot field above is validated to
    # a fixed length, so the decoded envelope's aggregate size is determined here:
    # nonce + slots_mac + per-slot (epk|kem_ct + wrap). Reject before any KEM/AEAD
    # primitive when it exceeds the bound — a tighter resource cap than MAX_SLOTS
    # for honest records, and the bound a parser that can see the decoded size
    # enforces.
    per_slot_bytes = (
        _X25519_PUBLIC_KEY_LENGTH + _WRAP_LENGTH
        if envelope.kem == KEM_X25519
        else _MLKEM768X25519_ENC_LENGTH + _WRAP_LENGTH
    )
    decoded_envelope_bytes = _NONCE_LENGTH + _SLOTS_MAC_LENGTH + n * per_slot_bytes
    if decoded_envelope_bytes > MAX_DECODED_ENVELOPE_BYTES:
        raise EciesSealedPoeError(
            EciesSealedPoeError.ENC_ENVELOPE_TOO_LARGE,
            f"decoded envelope size {decoded_envelope_bytes} exceeds "
            f"MAX_DECODED_ENVELOPE_BYTES={MAX_DECODED_ENVELOPE_BYTES}",
        )

    # Per-slot KEK uniqueness — rejected before any decapsulation so a duplicate
    # never enters the trial-decrypt loop. All slot lengths were validated above,
    # so the reassembled kem_ct / epk compared here are well-formed.
    _assert_unique_slot_kem_material(envelope.slots, envelope.kem)

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


# Slots transcript hash, the 32-byte message every candidate-CEK HMAC signs.
# KEM-driven so the hybrid kem_ct is committed via its canonical chunking and
# the cross-KEM header fields are bound. Constant across the trial-decrypt loop
# (depends only on the nonce, slots, and kem), so callers compute it once.
def _envelope_slots_hash(envelope: SealedEnvelope) -> bytes:
    return _compute_slots_hash(envelope.nonce, envelope.slots, envelope.kem)


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

    # The slots transcript hash is constant across every trial-decrypt pass
    # (depends only on the envelope), so it is computed once here.
    slots_hash = _envelope_slots_hash(envelope)

    if has_single:
        assert recipient_secret_key is not None  # noqa: S101
        candidate = _try_recipient_unwrap_with_idx(
            envelope, recipient_secret_key, constant_time_n, _slots_attempted_out
        )
        if candidate is None:
            return UnwrapResult(
                matched=False, plaintext=None, reason=UNWRAP_REASON_WRONG_RECIPIENT_KEY
            )
        # CEK-conflict defence-in-depth: a later matching slot recovered a CEK
        # that differs from the selected one. Fail closed with the generic
        # tampered-header reason (a commitment collision is an anomalous slot
        # set, not a recipient-key mismatch).
        if candidate.cek_conflict:
            return UnwrapResult(matched=False, plaintext=None, reason=UNWRAP_REASON_TAMPERED_HEADER)
        slots_mac_calc = _slots_mac_from_hash(candidate.cek, slots_hash)
        if not compare_ct(slots_mac_calc, envelope.slots_mac):
            return UnwrapResult(matched=False, plaintext=None, reason=UNWRAP_REASON_TAMPERED_HEADER)
        matched_cek = candidate.cek
    else:
        assert recipient_secret_keys is not None  # noqa: S101
        cek_conflict = False
        for k, priv in enumerate(recipient_secret_keys):
            if _privs_attempted_out is not None:
                if not _privs_attempted_out:
                    _privs_attempted_out.append(k + 1)
                else:
                    _privs_attempted_out[0] = k + 1
            inner_counter: list[int] | None = [] if _slots_attempted_out is not None else None
            candidate = _try_recipient_unwrap_with_idx(
                envelope, priv, constant_time_n, inner_counter
            )
            if _slots_attempted_out is not None and inner_counter is not None:
                _slots_attempted_out.append(inner_counter[0] if inner_counter else 0)
            if candidate is None:
                continue
            # A per-priv CEK conflict (two of this priv's slots recovering
            # different CEKs) makes the whole record anomalous regardless of
            # which priv matched the MAC — record it and fail closed after the
            # loop.
            if candidate.cek_conflict:
                cek_conflict = True
            cek = candidate.cek
            slots_mac_calc = _slots_mac_from_hash(cek, slots_hash)
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
        # A CEK conflict on the matching priv fails the record closed, even if
        # its first-slot CEK passed slots_mac.
        if matched_cek is not None and cek_conflict:
            return UnwrapResult(matched=False, plaintext=None, reason=UNWRAP_REASON_TAMPERED_HEADER)
        if matched_cek is None:
            reason = (
                UNWRAP_REASON_TAMPERED_HEADER
                if any_candidate_recovered
                else UNWRAP_REASON_WRONG_RECIPIENT_KEY
            )
            return UnwrapResult(matched=False, plaintext=None, reason=reason)

    # Content is opened under a payload_key derived from the recovered CEK, with
    # the structured slots-path AAD recomputed from the envelope. Guard the
    # single-shot bound before invoking the AEAD.
    _enforce_max_ciphertext(len(ciphertext))
    payload_key = _slots_payload_key(matched_cek, envelope.nonce)
    ad_content = _ad_content_slots(envelope.nonce, envelope.kem, slots_hash, envelope.slots_mac)
    try:
        plaintext = xchacha20_poly1305_decrypt(payload_key, envelope.nonce, ad_content, ciphertext)
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

    slots_hash = _envelope_slots_hash(envelope)
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
        # CEK-conflict defence-in-depth: this priv recovered different CEKs from
        # two matching slots — an anomalous slot set. Surface it as the generic
        # aead_pass_no_mac_match outcome (the trial-decrypt analogue of the
        # unwrap TAMPERED_HEADER rejection: a CEK opened but the slot set is not
        # trusted), never a clean match.
        if candidate.cek_conflict:
            any_candidate_recovered = True
            continue
        slots_mac_calc = _slots_mac_from_hash(candidate.cek, slots_hash)
        if compare_ct(slots_mac_calc, envelope.slots_mac):
            return TrialDecryptOnlyResult(
                kind=TRIAL_DECRYPT_KIND_MATCH, slot_idx=candidate.slot_idx, cek=candidate.cek
            )
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
