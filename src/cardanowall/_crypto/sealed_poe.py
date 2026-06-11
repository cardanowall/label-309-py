# Sealed-PoE construction for enc.scheme 1: multi-recipient KEM slots and the
# passphrase path, sharing one segmented-STREAM content layer.
#
# Wire-field names: scheme, aead, kem, nonce, slots, slots_mac, passphrase.
#
# Two KEM branches share one envelope shape, discriminated on the
# envelope-level `kem` field:
#
#   • kem == "x25519"          — classical ECIES. Per-slot epk(32) + wrap(48).
#   • kem == "mlkem768x25519"  — X-Wing hybrid (ML-KEM-768 + X25519). Per-slot
#                                the 1120-byte X-Wing ciphertext carried as a
#                                single byte string (`kem_ct`) + wrap(48). No
#                                per-slot epk.
#
# `SealedSlot` is a single dataclass with optional fields; a slot is classical
# when `epk` is present and hybrid when `kem_ct` is present.
#
# The construction binds the item's plaintext-hash claim: every wrap / unwrap /
# trial-decrypt / passphrase call takes the item's `hashes` map, and its
# labelled digest (`hashes_hash`) is committed inside the slots transcript (and
# the passphrase transcript), so an envelope spliced onto a different hash
# claim fails the on-chain MAC match before any ciphertext fetch.

from __future__ import annotations

import hashlib
import hmac as stdlib_hmac
import secrets
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Final

from .aead import (
    AeadVerificationError,
    chacha20_poly1305_decrypt,
    chacha20_poly1305_encrypt,
)
from .cbor import CanonicalCborValue, encode_canonical_cbor
from .compare_ct import compare_ct
from .kdf import argon2id_v13, hkdf_sha256
from .kem import X25519LowOrderPointError, x25519_ecdh, x25519_public_key
from .mlkem768x25519 import XWingLengthError, xwing_decapsulate, xwing_encapsulate, xwing_keygen
from .passphrase import (
    CARDANO_POE_PW_NORM_PROFILE,
    PassphraseNormalizationError,
    normalize_passphrase,
)
from .stream import TAG_SIZE, StreamTamperedError, stream_open, stream_seal

# HKDF info strings and SHA-256 prefix labels (KEK salts, transcripts, the
# item-hashes digest) are fixed protocol labels: exact ASCII, no terminator, no
# length prefix. Each is an internal building block of enc.scheme 1 — never
# serialised on the wire and never registry-selectable. The set is collision-
# free and prefix-free; the byte-length invariants below pin the
# SCREAMING_SNAKE constants to the literals every conformant verifier hashes
# against.
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
# SHA-256 prefixes for the per-slot KEK HKDF salts. Both KEMs use the same
# uniform shape — SHA-256(label || enc.nonce || <slot KEM material> || pub_R) —
# binding a slot-unique value, the recipient public key, and the
# envelope-unique nonce, so a CSPRNG failure that repeats KEM randomness across
# envelopes degrades to linkability instead of repeating a (KEK, zero-nonce)
# wrap pair.
CARDANO_POE_HASH_PREFIX_X25519_KEK_SALT: Final[bytes] = b"cardano-poe-x25519-kek-salt-v1"
CARDANO_POE_HASH_PREFIX_XWING_KEK_SALT: Final[bytes] = b"cardano-poe-xwing-kek-salt-v1"
# SHA-256 prefix for the item-hashes digest bound into both transcripts.
CARDANO_POE_HASH_PREFIX_ITEM_HASHES: Final[bytes] = b"cardano-poe-item-hashes-v1"
# SHA-256 prefix for the passphrase-transcript hash and HKDF info for the
# passphrase commitment MAC key (the 32-byte header inside the ciphertext
# blob — the passphrase path's analogue of slots_mac, kept off-chain so a
# chain-only observer gets no offline passphrase-test oracle).
CARDANO_POE_HASH_PREFIX_PASSPHRASE_TRANSCRIPT: Final[bytes] = (
    b"cardano-poe-passphrase-transcript-v1"
)
CARDANO_POE_HKDF_INFO_PASSPHRASE_MAC: Final[bytes] = b"cardano-poe-passphrase-mac-v1"

# Content-format identifier carried in `enc.aead`: RFC 8439 ChaCha20-Poly1305
# in the 64 KiB segmented STREAM layout (see `stream.py`). The sole registered
# content format under enc.scheme 1.
AEAD_CHACHA20_POLY1305_STREAM64K: Final[str] = "chacha20-poly1305-stream64k"

# The sole registered passphrase KDF under enc.scheme 1.
PASSPHRASE_KDF_ARGON2ID: Final[str] = "argon2id"  # noqa: S105 — KDF alg id, not a secret

UNWRAP_REASON_WRONG_RECIPIENT_KEY: Final[str] = "WRONG_RECIPIENT_KEY"
UNWRAP_REASON_TAMPERED_HEADER: Final[str] = "TAMPERED_HEADER"
UNWRAP_REASON_TAMPERED_CIPHERTEXT: Final[str] = "TAMPERED_CIPHERTEXT"

KEM_X25519: Final[str] = "x25519"
KEM_MLKEM768X25519: Final[str] = "mlkem768x25519"

_ZERO_NONCE_12: Final[bytes] = b"\x00" * 12
_EMPTY_SALT: Final[bytes] = b""
_ZERO_32: Final[bytes] = b"\x00" * 32
_X25519_PUBLIC_KEY_LENGTH: Final[int] = 32
_X25519_SECRET_KEY_LENGTH: Final[int] = 32
_CEK_LENGTH: Final[int] = 32
_NONCE_LENGTH: Final[int] = 24
_WRAP_LENGTH: Final[int] = 48
_SLOTS_MAC_LENGTH: Final[int] = 32
_COMMITMENT_LENGTH: Final[int] = 32

# X-Wing (ML-KEM-768 + X25519) component sizes, per draft-connolly-cfrg-xwing-kem
# / FIPS 203 / RFC 7748.
_MLKEM768X25519_PUBLIC_KEY_LENGTH: Final[int] = 1216
_MLKEM768X25519_ENC_LENGTH: Final[int] = 1120
_MLKEM768X25519_ESEED_LENGTH: Final[int] = 64

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

# Argon2id passphrase-envelope wire bounds: the salt is 16..64 bytes inclusive,
# and every params value is a uint in the pinned wire range 0..2^32-1, at or
# above the registry floors (memory >= 65536 KiB, iterations >= 3,
# parallelism >= 1 — security is dominated by the m x t product, with p >= 1 a
# deliberate browser-compatibility floor).
PASSPHRASE_SALT_MIN_BYTES: Final[int] = 16
PASSPHRASE_SALT_MAX_BYTES: Final[int] = 64
_PASSPHRASE_PARAM_MAX: Final[int] = (1 << 32) - 1
_ARGON2_M_MIN: Final[int] = 65536
_ARGON2_T_MIN: Final[int] = 3
_ARGON2_P_MIN: Final[int] = 1

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
if len(CARDANO_POE_HASH_PREFIX_X25519_KEK_SALT) != 30:
    raise RuntimeError(
        "CARDANO_POE_HASH_PREFIX_X25519_KEK_SALT byte-length invariant violated (expected 30)"
    )
if len(CARDANO_POE_HASH_PREFIX_XWING_KEK_SALT) != 29:
    raise RuntimeError(
        "CARDANO_POE_HASH_PREFIX_XWING_KEK_SALT byte-length invariant violated (expected 29)"
    )
if len(CARDANO_POE_HASH_PREFIX_ITEM_HASHES) != 26:
    raise RuntimeError(
        "CARDANO_POE_HASH_PREFIX_ITEM_HASHES byte-length invariant violated (expected 26)"
    )
if len(CARDANO_POE_HASH_PREFIX_PASSPHRASE_TRANSCRIPT) != 36:
    raise RuntimeError(
        "CARDANO_POE_HASH_PREFIX_PASSPHRASE_TRANSCRIPT byte-length invariant violated (expected 36)"
    )
if len(CARDANO_POE_HKDF_INFO_PASSPHRASE_MAC) != 29:
    raise RuntimeError(
        "CARDANO_POE_HKDF_INFO_PASSPHRASE_MAC byte-length invariant violated (expected 29)"
    )
if len(_ZERO_NONCE_12) != 12:
    raise RuntimeError("_ZERO_NONCE_12 byte-length invariant violated (expected 12)")


class EciesSealedPoeError(Exception):
    # Sealed-PoE construction error taxonomy. Codes whose concept is wire-
    # identical reuse the registry string (UNSUPPORTED_ENVELOPE_SCHEME,
    # UNSUPPORTED_AEAD_ALG, ENC_PASSPHRASE_EMPTY, ...); codes with no wire
    # counterpart (raw caller-input length errors, deterministic-override
    # mismatches) carry construction-only names.
    ENC_SLOTS_EMPTY = "ENC_SLOTS_EMPTY"
    ENC_SLOTS_MAC_INVALID_LENGTH = "ENC_SLOTS_MAC_INVALID_LENGTH"
    KEM_EPK_LENGTH_MISMATCH = "KEM_EPK_LENGTH_MISMATCH"
    KEM_CT_LENGTH_MISMATCH = "KEM_CT_LENGTH_MISMATCH"
    INVALID_CEK_LENGTH = "INVALID_CEK_LENGTH"
    NONCE_LENGTH_MISMATCH = "NONCE_LENGTH_MISMATCH"
    INVALID_EPHEMERAL_SECRET_LENGTH = "INVALID_EPHEMERAL_SECRET_LENGTH"  # noqa: S105
    EPHEMERAL_SECRETS_COUNT_MISMATCH = "EPHEMERAL_SECRETS_COUNT_MISMATCH"
    UNSUPPORTED_ENVELOPE_SCHEME = "UNSUPPORTED_ENVELOPE_SCHEME"
    UNSUPPORTED_AEAD_ALG = "UNSUPPORTED_AEAD_ALG"
    UNSUPPORTED_KEM_ALG = "UNSUPPORTED_KEM_ALG"
    INVALID_RECIPIENT_KEY = "INVALID_RECIPIENT_KEY"
    WRAP_LENGTH_MISMATCH = "WRAP_LENGTH_MISMATCH"
    # An item carrying an encryption envelope MUST commit to its plaintext: the
    # construction refuses an empty `hashes` map (there would be nothing for
    # the transcript's hashes_hash to bind).
    ENC_REQUIRES_CONTENT_HASH = "ENC_REQUIRES_CONTENT_HASH"
    # Two slots carry identical per-slot KEM material (duplicate `epk` for
    # x25519, or duplicate `kem_ct` for the hybrid path). The zero-nonce
    # per-slot wrap is sound only under per-slot KEK uniqueness; repeated KEM
    # material can repeat the (KEK, nonce) pair, so such an envelope is
    # rejected before any decapsulation.
    ENC_SLOTS_DUPLICATE_KEM_MATERIAL = "ENC_SLOTS_DUPLICATE_KEM_MATERIAL"
    # Resource bounds tripped before any KEM/AEAD primitive: more than MAX_SLOTS
    # slots, or a decoded envelope larger than MAX_DECODED_ENVELOPE_BYTES.
    ENC_SLOTS_TOO_MANY = "ENC_SLOTS_TOO_MANY"
    ENC_ENVELOPE_TOO_LARGE = "ENC_ENVELOPE_TOO_LARGE"
    # Passphrase path.
    ENC_PASSPHRASE_ALG_UNSUPPORTED = "ENC_PASSPHRASE_ALG_UNSUPPORTED"  # noqa: S105
    ENC_PASSPHRASE_SALT_TOO_SHORT = "ENC_PASSPHRASE_SALT_TOO_SHORT"  # noqa: S105
    ENC_PASSPHRASE_SALT_TOO_LONG = "ENC_PASSPHRASE_SALT_TOO_LONG"  # noqa: S105
    ENC_PASSPHRASE_ARGON2_PARAMS_TOO_LOW = "ENC_PASSPHRASE_ARGON2_PARAMS_TOO_LOW"  # noqa: S105
    ENC_PASSPHRASE_EMPTY = "ENC_PASSPHRASE_EMPTY"  # noqa: S105
    PASSPHRASE_INPUT_TOO_LONG = "PASSPHRASE_INPUT_TOO_LONG"  # noqa: S105
    INVALID_PASSPHRASE_PARAMS = "INVALID_PASSPHRASE_PARAMS"  # noqa: S105
    KDF_DERIVATION_FAILED = "KDF_DERIVATION_FAILED"

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code: str = code


# Per-slot wire shape, discriminated on field presence (the `kem` identifier is
# hoisted to envelope scope — every slot shares it):
#   • x25519:         { epk: bstr(32), wrap: bstr(48) }      → epk set, kem_ct None
#   • mlkem768x25519: { kem_ct: bstr(1120), wrap: bstr(48) } → kem_ct set, epk None
@dataclass(frozen=True)
class SealedSlot:
    wrap: bytes
    epk: bytes | None = None
    kem_ct: bytes | None = None


# Sealed envelope wire shape (slots path).
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


# Argon2id work-factor parameters as carried on the wire (`enc.passphrase.params`).
@dataclass(frozen=True)
class Argon2idParams:
    m: int  # memory, KiB
    t: int  # iterations
    p: int  # parallelism


# Sealed envelope wire shape (passphrase path): no slots, no slots_mac; the key
# commitment lives in the 32-byte header inside the ciphertext blob.
@dataclass(frozen=True)
class PassphraseEnvelope:
    scheme: int  # MUST be 1
    aead: str
    nonce: bytes
    alg: str
    salt: bytes
    params: Argon2idParams


@dataclass(frozen=True)
class PassphraseSealedPoeOutput:
    envelope: PassphraseEnvelope
    # commitment(32) || STREAM chunks — one blob, one URI, one fetch.
    ciphertext: bytes


# Trial-decrypt-only result discriminator: either a slot was accepted under the
# per-slot fold (kem_ok AND wrap_open_ok AND mac_ok) or nothing was — there is
# deliberately no finer-grained outcome, so a non-recipient cannot learn why a
# record is not theirs.
TRIAL_DECRYPT_KIND_MATCH: Final[str] = "match"
TRIAL_DECRYPT_KIND_NO_MATCH: Final[str] = "no_match"


@dataclass(frozen=True)
class TrialDecryptOnlyResult:
    kind: str
    slot_idx: int | None
    cek: bytes | None


# Labelled digest of the item's complete `hashes` map (every algorithm entry,
# canonically encoded). Bound into both transcripts so a slots_mac (or a
# passphrase commitment) match confirms the envelope was sealed for THIS item's
# hash claim; an envelope spliced onto a different `hashes` map fails the match
# step before any ciphertext fetch.
def item_hashes_hash(hashes: Mapping[str, bytes]) -> bytes:
    if len(hashes) == 0:
        raise EciesSealedPoeError(
            EciesSealedPoeError.ENC_REQUIRES_CONTENT_HASH,
            "an enc-bearing item's hashes map MUST carry at least one content hash",
        )
    value: dict[str | int, CanonicalCborValue] = {alg: digest for alg, digest in hashes.items()}
    return hashlib.sha256(
        CARDANO_POE_HASH_PREFIX_ITEM_HASHES + encode_canonical_cbor(value)
    ).digest()


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


# The slot array as bound under the `slots` key of SLOTS_TRANSCRIPT — the
# closed slot maps exactly as they appear on the wire. Single source of truth
# shared by wrap (compute) and unwrap/trial-decrypt (verify), so producer and
# verifier cannot diverge on the bytes the transcript commits to:
#
#   • x25519:         each slot → { epk: bstr(32), wrap: bstr(48) }
#   • mlkem768x25519: each slot → { kem_ct: bstr(1120), wrap: bstr(48) }
#
# Canonical-CBOR sorting orders each slot map's keys at encode time; the key
# set here is a set, never an ordering.
def _slots_transcript_value(slots: Sequence[SealedSlot], kem: str) -> list[CanonicalCborValue]:
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
            h_entry: dict[str | int, CanonicalCborValue] = {
                "kem_ct": s.kem_ct if s.kem_ct is not None else b"",
                "wrap": s.wrap,
            }
            value.append(h_entry)
    return value


# SLOTS_TRANSCRIPT is a closed seven-key map binding the slot set together with
# the cross-KEM header fields that fix how the slots are interpreted, and the
# item's plaintext-hash claim. It is hashed once to a 32-byte slots_hash that
# the CEK-keyed HMAC then signs. A relay that flips scheme / aead / kem / nonce
# — or splices the envelope onto a different hashes map — produces a different
# slots_hash, so the MAC fails. canonicalEncode determines map key order via
# the RFC 8949 §4.2.1 sort; the key set here is a set, never an ordering.
def _slots_transcript(
    nonce: bytes, slots: Sequence[SealedSlot], kem: str, hashes_hash: bytes
) -> bytes:
    transcript: dict[str | int, CanonicalCborValue] = {
        "scheme": 1,
        "path": "slots",
        "aead": AEAD_CHACHA20_POLY1305_STREAM64K,
        "kem": kem,
        "nonce": nonce,
        "slots": _slots_transcript_value(slots, kem),
        "hashes_hash": hashes_hash,
    }
    return encode_canonical_cbor(transcript)


def _compute_slots_hash(
    nonce: bytes, slots: Sequence[SealedSlot], kem: str, hashes_hash: bytes
) -> bytes:
    return hashlib.sha256(
        CARDANO_POE_HASH_PREFIX_SLOTS_TRANSCRIPT + _slots_transcript(nonce, slots, kem, hashes_hash)
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


def _slots_payload_key(cek: bytes, nonce: bytes) -> bytes:
    return hkdf_sha256(
        ikm=cek,
        salt=nonce,
        info=CARDANO_POE_HKDF_INFO_PAYLOAD,
        length=32,
    )


def _passphrase_payload_key(cek: bytes, nonce: bytes) -> bytes:
    return hkdf_sha256(
        ikm=cek,
        salt=nonce,
        info=CARDANO_POE_HKDF_INFO_PAYLOAD_PASSPHRASE,
        length=32,
    )


# Per-slot KEK HKDF salts: SHA-256(label || enc.nonce || <slot KEM material> ||
# pub_R). The slot's own KEM material anchors the KEK to a slot-unique value;
# the recipient public key binds it to the specific recipient (defeating
# confused-deputy relay of a slot's KEM material against another recipient);
# the envelope-unique nonce anchors it to one envelope. Computed outside the
# KEM, over the slot's own wire bytes, so X-Wing is held as a black box.
def _x25519_kek_salt(nonce: bytes, epk: bytes, pub_r: bytes) -> bytes:
    return hashlib.sha256(CARDANO_POE_HASH_PREFIX_X25519_KEK_SALT + nonce + epk + pub_r).digest()


def _xwing_kek_salt(nonce: bytes, kem_ct: bytes, pub_r: bytes) -> bytes:
    return hashlib.sha256(CARDANO_POE_HASH_PREFIX_XWING_KEK_SALT + nonce + kem_ct + pub_r).digest()


# Per-slot KEK-uniqueness gate. The zero-nonce wrap is sound only when every
# slot's KEK is unique; the KEK is a deterministic function of the slot's KEM
# material (plus the recipient public key and the envelope nonce), so two slots
# carrying identical KEM material against the same recipient repeat the
# (KEK, nonce) pair. We reject an envelope with duplicate per-slot KEM material
# — duplicate `epk` for x25519, duplicate `kem_ct` for the hybrid path — on
# both the producer side (before committing to the wire) and the verifier side
# (before any decapsulation).
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


# Wrap the CEK for one classical recipient.
def _wrap_slot_x25519(
    nonce: bytes, pub_r: bytes, priv_eph: bytes | None, cek: bytes, slot_idx: int
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
    kek = hkdf_sha256(
        ikm=shared,
        salt=_x25519_kek_salt(nonce, epk, pub_r),
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
# Encapsulation applies the pinned X-Wing revision's public-key validity check
# (the FIPS 203 modulus check on the ML-KEM encapsulation key); an invalid
# recipient key is rejected before any slot is produced.
def _wrap_slot_mlkem768x25519(
    nonce: bytes, pub_r: bytes, eseed: bytes | None, cek: bytes, slot_idx: int
) -> SealedSlot:
    try:
        enc, ss = xwing_encapsulate(pub_r, eseed)
    except XWingLengthError:
        raise
    except ValueError as cause:
        raise EciesSealedPoeError(
            EciesSealedPoeError.INVALID_RECIPIENT_KEY,
            f"recipient_public_keys[{slot_idx}] failed the X-Wing public-key "
            f"validity check: {cause}",
        ) from cause
    if len(enc) != _MLKEM768X25519_ENC_LENGTH:
        raise RuntimeError(
            f"internal: enc length={len(enc)}, expected {_MLKEM768X25519_ENC_LENGTH}"
        )
    kek = hkdf_sha256(
        ikm=ss,
        salt=_xwing_kek_salt(nonce, enc, pub_r),
        info=CARDANO_POE_HKDF_INFO_KEK_MLKEM768X25519,
        length=32,
    )
    wrap = chacha20_poly1305_encrypt(
        kek, _ZERO_NONCE_12, CARDANO_POE_HKDF_INFO_KEK_MLKEM768X25519, cek
    )
    if len(wrap) != _WRAP_LENGTH:
        raise RuntimeError(f"internal: wrap length={len(wrap)}, expected {_WRAP_LENGTH}")
    return SealedSlot(kem_ct=enc, wrap=wrap)


def ecies_sealed_poe_wrap(
    *,
    plaintext: bytes,
    recipient_public_keys: Sequence[bytes],
    # The item's complete hashes map (algorithm id → digest bytes). Its
    # labelled digest is bound into the slots transcript, so the on-chain
    # slots_mac commits to this item's hash claim.
    hashes: Mapping[str, bytes],
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

    # The KEM identifier is validated before any per-recipient check: an
    # unsupported algorithm is its own error, never a key-length complaint.
    if kem not in (KEM_X25519, KEM_MLKEM768X25519):
        raise EciesSealedPoeError(
            EciesSealedPoeError.UNSUPPORTED_KEM_ALG,
            f"kem={kem!r} unsupported (expected 'x25519' or 'mlkem768x25519')",
        )

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
                    f"eseeds length={len(eseeds)} must match recipient_public_keys length={n}",
                )
            for i, eseed in enumerate(eseeds):
                if len(eseed) != _MLKEM768X25519_ESEED_LENGTH:
                    raise EciesSealedPoeError(
                        EciesSealedPoeError.INVALID_EPHEMERAL_SECRET_LENGTH,
                        f"eseeds[{i}] MUST be exactly "
                        f"{_MLKEM768X25519_ESEED_LENGTH} bytes, got {len(eseed)}",
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

    # The item's hash claim, digested once; raises on an empty map.
    hashes_hash = item_hashes_hash(hashes)

    slots: list[SealedSlot] = []
    if kem == KEM_X25519:
        for i, pub_r in enumerate(recipient_public_keys):
            priv_eph = ephemeral_secrets[i] if ephemeral_secrets is not None else None
            slots.append(_wrap_slot_x25519(nonce, pub_r, priv_eph, cek, i))
    else:
        for i, pub_r in enumerate(recipient_public_keys):
            eseed_i = eseeds[i] if eseeds is not None else None
            slots.append(_wrap_slot_mlkem768x25519(nonce, pub_r, eseed_i, cek, i))

    # Per-slot KEK uniqueness is the safety condition for the zero-nonce wrap.
    # Duplicate per-slot KEM material (a repeated x25519 epk, or a repeated
    # hybrid kem_ct) would repeat the (KEK, nonce) pair, so reject it at the
    # producer before committing anything to the wire.
    _assert_unique_slot_kem_material(slots, kem)

    # Anonymity invariant: post-wrap CSPRNG shuffle so wire ordering encodes
    # no recipient identity.
    if not skip_shuffle:
        slots = _csprng_shuffle(slots)

    # Slot-set MAC binds the slots transcript hash (header fields + slot bytes
    # + the item's hashes_hash) to the CEK; the transcript is hashed once and
    # signed with a CEK-keyed HMAC.
    slots_hash = _compute_slots_hash(nonce, slots, kem, hashes_hash)
    slots_mac = _slots_mac_from_hash(cek, slots_hash)

    # Content is encrypted in the segmented STREAM format under a payload_key
    # derived from the CEK (never the CEK directly), salted by the
    # envelope-unique nonce. The per-chunk AAD is empty: all context is bound
    # transitively — payload_key derives from the CEK, and the CEK is committed
    # to the full header (including hashes_hash) by slots_mac.
    payload_key = _slots_payload_key(cek, nonce)
    ciphertext = stream_seal(payload_key, plaintext)

    envelope = SealedEnvelope(
        scheme=1,
        aead=AEAD_CHACHA20_POLY1305_STREAM64K,
        kem=kem,
        nonce=nonce,
        slots=tuple(slots),
        slots_mac=slots_mac,
    )
    return SealedPoeOutput(envelope=envelope, ciphertext=ciphertext)


# Per-private-key scan over the full slot array with the slot-set MAC folded
# into per-slot acceptance.
@dataclass(frozen=True)
class _SlotScanResult:
    found: bool
    cek: bytes
    slot_idx: int
    # A slot's wrap AEAD opened under this key (regardless of the MAC outcome).
    # Distinguishes the internal TAMPERED_HEADER diagnostic (something opened
    # but nothing reproduced slots_mac) from WRONG_RECIPIENT_KEY (nothing
    # opened at all).
    any_wrap_opened: bool
    # Two accepted slots recovered different CEKs — the multi-key commitment
    # collision the slot-set MAC assumption rules out. Fail closed.
    cek_conflict: bool


# The trial-decrypt loop body for one private key. A slot is accepted only when
# `kem_ok AND wrap_open_ok AND mac_ok` — the per-slot fold. This makes a forged
# shadow slot (one that wrap-opens under the recipient's key with an
# attacker-chosen CEK) inert: its CEK does not reproduce slots_mac, the slot is
# skipped exactly like a non-matching one, and an honest slot anywhere later in
# the array still wins.
#
# The loop visits EVERY slot — no early break — so a network-level observer
# cannot infer which slot index matched, and every slot pays the same KEM +
# HKDF + AEAD + MAC work: an invalid X25519 ECDH (small-order epk, all-zero
# shared secret) derives a dummy KEK from a zero IKM and still attempts the
# wrap-open and the MAC, with `kem_ok = 0` folded into the acceptance bit so
# such a slot can never be accepted regardless of the wrap or MAC outcome.
#
# The running selection state folds branchlessly: 0|1 bits combine with `&`/`|`
# (never a short-circuit) and the selected CEK / index update through byte and
# word masks on every slot, so no source-level control flow keys on which slot
# matched. CPython offers no hardware constant-time guarantee, so this is the
# best-effort selection discipline, not a timing proof.
def _scan_slots(
    envelope: SealedEnvelope,
    recipient_secret_key: bytes,
    slots_hash: bytes,
    _slots_attempted_out: list[int] | None,
) -> _SlotScanResult:
    if envelope.kem == KEM_X25519:
        pub_r_local = x25519_public_key(recipient_secret_key)
    else:
        # The recipient's own X-Wing public key, recomputed once from the seed,
        # is the `pub_R` term the producer bound into every slot's KEK salt.
        pub_r_local, _seed = xwing_keygen(recipient_secret_key)

    found = 0
    cek_conflict = 0
    any_wrap_opened = 0
    selected_cek: bytes = _ZERO_32
    selected_idx = -1

    for i, slot in enumerate(envelope.slots):
        if _slots_attempted_out is not None:
            if not _slots_attempted_out:
                _slots_attempted_out.append(i + 1)
            else:
                _slots_attempted_out[0] = i + 1

        if envelope.kem == KEM_X25519:
            epk = slot.epk if slot.epk is not None else b""
            kek_salt = _x25519_kek_salt(envelope.nonce, epk, pub_r_local)
            ad_wrap = CARDANO_POE_HKDF_INFO_KEK
            try:
                shared = x25519_ecdh(recipient_secret_key, epk)
                kem_ok = 1
                kek = hkdf_sha256(ikm=shared, salt=kek_salt, info=ad_wrap, length=32)
            except X25519LowOrderPointError:
                # RFC 7748 §6.1 all-zero shared secret: kem_ok = 0. Derive a
                # dummy KEK from a zero IKM (same salt/info — same HKDF work)
                # and fall through to the same wrap-open + MAC, so the failed
                # slot costs the same as a live one and is never accepted.
                kem_ok = 0
                kek = hkdf_sha256(ikm=_ZERO_32, salt=kek_salt, info=ad_wrap, length=32)
        else:
            enc_ct = slot.kem_ct if slot.kem_ct is not None else b""
            # X-Wing decapsulation never raises on attacker wire content:
            # ML-KEM implicit rejection yields a pseudorandom shared secret, so
            # a garbage kem_ct of valid length simply derives a KEK that fails
            # the wrap tag.
            shared = xwing_decapsulate(recipient_secret_key, enc_ct)
            kem_ok = 1
            ad_wrap = CARDANO_POE_HKDF_INFO_KEK_MLKEM768X25519
            kek = hkdf_sha256(
                ikm=shared,
                salt=_xwing_kek_salt(envelope.nonce, enc_ct, pub_r_local),
                info=ad_wrap,
                length=32,
            )

        # Atomic wrap open: on tag failure no plaintext is released and the
        # candidate CEK is a fixed dummy independent of the failed ciphertext.
        try:
            candidate_cek = chacha20_poly1305_decrypt(kek, _ZERO_NONCE_12, ad_wrap, slot.wrap)
            open_ok = 1
        except AeadVerificationError:
            candidate_cek = _ZERO_32
            open_ok = 0

        # The MAC is recomputed for every slot — matching and non-matching
        # slots pay identical HKDF + HMAC work — always over the same 32-byte
        # slots_hash.
        mac_ok = int(
            compare_ct(_slots_mac_from_hash(candidate_cek, slots_hash), envelope.slots_mac)
        )

        # Mask fold:
        #   ok           = kem_ok AND open_ok AND mac_ok
        #   first        = ok AND NOT found
        #   cek_conflict = cek_conflict OR (ok AND found AND NOT eq(cand, sel))
        #   selected     = select(first, candidate, selected)
        #   found        = found OR ok
        # The candidate-vs-selected comparison runs unconditionally; its
        # conflict contribution is masked off unless both slots were accepted.
        ok = kem_ok & open_ok & mac_ok
        any_wrap_opened |= kem_ok & open_ok
        first = ok & (found ^ 1)
        neq = int(compare_ct(candidate_cek, selected_cek)) ^ 1
        cek_conflict |= ok & found & neq
        byte_mask = (-first) & 0xFF
        inv_byte_mask = byte_mask ^ 0xFF
        selected_cek = bytes(
            (c & byte_mask) | (s & inv_byte_mask)
            for c, s in zip(candidate_cek, selected_cek, strict=True)
        )
        selected_idx = (i & -first) | (selected_idx & ~(-first))
        found |= ok

    return _SlotScanResult(
        found=bool(found),
        cek=selected_cek,
        slot_idx=selected_idx,
        any_wrap_opened=bool(any_wrap_opened),
        cek_conflict=bool(cek_conflict),
    )


# Partitioning-oracle defence: every wire length MUST be validated before any
# KEM/AEAD primitive is invoked, so malformed records cannot probe per-slot
# failure ordering. Shared between unwrap (single- and multi-priv) and
# trial-decrypt to guarantee byte-identical pre-trial behaviour.
def _assert_envelope_structure(
    envelope: SealedEnvelope,
    recipient_secret_keys: Sequence[bytes],
) -> None:
    if envelope.scheme != 1:
        raise EciesSealedPoeError(
            EciesSealedPoeError.UNSUPPORTED_ENVELOPE_SCHEME,
            f"envelope.scheme={envelope.scheme} unsupported (expected 1)",
        )
    if envelope.aead != AEAD_CHACHA20_POLY1305_STREAM64K:
        raise EciesSealedPoeError(
            EciesSealedPoeError.UNSUPPORTED_AEAD_ALG,
            f"envelope.aead={envelope.aead!r} unsupported "
            f"(expected {AEAD_CHACHA20_POLY1305_STREAM64K!r})",
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
                    f"envelope.slots[{i}].kem_ct MUST be exactly "
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
    # so the kem_ct / epk values compared here are well-formed.
    _assert_unique_slot_kem_material(envelope.slots, envelope.kem)

    for k, priv in enumerate(recipient_secret_keys):
        if len(priv) != _X25519_SECRET_KEY_LENGTH:
            raise EciesSealedPoeError(
                EciesSealedPoeError.INVALID_RECIPIENT_KEY,
                f"recipient_secret_keys[{k}] MUST be exactly "
                f"{_X25519_SECRET_KEY_LENGTH} bytes, got {len(priv)}",
            )


# Multi-recipient sealed-PoE unwrap (per-slot-folded trial-decrypt +
# partitioning-oracle length pre-checks + STREAM content open).
#
# Two forms (mutually exclusive — exactly one MUST be supplied):
#   • Single-priv form: `recipient_secret_key=<32 bytes>` — the standalone-
#     verifier path.
#   • Multi-priv form: `recipient_secret_keys=Sequence[bytes]` — for a rotated
#     identity holding `[current_priv, ...archived_privs]`. Caller supplies the
#     order; the iterator runs outer-loop = privkey x inner-loop = slot,
#     short-circuiting on the first priv with an accepted slot.
#
# Within one private key's pass the loop is constant-time across slots: every
# slot is visited and pays the same KEM + HKDF + AEAD + MAC work regardless of
# where (or whether) a match lands. The outer cross-priv loop short-circuits —
# variable time there leaks only the weak "which key matched" signal (how many
# rotations the recipient has performed), a documented trade-off; making it
# constant-work would cost a full KEM decapsulation per archived priv on every
# record.
def ecies_sealed_poe_unwrap(
    *,
    envelope: SealedEnvelope,
    ciphertext: bytes,
    hashes: Mapping[str, bytes],
    recipient_secret_key: bytes | None = None,
    recipient_secret_keys: Sequence[bytes] | None = None,
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
    privs: Sequence[bytes]
    if has_multi:
        assert recipient_secret_keys is not None  # noqa: S101
        if len(recipient_secret_keys) == 0:
            raise EciesSealedPoeError(
                EciesSealedPoeError.INVALID_RECIPIENT_KEY,
                "recipient_secret_keys MUST be a non-empty sequence, got length=0",
            )
        privs = recipient_secret_keys
    else:
        assert recipient_secret_key is not None  # noqa: S101
        privs = [recipient_secret_key]

    # Partitioning-oracle pre-checks (incl. per-priv length validation).
    _assert_envelope_structure(envelope, privs)

    # hashes_hash, the transcript, and slots_hash are computed once, before the
    # loop, and held constant across it: the per-slot MAC check re-keys HMAC
    # from each candidate CEK but always over the same 32-byte slots_hash.
    hashes_hash = item_hashes_hash(hashes)
    slots_hash = _compute_slots_hash(envelope.nonce, envelope.slots, envelope.kem, hashes_hash)

    matched_cek: bytes | None = None
    any_wrap_opened = False

    for k, priv in enumerate(privs):
        if _privs_attempted_out is not None:
            if not _privs_attempted_out:
                _privs_attempted_out.append(k + 1)
            else:
                _privs_attempted_out[0] = k + 1
        if has_multi:
            inner_counter: list[int] | None = [] if _slots_attempted_out is not None else None
        else:
            inner_counter = _slots_attempted_out
        scan = _scan_slots(envelope, priv, slots_hash, inner_counter)
        if has_multi and _slots_attempted_out is not None and inner_counter is not None:
            _slots_attempted_out.append(inner_counter[0] if inner_counter else 0)
        # A CEK conflict — two accepted slots recovering different CEKs under
        # one key — is anomalous for the whole record; fail closed regardless
        # of which slot would have won.
        if scan.cek_conflict:
            return UnwrapResult(matched=False, plaintext=None, reason=UNWRAP_REASON_TAMPERED_HEADER)
        if scan.found:
            matched_cek = scan.cek
            break
        any_wrap_opened = any_wrap_opened or scan.any_wrap_opened

    if matched_cek is None:
        # Internal diagnostic split (never distinguishable to an untrusted
        # caller): something wrap-opened but nothing reproduced slots_mac →
        # the header was tampered; nothing opened at all → not a recipient.
        reason = (
            UNWRAP_REASON_TAMPERED_HEADER if any_wrap_opened else UNWRAP_REASON_WRONG_RECIPIENT_KEY
        )
        return UnwrapResult(matched=False, plaintext=None, reason=reason)

    # Content opens under a payload_key derived from the accepted CEK, in the
    # segmented STREAM format; every chunk tag is verified before its plaintext
    # is released, and any layout violation fails the whole open.
    payload_key = _slots_payload_key(matched_cek, envelope.nonce)
    try:
        plaintext = stream_open(payload_key, ciphertext)
    except StreamTamperedError:
        return UnwrapResult(matched=False, plaintext=None, reason=UNWRAP_REASON_TAMPERED_CIPHERTEXT)
    return UnwrapResult(matched=True, plaintext=plaintext, reason=None)


# Trial-decrypt half of the sealed-PoE unwrap algorithm: recovers the CEK +
# slot index from the on-chain envelope bytes alone, without touching the
# content. Used by feed-scan agents where the envelope is available but the
# ciphertext is fetched lazily only at decrypt time.
#
# The result is deliberately binary — match or no-match. Every per-slot
# distinction (KEM validity, wrap-open, MAC) is folded into the acceptance bit,
# so a forged or tampered envelope is indistinguishable from "not mine".
def ecies_sealed_poe_trial_decrypt(
    *,
    envelope: SealedEnvelope,
    hashes: Mapping[str, bytes],
    recipient_secret_keys: Sequence[bytes],
    _slots_attempted_out: list[int] | None = None,
    _privs_attempted_out: list[int] | None = None,
) -> TrialDecryptOnlyResult:
    if len(recipient_secret_keys) == 0:
        raise EciesSealedPoeError(
            EciesSealedPoeError.INVALID_RECIPIENT_KEY,
            "recipient_secret_keys MUST be a non-empty sequence, got length=0",
        )
    _assert_envelope_structure(envelope, recipient_secret_keys)

    hashes_hash = item_hashes_hash(hashes)
    slots_hash = _compute_slots_hash(envelope.nonce, envelope.slots, envelope.kem, hashes_hash)

    for k, priv in enumerate(recipient_secret_keys):
        if _privs_attempted_out is not None:
            if not _privs_attempted_out:
                _privs_attempted_out.append(k + 1)
            else:
                _privs_attempted_out[0] = k + 1
        inner_counter: list[int] | None = [] if _slots_attempted_out is not None else None
        scan = _scan_slots(envelope, priv, slots_hash, inner_counter)
        if _slots_attempted_out is not None and inner_counter is not None:
            _slots_attempted_out.append(inner_counter[0] if inner_counter else 0)
        # A CEK conflict makes the whole record anomalous — never a match.
        if scan.cek_conflict:
            return TrialDecryptOnlyResult(kind=TRIAL_DECRYPT_KIND_NO_MATCH, slot_idx=None, cek=None)
        if scan.found:
            return TrialDecryptOnlyResult(
                kind=TRIAL_DECRYPT_KIND_MATCH, slot_idx=scan.slot_idx, cek=scan.cek
            )
    return TrialDecryptOnlyResult(kind=TRIAL_DECRYPT_KIND_NO_MATCH, slot_idx=None, cek=None)


# ---------------------------------------------------------------------------
# Passphrase path.
# ---------------------------------------------------------------------------


# Shape checks shared by seal (over caller inputs) and open (over wire data),
# run before any KDF work: each value a uint within the wire range, then the
# registry floors (m >= 65536 KiB, t >= 3, p >= 1). A below-floor passphrase
# envelope is categorically outside the construction — it cannot be produced
# OR opened through this API — so weak-KDF records never enter circulation.
def _assert_argon2id_params(params: Argon2idParams) -> None:
    for name, value in (("m", params.m), ("t", params.t), ("p", params.p)):
        if isinstance(value, bool) or not isinstance(value, int):
            raise EciesSealedPoeError(
                EciesSealedPoeError.INVALID_PASSPHRASE_PARAMS,
                f"params.{name} MUST be an integer",
            )
        if value < 0 or value > _PASSPHRASE_PARAM_MAX:
            raise EciesSealedPoeError(
                EciesSealedPoeError.INVALID_PASSPHRASE_PARAMS,
                f"params.{name}={value} outside the wire range 0..{_PASSPHRASE_PARAM_MAX}",
            )
    if params.m < _ARGON2_M_MIN or params.t < _ARGON2_T_MIN or params.p < _ARGON2_P_MIN:
        raise EciesSealedPoeError(
            EciesSealedPoeError.ENC_PASSPHRASE_ARGON2_PARAMS_TOO_LOW,
            f"params MUST satisfy m >= {_ARGON2_M_MIN}, t >= {_ARGON2_T_MIN}, "
            f"p >= {_ARGON2_P_MIN}; got m={params.m}, t={params.t}, p={params.p}",
        )


def _assert_passphrase_salt(salt: bytes) -> None:
    if len(salt) < PASSPHRASE_SALT_MIN_BYTES:
        raise EciesSealedPoeError(
            EciesSealedPoeError.ENC_PASSPHRASE_SALT_TOO_SHORT,
            f"salt MUST be at least {PASSPHRASE_SALT_MIN_BYTES} bytes, got {len(salt)}",
        )
    if len(salt) > PASSPHRASE_SALT_MAX_BYTES:
        raise EciesSealedPoeError(
            EciesSealedPoeError.ENC_PASSPHRASE_SALT_TOO_LONG,
            f"salt MUST be at most {PASSPHRASE_SALT_MAX_BYTES} bytes, got {len(salt)}",
        )


# PASSPHRASE_TRANSCRIPT is a closed six-key map (with `passphrase` itself a
# closed sub-map) binding the KDF parameters, the header fields, and the item's
# hash claim into the in-ciphertext commitment. The `normalization` value is a
# scheme-fixed constant pinning the profile the CEK was derived under; it is
# never serialised on the wire.
def _passphrase_transcript(
    nonce: bytes, salt: bytes, params: Argon2idParams, hashes_hash: bytes
) -> bytes:
    transcript: dict[str | int, CanonicalCborValue] = {
        "scheme": 1,
        "path": "passphrase",
        "aead": AEAD_CHACHA20_POLY1305_STREAM64K,
        "nonce": nonce,
        "hashes_hash": hashes_hash,
        "passphrase": {
            "alg": PASSPHRASE_KDF_ARGON2ID,
            "salt": salt,
            "params": {"m": params.m, "t": params.t, "p": params.p},
            "normalization": CARDANO_POE_PW_NORM_PROFILE,
        },
    }
    return encode_canonical_cbor(transcript)


def _compute_pw_hash(
    nonce: bytes, salt: bytes, params: Argon2idParams, hashes_hash: bytes
) -> bytes:
    return hashlib.sha256(
        CARDANO_POE_HASH_PREFIX_PASSPHRASE_TRANSCRIPT
        + _passphrase_transcript(nonce, salt, params, hashes_hash)
    ).digest()


def _passphrase_commitment(cek: bytes, pw_hash: bytes) -> bytes:
    mac_key = hkdf_sha256(
        ikm=cek,
        salt=_EMPTY_SALT,
        info=CARDANO_POE_HKDF_INFO_PASSPHRASE_MAC,
        length=32,
    )
    commitment = stdlib_hmac.new(mac_key, pw_hash, hashlib.sha256).digest()
    if len(commitment) != _COMMITMENT_LENGTH:
        raise RuntimeError(
            f"internal: commitment length={len(commitment)}, expected {_COMMITMENT_LENGTH}"
        )
    return commitment


# Normalize a caller passphrase under cardano-poe-pw-norm-v1, mapping the
# normalizer's typed failures onto the construction error type. Kept separate
# from the Argon2id step so the open path can raise these caller-input errors
# before any blob-dependent work.
def _normalize_passphrase_input(passphrase: str) -> bytes:
    try:
        return normalize_passphrase(passphrase)
    except PassphraseNormalizationError as cause:
        raise EciesSealedPoeError(cause.code, str(cause)) from cause


# CEK = argon2id(password, salt, params, 32) with the Argon2 version pinned at
# 0x13; `password` is the already-normalized passphrase byte string.
def _argon2id_cek(password: bytes, salt: bytes, params: Argon2idParams) -> bytes:
    try:
        return argon2id_v13(password, salt, params.m, params.t, params.p, _CEK_LENGTH)
    except Exception as cause:
        raise EciesSealedPoeError(
            EciesSealedPoeError.KDF_DERIVATION_FAILED,
            f"argon2id derivation failed: {cause}",
        ) from cause


def passphrase_sealed_poe_seal(
    *,
    plaintext: bytes,
    passphrase: str,
    # The item's complete hashes map; its labelled digest is bound into the
    # passphrase transcript exactly as on the slots path.
    hashes: Mapping[str, bytes],
    # Argon2id work factors. The default is the registry floor profile with the
    # recommended parallelism (m = 65536 KiB, t = 3, p = 4).
    params: Argon2idParams | None = None,
    # Test-only deterministic overrides — production callers MUST NOT pass
    # these; the salt MUST be freshly drawn per envelope (it is the sole
    # cross-record separator for a reused passphrase).
    salt: bytes | None = None,
    nonce: bytes | None = None,
) -> PassphraseSealedPoeOutput:
    params = params if params is not None else Argon2idParams(m=65536, t=3, p=4)
    _assert_argon2id_params(params)
    salt = salt if salt is not None else secrets.token_bytes(32)
    _assert_passphrase_salt(salt)
    nonce = nonce if nonce is not None else secrets.token_bytes(_NONCE_LENGTH)
    if len(nonce) != _NONCE_LENGTH:
        raise EciesSealedPoeError(
            EciesSealedPoeError.NONCE_LENGTH_MISMATCH,
            f"nonce MUST be exactly {_NONCE_LENGTH} bytes, got {len(nonce)}",
        )

    hashes_hash = item_hashes_hash(hashes)
    cek = _argon2id_cek(_normalize_passphrase_input(passphrase), salt, params)
    commitment = _passphrase_commitment(cek, _compute_pw_hash(nonce, salt, params, hashes_hash))
    payload_key = _passphrase_payload_key(cek, nonce)
    blob = commitment + stream_seal(payload_key, plaintext)

    envelope = PassphraseEnvelope(
        scheme=1,
        aead=AEAD_CHACHA20_POLY1305_STREAM64K,
        nonce=nonce,
        alg=PASSPHRASE_KDF_ARGON2ID,
        salt=salt,
        params=params,
    )
    return PassphraseSealedPoeOutput(envelope=envelope, ciphertext=blob)


def passphrase_sealed_poe_open(
    *,
    envelope: PassphraseEnvelope,
    ciphertext: bytes,
    passphrase: str,
    hashes: Mapping[str, bytes],
) -> UnwrapResult:
    # Typed caller-input rejections fire in a pinned order — the item's hash
    # claim, then passphrase normalization, then the envelope shape — and every
    # one of them strictly precedes any blob-dependent generic failure, so a
    # malformed call is reported the same way whatever blob accompanies it.
    hashes_hash = item_hashes_hash(hashes)
    password = _normalize_passphrase_input(passphrase)

    if envelope.scheme != 1:
        raise EciesSealedPoeError(
            EciesSealedPoeError.UNSUPPORTED_ENVELOPE_SCHEME,
            f"envelope.scheme={envelope.scheme} unsupported (expected 1)",
        )
    if envelope.aead != AEAD_CHACHA20_POLY1305_STREAM64K:
        raise EciesSealedPoeError(
            EciesSealedPoeError.UNSUPPORTED_AEAD_ALG,
            f"envelope.aead={envelope.aead!r} unsupported "
            f"(expected {AEAD_CHACHA20_POLY1305_STREAM64K!r})",
        )
    if envelope.alg != PASSPHRASE_KDF_ARGON2ID:
        raise EciesSealedPoeError(
            EciesSealedPoeError.ENC_PASSPHRASE_ALG_UNSUPPORTED,
            f"envelope.alg={envelope.alg!r} unsupported (expected 'argon2id')",
        )
    if len(envelope.nonce) != _NONCE_LENGTH:
        raise EciesSealedPoeError(
            EciesSealedPoeError.NONCE_LENGTH_MISMATCH,
            f"envelope.nonce MUST be exactly {_NONCE_LENGTH} bytes, got {len(envelope.nonce)}",
        )
    _assert_passphrase_salt(envelope.salt)
    _assert_argon2id_params(envelope.params)

    # A passphrase-path blob shorter than 48 bytes — the 32-byte commitment
    # header plus the 16-byte STREAM floor — cannot be well-formed; rejecting
    # it before the KDF spends no Argon2 work on it (the blob is public input,
    # so the early return reveals nothing). Like every other decryption failure
    # on this path it surfaces as the single generic failure; wrong passphrase,
    # tampered parameters, and tampered ciphertext are indistinguishable by
    # design.
    if len(ciphertext) < _COMMITMENT_LENGTH + TAG_SIZE:
        return UnwrapResult(matched=False, plaintext=None, reason=UNWRAP_REASON_TAMPERED_CIPHERTEXT)

    cek = _argon2id_cek(password, envelope.salt, envelope.params)

    # The commitment is verified in constant time BEFORE any STREAM chunk is
    # opened: the wrong-passphrase signal is the commitment, never a Poly1305
    # tag deep in the stream.
    expected = _passphrase_commitment(
        cek, _compute_pw_hash(envelope.nonce, envelope.salt, envelope.params, hashes_hash)
    )
    if not compare_ct(expected, ciphertext[:_COMMITMENT_LENGTH]):
        return UnwrapResult(matched=False, plaintext=None, reason=UNWRAP_REASON_TAMPERED_CIPHERTEXT)

    payload_key = _passphrase_payload_key(cek, envelope.nonce)
    try:
        plaintext = stream_open(payload_key, ciphertext[_COMMITMENT_LENGTH:])
    except StreamTamperedError:
        return UnwrapResult(matched=False, plaintext=None, reason=UNWRAP_REASON_TAMPERED_CIPHERTEXT)
    return UnwrapResult(matched=True, plaintext=plaintext, reason=None)
