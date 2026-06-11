"""Verifier-side resource bounds enforced before any KEM/AEAD primitive runs:
the slot-count cap (MAX_SLOTS) and the decoded-envelope byte backstop
(MAX_DECODED_ENVELOPE_BYTES). Both bound a public parser's work on a malformed
envelope; neither is a wire field. Each is pinned as a constant, asserted to
reject above the bound, and asserted to accept just below — without building a
giant envelope where a smaller one proves the boundary.
"""

from __future__ import annotations

import pytest

from cardanowall._crypto.sealed_poe import (
    MAX_DECODED_ENVELOPE_BYTES,
    MAX_SLOTS,
    EciesSealedPoeError,
    SealedEnvelope,
    SealedSlot,
    UnwrapResult,
    ecies_sealed_poe_unwrap,
)

_NONCE_LENGTH = 24
_SLOTS_MAC_LENGTH = 32
_EPK_LENGTH = 32
_WRAP_LENGTH = 48
_PER_SLOT_X25519 = _EPK_LENGTH + _WRAP_LENGTH  # 80


def _distinct_slots(count: int) -> tuple[SealedSlot, ...]:
    # A distinct, well-formed epk per slot (the duplicate-KEM-material gate forbids
    # repeats). The bytes need not be valid points: the resource-bound checks run
    # before any KEM primitive, so a structurally-shaped envelope suffices.
    slots: list[SealedSlot] = []
    for i in range(count):
        epk = bytearray(_EPK_LENGTH)
        epk[0] = i & 0xFF
        epk[1] = (i >> 8) & 0xFF
        slots.append(SealedSlot(epk=bytes(epk), wrap=bytes(_WRAP_LENGTH)))
    return tuple(slots)


def _envelope(slots: tuple[SealedSlot, ...]) -> SealedEnvelope:
    return SealedEnvelope(
        scheme=1,
        aead="chacha20-poly1305-stream64k",
        kem="x25519",
        nonce=bytes(_NONCE_LENGTH),
        slots=slots,
        slots_mac=bytes(_SLOTS_MAC_LENGTH),
    )


def _unwrap(slots: tuple[SealedSlot, ...]) -> UnwrapResult:
    return ecies_sealed_poe_unwrap(
        envelope=_envelope(slots),
        ciphertext=bytes(16),
        hashes={"sha2-256": bytes(32)},
        recipient_secret_key=bytes([0x11]) * 32,
    )


def test_bound_constants_are_pinned() -> None:
    assert MAX_SLOTS == 1024
    assert MAX_DECODED_ENVELOPE_BYTES == 65536


def test_rejects_more_than_max_slots() -> None:
    # MAX_SLOTS + 1 slots trips the slot-count cap (checked before the byte cap).
    with pytest.raises(EciesSealedPoeError) as exc:
        _unwrap(_distinct_slots(MAX_SLOTS + 1))
    assert exc.value.code == EciesSealedPoeError.ENC_SLOTS_TOO_MANY


def test_rejects_decoded_envelope_over_byte_backstop() -> None:
    # The smallest slot count whose decoded size exceeds the byte backstop but is
    # at or below MAX_SLOTS, so the byte backstop (not the slot cap) is the
    # tripping check. floor((65536 - 56) / 80) = 818 fit; 819 exceed it.
    fit = (MAX_DECODED_ENVELOPE_BYTES - _NONCE_LENGTH - _SLOTS_MAC_LENGTH) // _PER_SLOT_X25519
    over = fit + 1
    assert over <= MAX_SLOTS
    with pytest.raises(EciesSealedPoeError) as exc:
        _unwrap(_distinct_slots(over))
    assert exc.value.code == EciesSealedPoeError.ENC_ENVELOPE_TOO_LARGE


def test_accepts_envelope_just_below_the_byte_backstop() -> None:
    # One slot fewer than the byte-bound trip: the resource checks pass, so the
    # unwrap proceeds to the trial-decrypt loop and returns a structured
    # non-match (the slots are not real wraps) rather than a resource error.
    just_under = (
        MAX_DECODED_ENVELOPE_BYTES - _NONCE_LENGTH - _SLOTS_MAC_LENGTH
    ) // _PER_SLOT_X25519
    result = _unwrap(_distinct_slots(just_under))
    assert result.matched is False
