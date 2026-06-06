"""Regression (parity twin of crypto-core unwrap.low-order-epk.regression.test.ts):

A structurally valid sealed envelope carrying a small-order (low-order)
Montgomery ``epk`` in one of its slots must NOT crash trial-decrypt.

Bug: the per-slot X25519 ECDH ran OUTSIDE the AEAD try/except. PyCA
``cryptography`` rejects a small-order peer public key (the shared secret is
all-zero, RFC 7748 §6.1 contributory check) by raising ``ValueError``, which
escaped ``ecies_sealed_poe_unwrap`` / ``ecies_sealed_poe_trial_decrypt`` — an
attacker-supplied on-chain envelope could turn an inbox scan into an uncaught
exception. A wrong-LENGTH epk is blocked upstream by the structure check, so the
low-order point is the only runtime-reachable raise inside the loop.

Fix: a low-order epk slot is a non-match (no conformant wrap for this recipient
could have produced it) and is skipped exactly like an AEAD-tag failure.
"""

from __future__ import annotations

import pytest

from cardanowall._crypto.kem import X25519LowOrderPointError, x25519_ecdh, x25519_public_key
from cardanowall._crypto.sealed_poe import (
    TRIAL_DECRYPT_KIND_NO_AEAD_PASS,
    SealedEnvelope,
    SealedSlot,
    ecies_sealed_poe_trial_decrypt,
    ecies_sealed_poe_unwrap,
    ecies_sealed_poe_wrap,
)

# Canonical small-order Curve25519 u-coordinates (RFC 7748 §6.1 + an order-8
# point). Each makes the X25519 shared secret all-zero, so a conformant KEM
# rejects them.
LOW_ORDER_EPKS: dict[str, bytes] = {
    "all-zero u (order 1)": bytes(32),
    "u=1 (order 1)": bytes([1]) + bytes(31),
    "canonical order-8 point": bytes.fromhex(
        "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800"
    ),
    "p-1 (order 2)": bytes.fromhex(
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"
    ),
}


def _det_priv(seed: int) -> bytes:
    return bytes([(seed + j) & 0xFF for j in range(32)])


# A second, distinct low-order u-coordinate (RFC 7748 §6.1, p+1 reduces to 0).
# Used to clobber a sibling slot with a low-order point that is NOT byte-equal to
# the one under test, so the envelope still violates no per-slot KEK-uniqueness
# rule while every slot's shared secret is all-zero.
_SECOND_LOW_ORDER_EPK: bytes = bytes.fromhex(
    "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"
)


def _all_low_order_envelope(low_order_epk: bytes) -> tuple[SealedEnvelope, bytes]:
    recipient_public_keys = [
        x25519_public_key(_det_priv(0x11)),
        x25519_public_key(_det_priv(0x55)),
    ]
    out = ecies_sealed_poe_wrap(
        plaintext=b"all-low-order",
        recipient_public_keys=recipient_public_keys,
        skip_shuffle=True,
    )
    # Clobber both slots with low-order points so every slot's shared secret is
    # all-zero, but give each a DISTINCT epk: an envelope with duplicate per-slot
    # KEM material is rejected up front (per-slot KEK uniqueness), which is a
    # different defence than the all-zero shared-secret skip this test exercises.
    second = (
        _SECOND_LOW_ORDER_EPK
        if low_order_epk != _SECOND_LOW_ORDER_EPK
        else bytes(32)  # the all-zero point, still low-order and distinct
    )
    clobbered = (low_order_epk, second)
    slots = tuple(
        SealedSlot(epk=clobbered[i], wrap=s.wrap) for i, s in enumerate(out.envelope.slots)
    )
    env = SealedEnvelope(
        scheme=out.envelope.scheme,
        aead=out.envelope.aead,
        kem=out.envelope.kem,
        nonce=out.envelope.nonce,
        slots=slots,
        slots_mac=out.envelope.slots_mac,
    )
    return env, out.ciphertext


def _envelope_with_low_order_slot(low_order_epk: bytes) -> tuple[SealedEnvelope, bytes, bytes]:
    recipient_priv = _det_priv(0x20)
    other_priv = _det_priv(0x60)
    out = ecies_sealed_poe_wrap(
        plaintext=b"low-order-epk-regression",
        recipient_public_keys=[
            x25519_public_key(recipient_priv),
            x25519_public_key(other_priv),
        ],
        skip_shuffle=True,
    )
    # Clobber slot 1's epk with the low-order point. Slot 0 is still a real wrap
    # for recipient_priv (so a CEK is recovered), but slots_mac no longer matches
    # the clobbered slot set, so the verdict is TAMPERED_HEADER — the point is we
    # get a structured verdict, not an exception.
    slots = tuple(
        SealedSlot(epk=low_order_epk, wrap=s.wrap) if i == 1 else s
        for i, s in enumerate(out.envelope.slots)
    )
    env = SealedEnvelope(
        scheme=out.envelope.scheme,
        aead=out.envelope.aead,
        kem=out.envelope.kem,
        nonce=out.envelope.nonce,
        slots=slots,
        slots_mac=out.envelope.slots_mac,
    )
    return env, out.ciphertext, recipient_priv


@pytest.mark.parametrize("name", list(LOW_ORDER_EPKS))
def test_x25519_ecdh_raises_typed_low_order_error(name: str) -> None:
    with pytest.raises(X25519LowOrderPointError):
        x25519_ecdh(_det_priv(0x40), LOW_ORDER_EPKS[name])


@pytest.mark.parametrize("name", list(LOW_ORDER_EPKS))
def test_unwrap_single_priv_no_throw_no_match(name: str) -> None:
    env, ciphertext = _all_low_order_envelope(LOW_ORDER_EPKS[name])
    res = ecies_sealed_poe_unwrap(
        envelope=env,
        ciphertext=ciphertext,
        recipient_secret_key=_det_priv(0x99),
    )
    assert res.matched is False


@pytest.mark.parametrize("name", list(LOW_ORDER_EPKS))
def test_unwrap_multi_priv_no_throw_no_match(name: str) -> None:
    env, ciphertext = _all_low_order_envelope(LOW_ORDER_EPKS[name])
    res = ecies_sealed_poe_unwrap(
        envelope=env,
        ciphertext=ciphertext,
        recipient_secret_keys=[_det_priv(0x99), _det_priv(0xCD)],
    )
    assert res.matched is False


@pytest.mark.parametrize("name", list(LOW_ORDER_EPKS))
def test_trial_decrypt_no_throw_reports_no_aead_pass(name: str) -> None:
    env, _ = _all_low_order_envelope(LOW_ORDER_EPKS[name])
    res = ecies_sealed_poe_trial_decrypt(
        envelope=env,
        recipient_secret_keys=[_det_priv(0x99)],
    )
    assert res.kind == TRIAL_DECRYPT_KIND_NO_AEAD_PASS


@pytest.mark.parametrize("name", list(LOW_ORDER_EPKS))
def test_legit_slot_opens_with_low_order_sibling(name: str) -> None:
    env, ciphertext, matching_priv = _envelope_with_low_order_slot(LOW_ORDER_EPKS[name])
    # Must not raise; slot 0 opens but the clobbered slot set fails slots_mac.
    res = ecies_sealed_poe_unwrap(
        envelope=env,
        ciphertext=ciphertext,
        recipient_secret_key=matching_priv,
    )
    assert res.matched is False
    assert res.reason == "TAMPERED_HEADER"


@pytest.mark.parametrize("name", list(LOW_ORDER_EPKS))
def test_constant_time_n_enters_all_slots_with_trailing_low_order(name: str) -> None:
    env, ciphertext, matching_priv = _envelope_with_low_order_slot(LOW_ORDER_EPKS[name])
    slots_attempted: list[int] = []
    res = ecies_sealed_poe_unwrap(
        envelope=env,
        ciphertext=ciphertext,
        recipient_secret_key=matching_priv,
        _slots_attempted_out=slots_attempted,
    )
    # No raise, and the constant-time-N loop entered every slot.
    assert res.matched is False
    assert slots_attempted and slots_attempted[0] == len(env.slots)
