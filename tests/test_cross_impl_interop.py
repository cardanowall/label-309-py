"""Python sibling for the cross-impl interop guard.

Mirrors the cross-impl interop guard in @cardanowall/crypto-core.
This SDK does NOT ship an envelope-plaintext validator (envelope build/unlock
lives in the TypeScript stack only); the Python parity test exercises the same
simulation via a test-local v=1-only validator stub against a hand-constructed
v=2 plaintext object — the same "third-party CIP-309 implementer" interop
contract the TypeScript sibling pins.
"""

from __future__ import annotations

from typing import Any

import pytest

PASSPHRASE_RECIPIENT_LABEL = "recovery passphrase"  # noqa: S105 (label constant, not a credential)
ENVELOPE_PLAINTEXT_VERSION_V1 = 1


class EnvelopeUnlockError(Exception):
    """Local mirror of the TS EnvelopeUnlockError contract for the test."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code: str = code


def validate_plaintext_shape_v1_only(decoded: Any) -> dict[str, Any]:
    """Mirror of `validatePlaintextShape_v1Only` from the TS sibling.

    Hand-written stub of a v=1-only acceptance branch. NOT exported into
    the SDK; NOT a production reduced-acceptance feature flag. The stub
    raises EnvelopeUnlockError with the production-registry code
    `UNSUPPORTED_ENVELOPE_VERSION` on any ``v != 1``.
    """
    if not isinstance(decoded, dict):
        raise EnvelopeUnlockError("INVALID_PLAINTEXT_SHAPE", "envelope plaintext must be dict")
    v = decoded.get("v")
    if v != ENVELOPE_PLAINTEXT_VERSION_V1:
        raise EnvelopeUnlockError(
            "UNSUPPORTED_ENVELOPE_VERSION",
            f"v=1-only consumer rejects envelope plaintext .v={v!r}",
        )
    seed = decoded.get("seed")
    created_at = decoded.get("created_at")
    label = decoded.get("label")
    if not isinstance(seed, bytes) or not isinstance(created_at, str) or not isinstance(label, str):
        raise EnvelopeUnlockError("INVALID_PLAINTEXT_SHAPE", "malformed v=1 plaintext")
    return {"v": 1, "seed": seed, "created_at": created_at, "label": label}


def test_v1_only_consumer_rejects_v2_plaintext() -> None:
    decoded = {
        "v": 2,
        "seed": b"\x42" * 32,
        "previous_seeds": [b"\xa0" * 32, b"\xa1" * 32],
        "created_at": "2026-04-17T12:00:00.000Z",
        "label": PASSPHRASE_RECIPIENT_LABEL,
    }
    with pytest.raises(EnvelopeUnlockError) as exc:
        validate_plaintext_shape_v1_only(decoded)
    assert exc.value.code == "UNSUPPORTED_ENVELOPE_VERSION"


def test_v1_only_consumer_accepts_v1_plaintext() -> None:
    decoded = {
        "v": 1,
        "seed": b"\x42" * 32,
        "created_at": "2026-04-17T12:00:00.000Z",
        "label": PASSPHRASE_RECIPIENT_LABEL,
    }
    result = validate_plaintext_shape_v1_only(decoded)
    assert result["v"] == 1
    assert result["seed"] == b"\x42" * 32


def test_v1_only_consumer_rejects_v3_plaintext() -> None:
    """Defence-in-depth: stub rejects any `v != 1`, not just `v == 2`."""
    decoded = {
        "v": 3,
        "seed": b"\x00" * 32,
        "created_at": "2026-04-17T12:00:00.000Z",
        "label": PASSPHRASE_RECIPIENT_LABEL,
    }
    with pytest.raises(EnvelopeUnlockError) as exc:
        validate_plaintext_shape_v1_only(decoded)
    assert exc.value.code == "UNSUPPORTED_ENVELOPE_VERSION"
