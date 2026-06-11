"""Python sibling for inbox readability across rotation.

This SDK does NOT ship envelope build/unlock (that lives in the TypeScript
stack only). The Python parity test exercises the underlying sealed-poe +
seed-derive primitives: derive multi-seed X25519 privs, wrap a sealed-PoE
record to the oldest seed's pub as one of many recipients, then unwrap via the
multi-priv iterator with the documented newest-first ordering and assert the
original plaintext + structural counters match the @cardanowall/crypto-core
sibling test.
"""

from __future__ import annotations

import hashlib

from cardanowall._crypto.sealed_poe import (
    UNWRAP_REASON_WRONG_RECIPIENT_KEY,
    ecies_sealed_poe_unwrap,
    ecies_sealed_poe_wrap,
)
from cardanowall._crypto.seed_derive import derive_x25519_keypair_from_seed

# Pinned byte-deterministic seeds (mirror the TS sibling).
S0 = b"\xa0" * 32
S1 = b"\xa1" * 32
S2 = b"\xa2" * 32
S3 = b"\xa3" * 32

EXPECTED_PLAINTEXT = b"R_0 plaintext fixture"


def test_inbox_readability_across_three_rotations() -> None:
    x0 = derive_x25519_keypair_from_seed(S0)
    x1 = derive_x25519_keypair_from_seed(S1)
    x2 = derive_x25519_keypair_from_seed(S2)
    x3 = derive_x25519_keypair_from_seed(S3)

    # Wrap R_0 to pub(s_0) plus two unrelated padding pubs.
    pad1 = derive_x25519_keypair_from_seed(b"\xd1" * 32)
    pad2 = derive_x25519_keypair_from_seed(b"\xd2" * 32)
    hashes = {"sha2-256": hashlib.sha256(EXPECTED_PLAINTEXT).digest()}
    out = ecies_sealed_poe_wrap(
        plaintext=EXPECTED_PLAINTEXT,
        hashes=hashes,
        recipient_public_keys=[x0["public_key"], pad1["public_key"], pad2["public_key"]],
    )

    # Store-shaped (current first, archived oldest-first) priv array.
    store_shaped: list[bytes] = [
        x3["secret_key"],
        x0["secret_key"],
        x1["secret_key"],
        x2["secret_key"],
    ]
    # Newest-first ordering: current first, archive reversed.
    ordered: list[bytes] = [store_shaped[0], *reversed(store_shaped[1:])]
    assert ordered[0] == x3["secret_key"]
    assert ordered[1] == x2["secret_key"]
    assert ordered[2] == x1["secret_key"]
    assert ordered[3] == x0["secret_key"]

    slots_attempted: list[int] = []
    privs_attempted: list[int] = []
    result = ecies_sealed_poe_unwrap(
        envelope=out.envelope,
        ciphertext=out.ciphertext,
        hashes=hashes,
        recipient_secret_keys=ordered,
        _slots_attempted_out=slots_attempted,
        _privs_attempted_out=privs_attempted,
    )

    assert result.matched is True
    assert result.plaintext == EXPECTED_PLAINTEXT
    # The match is the oldest archived priv (priv(s_0)) at index 3 after
    # newest-first reversal; iterator exhausts all 4 outer iterations.
    assert privs_attempted[0] == 4
    # Per-priv constant-time-N: every priv enters the full slot loop (N=3).
    assert slots_attempted == [3, 3, 3, 3]


def test_inbox_readability_no_match_after_rotation_returns_wrong_recipient_key() -> None:
    """Sanity guard: if the user's seed family is entirely disjoint from the
    record's slot set, the multi-priv unwrap correctly reports
    WRONG_RECIPIENT_KEY without leaking match position."""
    x_user_a = derive_x25519_keypair_from_seed(b"\xb0" * 32)
    x_user_b = derive_x25519_keypair_from_seed(b"\xb1" * 32)
    pad1 = derive_x25519_keypair_from_seed(b"\xd1" * 32)
    pad2 = derive_x25519_keypair_from_seed(b"\xd2" * 32)
    pad3 = derive_x25519_keypair_from_seed(b"\xd3" * 32)
    hashes = {"sha2-256": hashlib.sha256(EXPECTED_PLAINTEXT).digest()}
    out = ecies_sealed_poe_wrap(
        plaintext=EXPECTED_PLAINTEXT,
        hashes=hashes,
        recipient_public_keys=[pad1["public_key"], pad2["public_key"], pad3["public_key"]],
    )
    ordered = [x_user_a["secret_key"], x_user_b["secret_key"]]
    slots_attempted: list[int] = []
    privs_attempted: list[int] = []
    result = ecies_sealed_poe_unwrap(
        envelope=out.envelope,
        ciphertext=out.ciphertext,
        hashes=hashes,
        recipient_secret_keys=ordered,
        _slots_attempted_out=slots_attempted,
        _privs_attempted_out=privs_attempted,
    )
    assert result.matched is False
    assert result.reason == UNWRAP_REASON_WRONG_RECIPIENT_KEY
    assert privs_attempted[0] == 2
    assert slots_attempted == [3, 3]
