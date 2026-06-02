"""Smoke test for the public ``cardanowall.hash`` namespace.

Asserts the re-exports resolve and emit the canonical SHA-256 / Blake2b-256
digests for the empty input — both are widely-quoted reference values, so a
regression in the re-export wiring (wrong module, wrong digest size) shows
up immediately.
"""

from __future__ import annotations

from cardanowall.hash import blake2b_256, dual_hash, sha2_256

SHA256_EMPTY_HEX = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
# Blake2b-256(empty); reference vector from RFC 7693 §A and the noble-hashes
# test corpus.
BLAKE2B256_EMPTY_HEX = "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8"


def test_sha2_256_of_empty_input_matches_canonical_digest() -> None:
    assert sha2_256(b"").hex() == SHA256_EMPTY_HEX


def test_blake2b_256_of_empty_input_matches_canonical_digest() -> None:
    assert blake2b_256(b"").hex() == BLAKE2B256_EMPTY_HEX


def test_dual_hash_returns_both_digests_for_same_input() -> None:
    both = dual_hash(b"")
    assert both["sha256"].hex() == SHA256_EMPTY_HEX
    assert both["blake2b256"].hex() == BLAKE2B256_EMPTY_HEX
