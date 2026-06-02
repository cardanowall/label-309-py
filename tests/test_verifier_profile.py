"""Unit tests for detect_conformance_profile."""

from __future__ import annotations

from cardanowall.verifier.profile import detect_conformance_profile


def _base_record() -> dict[str, object]:
    return {
        "v": 1,
        "chain": "cardano:mainnet",
        "iat": "2026-01-01T00:00:00.000Z",
        "items": [{"item_idx": 0, "hashes": {"sha2-256": b"\x00" * 32}}],
    }


def test_core_for_hash_only_record() -> None:
    assert detect_conformance_profile(_base_record()) == "core"  # type: ignore[arg-type]


def test_signed_when_sigs_nonempty_and_no_enc() -> None:
    rec = _base_record()
    rec["sigs"] = [{"cose_sign1": b"\x00" * 64}]
    assert detect_conformance_profile(rec) == "signed"  # type: ignore[arg-type]


def test_core_when_sigs_empty() -> None:
    rec = _base_record()
    rec["sigs"] = []
    assert detect_conformance_profile(rec) == "core"  # type: ignore[arg-type]


def test_sealed_when_any_item_has_enc() -> None:
    rec = _base_record()
    rec["items"] = [{"item_idx": 0, "hashes": {"sha2-256": b"\x00" * 32}, "enc": {"scheme": 1}}]
    assert detect_conformance_profile(rec) == "sealed"  # type: ignore[arg-type]


def test_sealed_wins_over_signed_when_both_present() -> None:
    rec = _base_record()
    rec["items"] = [{"item_idx": 0, "hashes": {"sha2-256": b"\x00" * 32}, "enc": {"scheme": 1}}]
    rec["sigs"] = [{"cose_sign1": b"\x00" * 64}]
    assert detect_conformance_profile(rec) == "sealed"  # type: ignore[arg-type]


def test_sealed_when_only_one_of_multiple_items_carries_enc() -> None:
    rec = _base_record()
    rec["items"] = [
        {"item_idx": 0, "hashes": {"sha2-256": b"\x00" * 32}},
        {"item_idx": 1, "hashes": {"sha2-256": b"\x00" * 32}, "enc": {"scheme": 1}},
    ]
    assert detect_conformance_profile(rec) == "sealed"  # type: ignore[arg-type]
