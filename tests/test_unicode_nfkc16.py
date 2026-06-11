from __future__ import annotations

import json
from pathlib import Path

import pytest

from cardanowall._crypto.unicode_nfkc16 import (
    Nfkc16Error,
    is_assigned16,
    is_white_space16,
    nfkc16,
)

ORACLE_PATH = Path(__file__).parent / "fixtures" / "unicode" / "nfkc-16.0.json"


def _string_from_hex(seq: str) -> str:
    return "".join(chr(int(token, 16)) for token in seq.split(" "))


def _load_pairs() -> list[tuple[str, str, str, list[str]]]:
    """Return (source_hex, source, expected, parts) for every oracle pair."""
    corpus = json.loads(ORACLE_PATH.read_text())
    assert isinstance(corpus, dict)
    assert corpus["ucd_version"] == "16.0.0"
    raw_pairs = corpus["pairs"]
    assert isinstance(raw_pairs, list)
    pairs: list[tuple[str, str, str, list[str]]] = []
    for line in raw_pairs:
        assert isinstance(line, str)
        mapping, _, parts = line.partition("|")
        source_hex, _, expected_hex = mapping.partition(";")
        pairs.append(
            (
                source_hex,
                _string_from_hex(source_hex),
                _string_from_hex(expected_hex),
                parts.split(" "),
            )
        )
    return pairs


def _load_samples(key: str) -> list[int]:
    corpus = json.loads(ORACLE_PATH.read_text())
    assert isinstance(corpus, dict)
    samples = corpus[key]
    assert isinstance(samples, list)
    out: list[int] = []
    for token in samples:
        assert isinstance(token, str)
        out.append(int(token, 16))
    return out


PAIRS = _load_pairs()
SAMPLE_ASSIGNED = _load_samples("sample_assigned")
SAMPLE_UNASSIGNED = _load_samples("sample_unassigned")


def test_oracle_carries_the_full_corpus() -> None:
    assert len(PAIRS) > 30000
    assert len(SAMPLE_ASSIGNED) >= 40
    assert len(SAMPLE_UNASSIGNED) >= 40


def test_replays_every_oracle_pair_byte_exactly() -> None:
    failures: list[str] = []
    for source_hex, source, expected, _parts in PAIRS:
        actual = nfkc16(source)
        if actual != expected:
            failures.append(f"{source_hex} -> {actual!r} (expected {expected!r})")
            if len(failures) >= 20:
                break
    assert failures == []


def test_unlisted_assigned_code_points_are_nfkc_stable() -> None:
    # NormalizationTest guarantees X == NFKC(X) for every code point that never
    # appears as column 1 of Part 1; replay that invariant over every 17th
    # assigned code point.
    part1_singles = {
        ord(source) for _hex, source, _expected, parts in PAIRS if len(source) == 1 and "1" in parts
    }
    assert len(part1_singles) > 5000

    failures: list[str] = []
    assigned_seen = 0
    checked = 0
    for cp in range(0x110000):
        if not is_assigned16(cp):
            continue
        assigned_seen += 1
        if assigned_seen % 17 != 0:
            continue
        if 0xD800 <= cp <= 0xDFFF or cp in part1_singles:
            continue
        source = chr(cp)
        checked += 1
        if nfkc16(source) != source:
            failures.append(f"{cp:04X}")
            if len(failures) >= 20:
                break
    assert failures == []
    assert checked > 10000


def test_rejects_every_sampled_unassigned_code_point() -> None:
    for cp in SAMPLE_UNASSIGNED:
        assert is_assigned16(cp) is False
        for text in (chr(cp), f"a{chr(cp)}b"):
            with pytest.raises(Nfkc16Error) as excinfo:
                nfkc16(text)
            assert excinfo.value.code == Nfkc16Error.UNASSIGNED_CODEPOINT
            assert excinfo.value.code_point == cp


def test_accepts_every_sampled_assigned_code_point() -> None:
    for cp in SAMPLE_ASSIGNED:
        assert is_assigned16(cp) is True
        nfkc16(chr(cp))


def test_is_assigned16_is_total_and_false_outside_code_point_space() -> None:
    assert is_assigned16(-1) is False
    assert is_assigned16(0x110000) is False


def test_rejects_surrogate_code_points() -> None:
    # Python strings carry lone surrogates as single code points; an escaped
    # "\ud83d\ude00" stays two surrogates rather than pairing into U+1F600.
    # Every surrogate is rejected as malformed scalar input.
    for text in ("\ud800", "\udc00", "a\ud800z", "a\ud800", "\ud83d\ude00"):
        with pytest.raises(Nfkc16Error) as excinfo:
            nfkc16(text)
        assert excinfo.value.code == Nfkc16Error.UNPAIRED_SURROGATE


def test_accepts_assigned_astral_code_points() -> None:
    assert nfkc16("😀") == "\U0001f600"


def test_empty_string_is_identity() -> None:
    assert nfkc16("") == ""


def test_white_space_property_is_pinned() -> None:
    for cp in (0x09, 0x0D, 0x20, 0x85, 0xA0, 0x1680, 0x2000, 0x200A, 0x2028, 0x3000):
        assert is_white_space16(cp) is True
    # U+200B ZERO WIDTH SPACE and U+FEFF are not White_Space; str.isspace()
    # disagrees about U+001C..1F, which is exactly why the property is pinned.
    for cp in (0x08, 0x0E, 0x1C, 0x21, 0x200B, 0xFEFF, 0x3001):
        assert is_white_space16(cp) is False
