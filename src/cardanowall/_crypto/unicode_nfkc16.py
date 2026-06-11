"""Pinned Unicode 16.0.0 NFKC normalization.

Keys derived from passphrases must come out identical in every conformant
implementation, today and years from now, so this module never delegates to
the standard library's ``unicodedata`` — its tables float with the
interpreter's Unicode version, and two runtimes on different versions can
derive different keys from the same passphrase. The tables here are generated
from the Unicode 16.0.0 UCD and pinned. Code points that Unicode 16.0 leaves
unassigned are rejected outright: the Unicode stability policy only guarantees
normalization stability for code points that are assigned in the pinned
version, so passing unassigned input through would re-open the drift.

Algorithm (UAX #15, no quick-check fast path): validate scalar values and the
assigned-at-16.0 guard, fully decompose through the flat NFKD table (recursion
was resolved at table-generation time; Hangul is algorithmic), canonically
reorder by combining class, then canonically compose (pair table with
composition exclusions applied, plus algorithmic Hangul).
"""

from __future__ import annotations

from bisect import bisect_right

from .unicode_nfkc16_data import (
    NFKC16_ASSIGNED_RANGES_PACKED,
    NFKC16_CCC_PACKED,
    NFKC16_COMPOSITION_PACKED,
    NFKC16_DECOMPOSITION_PACKED,
    NFKC16_WHITE_SPACE_RANGES_PACKED,
)


class Nfkc16Error(Exception):
    """Input that the pinned Unicode 16.0.0 profile rejects."""

    UNPAIRED_SURROGATE = "UNPAIRED_SURROGATE"
    UNASSIGNED_CODEPOINT = "UNASSIGNED_CODEPOINT"

    def __init__(self, code: str, message: str, code_point: int) -> None:
        super().__init__(f"{code}: {message}")
        self.code: str = code
        self.code_point: int = code_point


# Hangul decomposition/composition is algorithmic (UAX #15 section 3.12).
_HANGUL_S_BASE = 0xAC00
_HANGUL_L_BASE = 0x1100
_HANGUL_V_BASE = 0x1161
_HANGUL_T_BASE = 0x11A7
_HANGUL_L_COUNT = 19
_HANGUL_V_COUNT = 21
_HANGUL_T_COUNT = 28
_HANGUL_N_COUNT = _HANGUL_V_COUNT * _HANGUL_T_COUNT  # 588
_HANGUL_S_COUNT = _HANGUL_L_COUNT * _HANGUL_N_COUNT  # 11172

_SURROGATE_FIRST = 0xD800
_SURROGATE_LAST = 0xDFFF
_MAX_CODE_POINT = 0x10FFFF


def _parse_decomposition(packed: str) -> dict[int, tuple[int, ...]]:
    out: dict[int, tuple[int, ...]] = {}
    for entry in packed.split(";"):
        key, _, targets = entry.partition("=")
        out[int(key, 16)] = tuple(int(token, 16) for token in targets.split(" "))
    return out


def _parse_ccc(packed: str) -> dict[int, int]:
    out: dict[int, int] = {}
    for entry in packed.split(";"):
        span, _, value = entry.partition(":")
        start, _, end = span.partition("-")
        first = int(start, 16)
        last = int(end, 16) if end else first
        combining = int(value, 16)
        for cp in range(first, last + 1):
            out[cp] = combining
    return out


def _parse_composition(packed: str) -> dict[tuple[int, int], int]:
    out: dict[tuple[int, int], int] = {}
    for entry in packed.split(";"):
        key, _, composed = entry.partition("=")
        starter, combining = key.split(" ")
        out[(int(starter, 16), int(combining, 16))] = int(composed, 16)
    return out


def _parse_ranges(packed: str) -> tuple[list[int], list[int]]:
    starts: list[int] = []
    ends: list[int] = []
    for entry in packed.split(";"):
        start, _, end = entry.partition("-")
        first = int(start, 16)
        starts.append(first)
        ends.append(int(end, 16) if end else first)
    return starts, ends


_DECOMPOSITION = _parse_decomposition(NFKC16_DECOMPOSITION_PACKED)
_CCC = _parse_ccc(NFKC16_CCC_PACKED)
_COMPOSITION = _parse_composition(NFKC16_COMPOSITION_PACKED)
_ASSIGNED_STARTS, _ASSIGNED_ENDS = _parse_ranges(NFKC16_ASSIGNED_RANGES_PACKED)
_WHITE_SPACE_STARTS, _WHITE_SPACE_ENDS = _parse_ranges(NFKC16_WHITE_SPACE_RANGES_PACKED)


def _in_ranges(starts: list[int], ends: list[int], code_point: int) -> bool:
    index = bisect_right(starts, code_point) - 1
    return index >= 0 and code_point <= ends[index]


def is_assigned16(code_point: int) -> bool:
    """Whether the code point is assigned (General_Category != Cn) in Unicode 16.0.0."""
    if code_point < 0 or code_point > _MAX_CODE_POINT:
        return False
    return _in_ranges(_ASSIGNED_STARTS, _ASSIGNED_ENDS, code_point)


def is_white_space16(code_point: int) -> bool:
    """Whether the code point has White_Space=Yes in Unicode 16.0.0."""
    if code_point < 0 or code_point > _MAX_CODE_POINT:
        return False
    return _in_ranges(_WHITE_SPACE_STARTS, _WHITE_SPACE_ENDS, code_point)


def _validated_scalar_values(text: str) -> list[int]:
    """Reject surrogates and unassigned code points, in input order.

    Python strings can carry lone surrogate code points (for example via
    surrogatepass decoding); they are never valid scalar values, so they are
    rejected exactly like an unpaired surrogate in a UTF-16 implementation.
    """
    code_points: list[int] = []
    for index, char in enumerate(text):
        cp = ord(char)
        if _SURROGATE_FIRST <= cp <= _SURROGATE_LAST:
            raise Nfkc16Error(
                Nfkc16Error.UNPAIRED_SURROGATE,
                f"unpaired surrogate 0x{cp:X} at index {index}",
                cp,
            )
        if not _in_ranges(_ASSIGNED_STARTS, _ASSIGNED_ENDS, cp):
            raise Nfkc16Error(
                Nfkc16Error.UNASSIGNED_CODEPOINT,
                f"code point U+{cp:04X} is not assigned in Unicode 16.0.0",
                cp,
            )
        code_points.append(cp)
    return code_points


def _decompose(code_points: list[int]) -> list[int]:
    out: list[int] = []
    for cp in code_points:
        if _HANGUL_S_BASE <= cp < _HANGUL_S_BASE + _HANGUL_S_COUNT:
            s_index = cp - _HANGUL_S_BASE
            out.append(_HANGUL_L_BASE + s_index // _HANGUL_N_COUNT)
            out.append(_HANGUL_V_BASE + (s_index % _HANGUL_N_COUNT) // _HANGUL_T_COUNT)
            trailing = s_index % _HANGUL_T_COUNT
            if trailing != 0:
                out.append(_HANGUL_T_BASE + trailing)
            continue
        mapped = _DECOMPOSITION.get(cp)
        if mapped is not None:
            out.extend(mapped)
        else:
            out.append(cp)
    return out


def _canonical_reorder(code_points: list[int]) -> None:
    """Canonical Ordering Algorithm: stable insertion sort of nonzero-ccc runs."""
    for i in range(1, len(code_points)):
        cp = code_points[i]
        combining = _CCC.get(cp, 0)
        if combining == 0:
            continue
        j = i
        while j > 0 and _CCC.get(code_points[j - 1], 0) > combining:
            code_points[j] = code_points[j - 1]
            j -= 1
        code_points[j] = cp


def _compose_pair(a: int, b: int) -> int | None:
    if (
        _HANGUL_L_BASE <= a < _HANGUL_L_BASE + _HANGUL_L_COUNT
        and _HANGUL_V_BASE <= b < _HANGUL_V_BASE + _HANGUL_V_COUNT
    ):
        return (
            _HANGUL_S_BASE
            + ((a - _HANGUL_L_BASE) * _HANGUL_V_COUNT + (b - _HANGUL_V_BASE)) * _HANGUL_T_COUNT
        )
    if (
        _HANGUL_S_BASE <= a < _HANGUL_S_BASE + _HANGUL_S_COUNT
        and (a - _HANGUL_S_BASE) % _HANGUL_T_COUNT == 0
        and _HANGUL_T_BASE < b < _HANGUL_T_BASE + _HANGUL_T_COUNT
    ):
        return a + (b - _HANGUL_T_BASE)
    return _COMPOSITION.get((a, b))


def _compose(code_points: list[int]) -> list[int]:
    """Canonical Composition Algorithm.

    A combining character composes with the last starter when it is not
    blocked: either it directly follows the starter, or every character in
    between has a strictly lower combining class (the sequence is canonically
    ordered, so checking the immediately preceding class suffices). Primary
    composites are always starters, so a successful composition never changes
    the trailing combining class.
    """
    out: list[int] = []
    starter_idx = -1
    last_ccc = 0
    for cp in code_points:
        combining = _CCC.get(cp, 0)
        if starter_idx >= 0 and (starter_idx == len(out) - 1 or last_ccc < combining):
            composed = _compose_pair(out[starter_idx], cp)
            if composed is not None:
                out[starter_idx] = composed
                continue
        out.append(cp)
        last_ccc = combining
        if combining == 0:
            starter_idx = len(out) - 1
    return out


def nfkc16(text: str) -> str:
    """Normalize to NFKC exactly as Unicode 16.0.0 defines it.

    Raises :class:`Nfkc16Error` with code UNPAIRED_SURROGATE when the input
    contains a surrogate code point, and with code UNASSIGNED_CODEPOINT when
    it contains a code point that Unicode 16.0.0 leaves unassigned
    (normalization of such input would not be stable across Unicode versions).
    """
    code_points = _validated_scalar_values(text)
    decomposed = _decompose(code_points)
    _canonical_reorder(decomposed)
    return "".join(chr(cp) for cp in _compose(decomposed))
