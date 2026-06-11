"""Behaviour tests for the `cardano-poe-pw-norm-v1` passphrase normalization
profile: raw UTF-8 byte cap before any normalization work, pinned-Unicode-16.0
NFKC (with the unnormalizable-input rejection), White_Space run collapse to a
single U+0020, trim, and the post-normalization-empty rejection."""

from __future__ import annotations

import pytest

from cardanowall._crypto.passphrase import (
    MAX_PASSPHRASE_INPUT_BYTES,
    PassphraseNormalizationError,
    normalize_passphrase,
)


def test_plain_ascii_is_utf8_unchanged() -> None:
    assert normalize_passphrase("correct horse battery staple") == b"correct horse battery staple"


def test_nfkc_folds_compatibility_forms() -> None:
    # Full-width Latin + digits fold to ASCII; the ﬁ ligature decomposes.
    assert normalize_passphrase("ｐａｓｓ１２３") == b"pass123"  # noqa: RUF001
    assert normalize_passphrase("ﬁle") == b"file"
    # Combining sequence composes to the precomposed form.
    assert normalize_passphrase("é") == "é".encode()


def test_whitespace_runs_collapse_to_single_space() -> None:
    # Mixed run of space, tab, NBSP, and ideographic space collapses to one
    # U+0020 — including members outside the `\s` regex class's behaviour.
    assert normalize_passphrase("a \t\u00a0\u3000 b") == b"a b"
    assert normalize_passphrase("a\u2028b\u2029c") == b"a b c"
    # U+0085 NEL carries White_Space and collapses too.
    assert normalize_passphrase("a\u0085b") == b"a b"


def test_leading_and_trailing_whitespace_is_trimmed() -> None:
    assert normalize_passphrase("  padded  ") == b"padded"
    assert normalize_passphrase("\u3000padded\t") == b"padded"


def test_empty_and_whitespace_only_rejected() -> None:
    for candidate in ("", " ", " \t\u00a0\u3000 ", "\u2028\u2029"):
        with pytest.raises(PassphraseNormalizationError) as exc:
            normalize_passphrase(candidate)
        assert exc.value.code == "ENC_PASSPHRASE_EMPTY"


def test_raw_byte_cap_is_enforced_before_normalization() -> None:
    # The cap measures the raw UTF-8 encoding, not code points: 1366 ideographic
    # spaces are 4098 bytes, over the 4096-byte cap, even though normalization
    # would collapse them entirely.
    over = "\u3000" * 1366
    assert len(over.encode("utf-8")) > MAX_PASSPHRASE_INPUT_BYTES
    with pytest.raises(PassphraseNormalizationError) as exc:
        normalize_passphrase(over)
    assert exc.value.code == "PASSPHRASE_INPUT_TOO_LONG"

    at_cap = "a" * MAX_PASSPHRASE_INPUT_BYTES
    assert normalize_passphrase(at_cap) == at_cap.encode()


def test_multibyte_passphrases_survive() -> None:
    assert normalize_passphrase("пароль доступа") == "пароль доступа".encode()
    assert normalize_passphrase("合言葉\u3000です") == "合言葉 です".encode()


def test_hangul_jamo_compose_through_the_pinned_algorithmic_path() -> None:
    # L+V+T jamo (U+1100 U+1161 U+11A8) compose to the precomposed syllable
    # U+AC01.
    assert normalize_passphrase("각") == "각".encode()


def test_unassigned_codepoint_rejected_as_unnormalizable() -> None:
    # U+0378 (BMP) and U+1FFFF (supplementary) are unassigned in Unicode 16.0;
    # a later Unicode version could give them decompositions, so accepting
    # them would let the derived key drift across implementations.
    for candidate in ("pass͸word", "tail\U0001ffff"):
        with pytest.raises(PassphraseNormalizationError) as exc:
            normalize_passphrase(candidate)
        assert exc.value.code == "ENC_PASSPHRASE_UNNORMALIZABLE"


def test_lone_surrogate_rejected_as_unnormalizable() -> None:
    # surrogateescape decoding of a non-UTF-8 byte yields a str carrying a
    # lone surrogate — exactly the shape an undecodable CLI/file input takes.
    smuggled = b"pass\x80word".decode("utf-8", "surrogateescape")
    assert "\udc80" in smuggled
    for candidate in (smuggled, "\ud800ab", "ab\udfff"):
        with pytest.raises(PassphraseNormalizationError) as exc:
            normalize_passphrase(candidate)
        assert exc.value.code == "ENC_PASSPHRASE_UNNORMALIZABLE"


def test_unnormalizable_precedes_collapse_trim_and_empty() -> None:
    # Whitespace-only apart from the unassigned codepoint: were collapse/trim
    # to run first, this would surface ENC_PASSPHRASE_EMPTY.
    with pytest.raises(PassphraseNormalizationError) as exc:
        normalize_passphrase(" ͸ ")
    assert exc.value.code == "ENC_PASSPHRASE_UNNORMALIZABLE"


def test_raw_byte_cap_precedes_the_unnormalizable_check() -> None:
    # U+0378 is 2 UTF-8 bytes, so the raw input is 4098 bytes: over the cap,
    # which fires before the pinned normalizer ever sees the input — including
    # for input that also carries a lone surrogate (3 bytes under the
    # surrogate-tolerant measurement, never a UnicodeEncodeError).
    with pytest.raises(PassphraseNormalizationError) as exc:
        normalize_passphrase("͸" + "a" * 4096)
    assert exc.value.code == "PASSPHRASE_INPUT_TOO_LONG"

    with pytest.raises(PassphraseNormalizationError) as exc:
        normalize_passphrase("\udc80" + "a" * 4094)
    assert exc.value.code == "PASSPHRASE_INPUT_TOO_LONG"
