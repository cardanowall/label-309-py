from __future__ import annotations

from cardanowall._crypto.compare_ct import compare_ct


def test_compare_ct_equal_returns_true() -> None:
    assert compare_ct(b"\x01\x02\x03", b"\x01\x02\x03") is True


def test_compare_ct_unequal_content_returns_false() -> None:
    assert compare_ct(b"\x01\x02\x03", b"\x01\x02\x04") is False


def test_compare_ct_length_mismatch_short_circuits_to_false() -> None:
    assert compare_ct(b"\x01\x02\x03", b"\x01\x02") is False
    assert compare_ct(b"\x01\x02", b"\x01\x02\x03") is False


def test_compare_ct_empty_arrays_return_true() -> None:
    assert compare_ct(b"", b"") is True


def test_compare_ct_32_byte_identical_returns_true() -> None:
    a = b"\xab" * 32
    b = b"\xab" * 32
    assert compare_ct(a, b) is True


def test_compare_ct_32_byte_one_byte_diff_returns_false() -> None:
    a = b"\xab" * 32
    arr = bytearray(a)
    arr[15] = 0xAC
    assert compare_ct(a, bytes(arr)) is False
