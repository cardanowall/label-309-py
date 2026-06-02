"""Unit tests for the Python conformance CLI dispatcher."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from unittest.mock import AsyncMock, patch

from cardanowall.conformance.__main__ import parse_args, run

_VALID_TX = "a" * 64


@dataclass
class _CapturedIO:
    stdout_chunks: list[str] = field(default_factory=list)
    stderr_chunks: list[str] = field(default_factory=list)

    def stdout(self, text: str) -> None:
        self.stdout_chunks.append(text)

    def stderr(self, text: str) -> None:
        self.stderr_chunks.append(text)

    @property
    def stdout_text(self) -> str:
        return "".join(self.stdout_chunks)

    @property
    def stderr_text(self) -> str:
        return "".join(self.stderr_chunks)


def _fake_report(*, verdict: str, exit_code: int) -> Any:
    """Fake verifier report carrying just the fields the CLI consumes."""

    @dataclass(frozen=True)
    class _FakeReport:
        verdict: str
        exit_code: int

    return _FakeReport(verdict=verdict, exit_code=exit_code)


def test_parse_args_extracts_tx_hash() -> None:
    out = parse_args([_VALID_TX])
    assert out.tx_hash == _VALID_TX


def test_parse_args_rejects_unknown_flag() -> None:
    out = parse_args(["--bogus"])
    assert out.error is not None and "unknown" in out.error


def test_parse_args_collects_multiple_gateways() -> None:
    out = parse_args([_VALID_TX, "--gateway", "http://g1", "--gateway", "http://g2"])
    assert out.gateways == ("http://g1", "http://g2")


def test_parse_args_threshold_must_be_integer() -> None:
    out = parse_args([_VALID_TX, "--threshold", "1.5"])
    assert out.error is not None


def test_parse_args_help_and_version() -> None:
    assert parse_args(["--help"]).show_help
    assert parse_args(["--version"]).show_version


def test_run_exits_0_on_valid() -> None:
    io = _CapturedIO()
    with patch(
        "cardanowall.conformance.__main__.verify_tx",
        new=AsyncMock(return_value=_fake_report(verdict="valid", exit_code=0)),
    ), patch(
        "cardanowall.conformance.__main__.verify_report_to_dict",
        return_value={"verdict": "valid", "exit_code": 0},
    ):
        code = run([_VALID_TX], io)
    assert code == 0
    assert "valid" in io.stdout_text


def test_run_exits_1_on_integrity_failure() -> None:
    io = _CapturedIO()
    with patch(
        "cardanowall.conformance.__main__.verify_tx",
        new=AsyncMock(return_value=_fake_report(verdict="failed", exit_code=1)),
    ), patch(
        "cardanowall.conformance.__main__.verify_report_to_dict",
        return_value={"verdict": "failed", "exit_code": 1},
    ):
        assert run([_VALID_TX], io) == 1


def test_run_exits_2_on_network_failure() -> None:
    io = _CapturedIO()
    with patch(
        "cardanowall.conformance.__main__.verify_tx",
        new=AsyncMock(return_value=_fake_report(verdict="failed", exit_code=2)),
    ), patch(
        "cardanowall.conformance.__main__.verify_report_to_dict",
        return_value={"verdict": "failed", "exit_code": 2},
    ):
        assert run([_VALID_TX], io) == 2


def test_run_exits_3_on_pending() -> None:
    io = _CapturedIO()
    with patch(
        "cardanowall.conformance.__main__.verify_tx",
        new=AsyncMock(return_value=_fake_report(verdict="pending", exit_code=3)),
    ), patch(
        "cardanowall.conformance.__main__.verify_report_to_dict",
        return_value={"verdict": "pending", "exit_code": 3},
    ):
        assert run([_VALID_TX], io) == 3


def test_run_exits_4_on_missing_tx_hash() -> None:
    io = _CapturedIO()
    code = run([], io)
    assert code == 4
    assert "required" in io.stderr_text.lower()


def test_run_exits_4_on_malformed_tx_hash() -> None:
    io = _CapturedIO()
    code = run(["not-a-hex"], io)
    assert code == 4
    assert "invalid" in io.stderr_text.lower()


def test_run_exits_2_when_verifier_throws() -> None:
    io = _CapturedIO()
    with patch(
        "cardanowall.conformance.__main__.verify_tx",
        new=AsyncMock(side_effect=RuntimeError("net down")),
    ):
        assert run([_VALID_TX], io) == 2


def test_run_version_exits_0() -> None:
    io = _CapturedIO()
    assert run(["--version"], io) == 0
    assert "cardanowall-sdk-conformance" in io.stdout_text


def test_run_help_exits_0() -> None:
    io = _CapturedIO()
    assert run(["--help"], io) == 0
    assert "Usage:" in io.stdout_text
