"""Conformance CLI: single-tx verification against the standalone verifier.

Exit codes (extended with 4 for CLI input errors):
    0 = valid, 1 = failed (integrity), 2 = failed (network),
    3 = pending, 4 = CLI input error
"""

from __future__ import annotations

import asyncio
import json
import re
import sys
from dataclasses import dataclass
from typing import Protocol

from cardanowall import KOIOS_MAINNET_URL, VerifyTxInput, verify_tx
from cardanowall.verifier.serialize import verify_report_to_dict

_VERSION = "0.1.0"

_USAGE = (
    "Usage: cardanowall-sdk-conformance <tx-hash> [--gateway <url>] "
    "[--threshold <n>] [--json]\n"
    "       cardanowall-sdk-conformance --version\n"
    "       cardanowall-sdk-conformance --help\n"
    "\n"
    "Runs the cardanowall-sdk standalone Label 309 verifier against a single\n"
    "Cardano transaction. Exit codes:\n"
    "  0 = valid, 1 = failed (integrity), 2 = failed (network), "
    "3 = pending, 4 = CLI input error.\n"
)


@dataclass(frozen=True)
class ParsedArgs:
    tx_hash: str | None
    gateways: tuple[str, ...]
    threshold: int | None
    json: bool
    show_help: bool
    show_version: bool
    error: str | None


class _IO(Protocol):
    def stdout(self, text: str) -> None: ...
    def stderr(self, text: str) -> None: ...


@dataclass
class _StdIO:
    """Default IO impl that writes to sys.stdout/stderr."""

    def stdout(self, text: str) -> None:  # pragma: no cover — trivial
        sys.stdout.write(text)

    def stderr(self, text: str) -> None:  # pragma: no cover — trivial
        sys.stderr.write(text)


def parse_args(argv: list[str]) -> ParsedArgs:
    tx_hash: str | None = None
    gateways: list[str] = []
    threshold: int | None = None
    json_flag = True
    show_help = False
    show_version = False
    error: str | None = None

    i = 0
    while i < len(argv):
        arg = argv[i]
        if arg in {"--help", "-h"}:
            show_help = True
        elif arg in {"--version", "-V"}:
            show_version = True
        elif arg == "--json":
            json_flag = True
        elif arg == "--gateway":
            i += 1
            if i >= len(argv):
                error = "--gateway requires a value"
                break
            gateways.append(argv[i])
        elif arg == "--threshold":
            i += 1
            if i >= len(argv):
                error = "--threshold requires a non-negative integer"
                break
            try:
                n = int(argv[i])
                if n < 0:
                    raise ValueError()
                threshold = n
            except ValueError:
                error = "--threshold requires a non-negative integer"
                break
        elif arg.startswith("-"):
            error = f"unknown flag: {arg}"
            break
        elif tx_hash is None:
            tx_hash = arg
        else:
            error = f"unexpected positional argument: {arg}"
            break
        i += 1

    return ParsedArgs(
        tx_hash=tx_hash,
        gateways=tuple(gateways),
        threshold=threshold,
        json=json_flag,
        show_help=show_help,
        show_version=show_version,
        error=error,
    )


_TX_HASH_RE = re.compile(r"^[0-9a-f]{64}$", re.IGNORECASE)


async def _run_async(argv: list[str], io: _IO) -> int:
    parsed = parse_args(argv)
    if parsed.show_help:
        io.stdout(_USAGE)
        return 0
    if parsed.show_version:
        io.stdout(f"cardanowall-sdk-conformance {_VERSION}\n")
        return 0
    if parsed.error is not None:
        io.stderr(f"cardanowall-sdk-conformance: {parsed.error}\n{_USAGE}")
        return 4
    if parsed.tx_hash is None:
        io.stderr(f"cardanowall-sdk-conformance: <tx-hash> is required\n{_USAGE}")
        return 4
    if not _TX_HASH_RE.match(parsed.tx_hash):
        io.stderr(
            "cardanowall-sdk-conformance: invalid tx-hash "
            f"(expected 64 hex chars): {parsed.tx_hash}\n"
        )
        return 4

    gateways = parsed.gateways if parsed.gateways else (KOIOS_MAINNET_URL,)
    try:
        input_kwargs: dict[str, object] = {
            "tx_hash": parsed.tx_hash.lower(),
            "cardano_gateway_chain": gateways,
        }
        if parsed.threshold is not None:
            input_kwargs["confirmation_depth_threshold"] = parsed.threshold
        report = await verify_tx(VerifyTxInput(**input_kwargs))  # type: ignore[arg-type]
        io.stdout(json.dumps(verify_report_to_dict(report), indent=2, default=str) + "\n")
        return int(report.exit_code)
    except Exception as err:
        io.stderr(f"cardanowall-sdk-conformance: verifier error: {err}\n")
        return 2


def run(argv: list[str], io: _IO) -> int:
    return asyncio.run(_run_async(argv, io))


def main() -> int:
    return run(sys.argv[1:], _StdIO())


if __name__ == "__main__":
    sys.exit(main())
