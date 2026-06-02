from __future__ import annotations

import dataclasses
from typing import Any, cast

from .types import ValidationSummary, VerifyReport


def verify_report_to_dict(report: VerifyReport) -> dict[str, Any]:
    """Walk the frozen dataclass tree into a JSON-safe dict.

    Byte-for-byte parity with the TypeScript twin's `verifyReportToDict`:

    - Field names: snake_case (dataclass field names are already snake_case).
    - bytes -> lowercase hex without 0x prefix.
    - tuple -> list.
    - `None` values are OMITTED (TS omits `undefined`/`null`).
    - Empty lists/tuples are EMITTED as `[]` — EXCEPT the `validation`
      summary's `issues` / `warnings` / `info`, which the TS verifier builds
      via `composeValidation` and never materialises when empty. We mirror that
      single structural omission here so `validation` serialises to
      `{"valid": …}` alone when there is nothing to report, while genuinely
      empty list fields elsewhere (e.g. `tx_witnesses` on a placeholder-body
      record) still serialise as `[]`.
    - Nested dataclasses recursed.
    """
    return cast(dict[str, Any], _walk(report))


def _walk(value: Any) -> Any:
    if value is None:
        return None
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, bool):
        return value
    if isinstance(value, (str, int, float)):
        return value
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        # The validation summary is the ONLY place an empty list-shape is
        # equivalent to absence (matching the TS `composeValidation` helper,
        # which omits empty issues/warnings/info). Every other dataclass field
        # emits its empty collections as `[]`.
        is_validation_summary = isinstance(value, ValidationSummary)
        out: dict[str, Any] = {}
        for f in dataclasses.fields(value):
            v = getattr(value, f.name)
            if v is None:
                continue
            if (
                is_validation_summary
                and f.name in ("issues", "warnings", "info")
                and isinstance(v, (list, tuple))
                and len(v) == 0
            ):
                continue
            out[f.name] = _walk(v)
        return out
    if isinstance(value, (list, tuple)):
        return [_walk(item) for item in value]
    if isinstance(value, dict):
        return {str(k): _walk(v) for k, v in value.items()}
    raise TypeError(f"unsupported type {type(value).__name__} in VerifyReport tree")
