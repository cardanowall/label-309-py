"""Canonical JSON projection of ``VerifyReport``.

The TypeScript and Python SDKs must emit byte-identical JSON for the same
report so cross-language fixtures stay in lockstep. The TypeScript report
type IS the wire shape; this module maps the Python dataclass tree onto it:

  - dataclass field names are camelized (``exit_code`` → ``exitCode``,
    ``audit_trail`` → ``auditTrail``, ``content_check`` → ``contentCheck``,
    ``duration_ms`` → ``durationMs``, …) EXCEPT
      * the spec-pinned chain facts ``block_time`` / ``block_slot``, and
      * the transaction-description sub-objects (``VerifyTxWitness`` /
        ``VerifyTxOutput`` / ``VerifyTxSummary``), whose snake_case fields
        are the wire form already;
  - ``bytes`` values render as lowercase hex without a ``0x`` prefix;
  - ``None`` values are OMITTED (the TypeScript twin omits
    ``undefined``/``null``);
  - tuples render as JSON arrays; plain dict values (the embedded
    ``PoeRecord`` and its ``hashes`` maps) pass through with their wire keys
    untouched.
"""

from __future__ import annotations

import dataclasses
from typing import Any, Final, cast

from .types import HttpCallRecord, VerifyReport, VerifyTxOutput, VerifyTxSummary, VerifyTxWitness

# Report-level keys the published schema pins in snake_case.
_KEEP_SNAKE_FIELDS: Final[frozenset[str]] = frozenset({"block_time", "block_slot"})

# Dataclasses whose field names are wire-form verbatim (no camelization).
_WIRE_VERBATIM_TYPES: Final[tuple[type, ...]] = (VerifyTxWitness, VerifyTxOutput, VerifyTxSummary)


def _camelize(name: str) -> str:
    head, *rest = name.split("_")
    return head + "".join(part.title() for part in rest)


def verify_report_to_dict(report: VerifyReport) -> dict[str, Any]:
    """Project a ``VerifyReport`` onto the published report wire shape."""
    return cast(dict[str, Any], _walk(report))


def _walk(value: Any) -> Any:
    if isinstance(value, bytes):
        return value.hex()
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        verbatim = isinstance(value, _WIRE_VERBATIM_TYPES)
        out: dict[str, Any] = {}
        for f in dataclasses.fields(value):
            v = getattr(value, f.name)
            if v is None:
                # `status` is REQUIRED on every audit-trail entry by the
                # published schema, with null as the no-response reading — it
                # must serialize as JSON null, never be omitted.
                if isinstance(value, HttpCallRecord) and f.name == "status":
                    out["status"] = None
                continue
            key = f.name if verbatim or f.name in _KEEP_SNAKE_FIELDS else _camelize(f.name)
            out[key] = _walk(v)
        return out
    if isinstance(value, (list, tuple)):
        return [_walk(item) for item in value]
    if isinstance(value, dict):
        return {str(k): _walk(v) for k, v in value.items() if v is not None}
    if value is None or isinstance(value, (bool, str, int, float)):
        return value
    raise TypeError(f"unsupported type {type(value).__name__} in VerifyReport tree")


__all__ = ["verify_report_to_dict"]
