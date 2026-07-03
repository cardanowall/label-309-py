"""Raised by :meth:`PoeNamespace.wait` when the awaited PoE record reaches the
terminal ``failed`` status (including the raw engine ``permanent_failure``,
which normalises to ``failed``).

The error carries the final normalised :class:`~cardanowall.client.types.PoeStatusSnapshot`
so callers can inspect the record id, tx hash, and confirmation data of the
failed publish without a second round-trip.
"""

from __future__ import annotations

from .types import PoeStatusSnapshot


class PoeFailedError(Exception):
    snapshot: PoeStatusSnapshot

    def __init__(self, snapshot: PoeStatusSnapshot) -> None:
        super().__init__(
            f"PoE record {snapshot['id'] or '<unknown>'} reached the terminal 'failed' status"
        )
        self.snapshot = snapshot


__all__ = ["PoeFailedError"]
