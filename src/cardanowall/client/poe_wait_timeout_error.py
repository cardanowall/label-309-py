"""Raised by :meth:`PoeNamespace.wait` when the caller-supplied ``timeout``
elapses before the record reaches the requested target (or a terminal state).

The error carries ``last_snapshot`` — the most recent normalised status
snapshot seen before the deadline, or ``None`` when the deadline hit before
any snapshot arrived — so callers can report how far the publish had
progressed.
"""

from __future__ import annotations

from .types import PoeStatusSnapshot


class PoeWaitTimeoutError(Exception):
    last_snapshot: PoeStatusSnapshot | None

    def __init__(self, last_snapshot: PoeStatusSnapshot | None) -> None:
        progressed = (
            f"last status '{last_snapshot['status']}'"
            if last_snapshot is not None
            else "no status snapshot received"
        )
        super().__init__(f"timed out waiting for the PoE record ({progressed})")
        self.last_snapshot = last_snapshot


__all__ = ["PoeWaitTimeoutError"]
