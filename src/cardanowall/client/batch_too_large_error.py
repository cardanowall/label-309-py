"""400 ``batch-too-large`` — the ``records[]`` array on
``/api/v1/poe/publish-batch`` carries more entries than the per-call ceiling
(max 50).

Wire-format extension members::

    { "max": <int>, "got": <int> }
"""

from __future__ import annotations

from typing import Any

from .http_error import Cip309HttpError, ProblemDetails


def _read_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    return None


class BatchTooLargeError(Cip309HttpError):
    max: int | None
    got: int | None

    def __init__(
        self,
        *,
        problem: ProblemDetails,
        extensions: dict[str, Any] | None = None,
        request_id: str | None = None,
        retry_after_seconds: int | None = None,
    ) -> None:
        super().__init__(
            problem=problem,
            extensions=extensions,
            request_id=request_id,
            retry_after_seconds=retry_after_seconds,
        )
        self.max = _read_int(self.extensions.get("max"))
        self.got = _read_int(self.extensions.get("got"))


__all__ = ["BatchTooLargeError"]
