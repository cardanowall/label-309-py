"""409 ``quote-already-consumed`` — the publish quote referenced by
``quote_id`` has already been used by a prior /publish call. Quotes are
single-use; a freshly-issued quote covers exactly one PoE submission. The
caller should request a fresh quote via POST /api/v1/poe/quote and retry.

Wire-format extension members (RFC 7807 §3.2)::

    { "quote_id": "<uuid>" }
"""

from __future__ import annotations

from typing import Any

from .http_error import Label309HttpError, ProblemDetails


def _read_str(value: Any) -> str | None:
    return value if isinstance(value, str) else None


class QuoteAlreadyConsumedError(Label309HttpError):
    quote_id: str | None

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
        self.quote_id = _read_str(self.extensions.get("quote_id"))


__all__ = ["QuoteAlreadyConsumedError"]
