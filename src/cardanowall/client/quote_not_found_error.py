"""404 ``quote-not-found`` — the supplied ``quote_id`` does not exist for
the authenticated account. Either the UUID is wrong, or the quote belongs
to a different account (the server enforces account scoping on quote rows).

Wire-format extension members (RFC 7807 §3.2)::

    { "quote_id": "<uuid>" }
"""

from __future__ import annotations

from typing import Any

from .http_error import Cip309HttpError, ProblemDetails


def _read_str(value: Any) -> str | None:
    return value if isinstance(value, str) else None


class QuoteNotFoundError(Cip309HttpError):
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


__all__ = ["QuoteNotFoundError"]
