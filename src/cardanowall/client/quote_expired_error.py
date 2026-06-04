"""410 ``quote-expired`` — the publish quote referenced by ``quote_id``
exceeded its TTL (15 minutes from issuance) before /publish consumed it.
The caller should request a fresh quote via POST /api/v1/poe/quote and
retry.

Wire-format extension members (RFC 7807 §3.2)::

    { "quote_id": "<uuid>" }
"""

from __future__ import annotations

from typing import Any

from .http_error import Label309HttpError, ProblemDetails


def _read_str(value: Any) -> str | None:
    return value if isinstance(value, str) else None


class QuoteExpiredError(Label309HttpError):
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


__all__ = ["QuoteExpiredError"]
