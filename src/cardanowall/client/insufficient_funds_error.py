"""402 ``insufficient-funds`` — the account's USD balance is below the cost
of the requested operation.

Wire-format extension members (RFC 7807 §3.2). Money fields land as decimal
strings so JSON parsing preserves precision::

    {
      "balance_usd_micros":  "<decimal string>",
      "required_usd_micros": "<decimal string>",
      "top_up_url":          "/billing/top-up"
    }

Field-name mapping (wire → SDK):
    balance_usd_micros  → balance_usd_micros  (string → int)
    required_usd_micros → required_usd_micros (string → int)
    top_up_url          → top_up_url          (snake_case kept)

Idempotency contract: a 402 is non-committing — the server does NOT cache
the response under the request's ``Idempotency-Key``. After topping up via
the billing surface, the SDK consumer MAY retry with the SAME
``Idempotency-Key`` within the 24h TTL window; the handler runs fresh and
(assuming the balance now suffices) the retry returns 202 with a freshly
assigned ``id``.
"""

from __future__ import annotations

from typing import Any

from .http_error import Label309HttpError, ProblemDetails


def _read_int_string(value: Any) -> int | None:
    if not isinstance(value, str):
        return None
    if (
        not value
        or (value[0] == "-" and not value[1:].isdigit())
        or (value[0] != "-" and not value.isdigit())
    ):
        return None
    try:
        return int(value)
    except ValueError:
        return None


def _read_str(value: Any) -> str | None:
    return value if isinstance(value, str) else None


class InsufficientFundsError(Label309HttpError):
    balance_usd_micros: int | None
    required_usd_micros: int | None
    top_up_url: str | None

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
        self.balance_usd_micros = _read_int_string(self.extensions.get("balance_usd_micros"))
        self.required_usd_micros = _read_int_string(self.extensions.get("required_usd_micros"))
        self.top_up_url = _read_str(self.extensions.get("top_up_url"))


__all__ = ["InsufficientFundsError"]
