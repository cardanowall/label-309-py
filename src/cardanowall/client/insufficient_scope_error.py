"""403 ``insufficient-scope`` — the API key authenticated but does not grant
the scope required for the endpoint.

Wire-format extension members::

    { "required": ["poe:create"], "granted": ["poe:read", "account:read"] }

Both arrays are surfaced verbatim on the typed error. ``required_scope`` is
a convenience for the common single-scope case (the server emits a
one-element ``required`` array today).
"""

from __future__ import annotations

from typing import Any

from .http_error import Label309HttpError, ProblemDetails


def _read_scope_array(value: Any) -> tuple[str, ...]:
    if not isinstance(value, list):
        return ()
    return tuple(item for item in value if isinstance(item, str))


class InsufficientScopeError(Label309HttpError):
    required_scopes: tuple[str, ...]
    granted_scopes: tuple[str, ...]

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
        self.required_scopes = _read_scope_array(self.extensions.get("required"))
        self.granted_scopes = _read_scope_array(self.extensions.get("granted"))

    @property
    def required_scope(self) -> str | None:
        """Convenience for the single-scope case: first entry of ``required_scopes``."""
        return self.required_scopes[0] if self.required_scopes else None


__all__ = ["InsufficientScopeError"]
