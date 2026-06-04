"""503 ``service-unavailable`` — temporary inability to serve the request.

The retry hint, if any, is on the standard ``Retry-After`` header —
surfaced on ``err.retry_after_seconds``.
"""

from __future__ import annotations

from .http_error import Label309HttpError


class ServiceUnavailableError(Label309HttpError):
    pass


__all__ = ["ServiceUnavailableError"]
