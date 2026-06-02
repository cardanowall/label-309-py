"""429 ``rate-limited`` — the caller exceeded the per-key request quota.

The retry hint lives on the standard ``Retry-After`` HTTP response header
(RFC 9110 §10.2.3). The SDK parses it into ``retry_after_seconds`` on the
raised error; the value is ``None`` if the header is absent or non-numeric.
Per RFC 7807, no retry hint appears in the problem body.
"""

from __future__ import annotations

from .http_error import Cip309HttpError


class RateLimitedError(Cip309HttpError):
    pass


__all__ = ["RateLimitedError"]
