"""401 ``unauthorized`` — caller is not authenticated. The server emits this
when the ``Authorization: Bearer`` header is missing, malformed, or names a
revoked / unknown API key.

``UnauthenticatedError`` is retained as a backward-compatible alias.
"""

from __future__ import annotations

from .http_error import Cip309HttpError


class UnauthorizedError(Cip309HttpError):
    pass


UnauthenticatedError = UnauthorizedError


__all__ = ["UnauthenticatedError", "UnauthorizedError"]
