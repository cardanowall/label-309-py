"""400 ``invalid-body`` — the request body was structurally malformed (e.g.
not valid JSON, or a higher-level shape check failed before Zod ran).
Schema validation failures emit ``validation-failed`` (→
:class:`ValidationFailedError`) instead.
"""

from __future__ import annotations

from .http_error import Cip309HttpError


class InvalidBodyError(Cip309HttpError):
    pass


__all__ = ["InvalidBodyError"]
