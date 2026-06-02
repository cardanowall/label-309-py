"""404 ``not-found`` — generic missing-resource response.

Domain-specific 404s (notably ``record-not-found``) deserialise to their own
subclass.
"""

from __future__ import annotations

from .http_error import Cip309HttpError


class NotFoundError(Cip309HttpError):
    pass


__all__ = ["NotFoundError"]
