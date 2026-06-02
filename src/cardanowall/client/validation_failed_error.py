"""400 ``validation-failed`` — the request body parsed as JSON but failed
the route's schema check.

The per-field issues live on ``err.errors`` (Zod issue codes; e.g.
``invalid_type``, ``too_small``, ``custom``).
"""

from __future__ import annotations

from .http_error import Cip309HttpError


class ValidationFailedError(Cip309HttpError):
    pass


__all__ = ["ValidationFailedError"]
