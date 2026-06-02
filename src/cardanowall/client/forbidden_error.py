"""403 ``forbidden`` — the caller is authenticated but lacks permission.

Covers the generic ``forbidden`` code plus the edge-proxy ``csrf-invalid``
flavour; scope-specific failures surface as :class:`InsufficientScopeError`
instead.
"""

from __future__ import annotations

from .http_error import Cip309HttpError


class ForbiddenError(Cip309HttpError):
    pass


__all__ = ["ForbiddenError"]
