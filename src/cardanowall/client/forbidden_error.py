"""403 ``forbidden`` — the caller is authenticated but lacks permission.

Covers the generic ``forbidden`` code plus the edge-proxy ``csrf-invalid``
flavour; scope-specific failures surface as :class:`InsufficientScopeError`
instead.
"""

from __future__ import annotations

from .http_error import Label309HttpError


class ForbiddenError(Label309HttpError):
    pass


__all__ = ["ForbiddenError"]
