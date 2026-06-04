"""409 ``idempotency-key-conflict`` — the supplied ``Idempotency-Key`` has been
seen before with a different request body within its 24h TTL window.
"""

from __future__ import annotations

from .http_error import Label309HttpError


class IdempotencyConflictError(Label309HttpError):
    pass


__all__ = ["IdempotencyConflictError"]
