"""404 ``record-not-found`` — no Label 309 record is registered for the
requested ``tx_hash``.
"""

from __future__ import annotations

from .http_error import Label309HttpError


class RecordNotFoundError(Label309HttpError):
    pass


__all__ = ["RecordNotFoundError"]
