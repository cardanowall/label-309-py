"""404 ``record-not-found`` — no CIP-309 record is registered for the
requested ``tx_hash``.
"""

from __future__ import annotations

from .http_error import Cip309HttpError


class RecordNotFoundError(Cip309HttpError):
    pass


__all__ = ["RecordNotFoundError"]
