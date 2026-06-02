"""400 ``batch-empty`` — the ``records[]`` array on
``/api/v1/poe/publish-batch`` was empty. The batch endpoint requires at
least one record.
"""

from __future__ import annotations

from .http_error import Cip309HttpError


class BatchEmptyError(Cip309HttpError):
    pass


__all__ = ["BatchEmptyError"]
