"""400 ``batch-empty`` — the ``records[]`` array on
``/poe/publish-batch`` was empty. The batch endpoint requires at
least one record.
"""

from __future__ import annotations

from .http_error import Label309HttpError


class BatchEmptyError(Label309HttpError):
    pass


__all__ = ["BatchEmptyError"]
