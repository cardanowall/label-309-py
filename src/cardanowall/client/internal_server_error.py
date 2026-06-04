"""500 ``internal-error`` — unexpected server-side failure. The detail message
is deliberately generic; correlate the failure via ``err.request_id`` in
server logs.
"""

from __future__ import annotations

from .http_error import Label309HttpError


class InternalServerError(Label309HttpError):
    pass


__all__ = ["InternalServerError"]
