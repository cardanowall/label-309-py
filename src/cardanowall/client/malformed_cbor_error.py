"""400 ``malformed-cbor`` — the ``record_bytes`` payload could not be parsed
as canonical CBOR per the Label 309 deterministic encoding rules.
"""

from __future__ import annotations

from .http_error import Label309HttpError


class MalformedCborError(Label309HttpError):
    pass


__all__ = ["MalformedCborError"]
