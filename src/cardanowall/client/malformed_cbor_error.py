"""400 ``malformed-cbor`` — the ``record_bytes`` payload could not be parsed
as canonical CBOR per the CIP-309 deterministic encoding rules.
"""

from __future__ import annotations

from .http_error import Cip309HttpError


class MalformedCborError(Cip309HttpError):
    pass


__all__ = ["MalformedCborError"]
