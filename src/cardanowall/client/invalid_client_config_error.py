"""Raised from the Cip309Client constructor when the config cannot be
resolved into a usable gateway target.

The single trigger: no ``base_url`` was supplied (or it was empty). The client
is gateway-agnostic and has no default host, so a base URL is required to know
which HTTP origin to target.

``code`` matches the TypeScript SDK's ``InvalidClientConfigError.code``.
"""

from __future__ import annotations


class InvalidClientConfigError(Exception):
    code = "INVALID_CLIENT_CONFIG"


__all__ = ["InvalidClientConfigError"]
