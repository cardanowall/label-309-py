"""``client.account.*`` — account read surface.

Wraps the account read route (suffix appended to the configured versioned
``base_url``):

* ``GET /account/balance`` → :meth:`AccountNamespace.balance`

Auth is required (Bearer with ``account:read`` scope, or a session cookie when
the gateway is browser-fronted). The configured API key is forwarded as
``Authorization: Bearer …``.

The balance is USD micro-cents carried as a decimal string on the wire
(``balance_usd_micros``). The SDK returns it verbatim as a string and never
coerces it to an ``int``, so the bigint value survives without precision loss.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

import httpx

from .parse_http_error import parse_http_error
from .types import AccountBalance


@dataclass(frozen=True)
class _ResolvedConfig:
    api_key: str | None
    base_url: str
    http_client: httpx.AsyncClient


def _build_headers(api_key: str | None) -> dict[str, str]:
    headers = {"content-type": "application/json", "accept": "application/json"}
    if api_key is not None:
        headers["authorization"] = f"Bearer {api_key}"
    return headers


def _parse_retry_after(header: str | None) -> int | None:
    if header is None:
        return None
    try:
        parsed = int(header)
    except ValueError:
        return None
    return parsed


def _raise_for_status(response: httpx.Response) -> None:
    if response.is_success:
        return
    try:
        body = response.json()
    except (json.JSONDecodeError, ValueError):
        body = None
    request_id = response.headers.get("x-request-id")
    retry_after_seconds = _parse_retry_after(response.headers.get("retry-after"))
    raise parse_http_error(
        http_status=response.status_code,
        body=body,
        request_id=request_id,
        retry_after_seconds=retry_after_seconds,
    )


class AccountNamespace:
    """``GET /account/balance``."""

    def __init__(self, config: _ResolvedConfig) -> None:
        self._config = config

    async def balance(self) -> AccountBalance:
        """Fetch the caller's current prepaid USD balance.

        Returns the typed :class:`AccountBalance` ``{ "balance_usd_micros":
        "<decimal string>" }`` verbatim from the gateway — the USD micro-cents
        value stays a string, never parsed into an ``int``, so no precision is
        lost. An account with no ledger activity yet reads ``"0"``.

        Requires authentication: 401 (:class:`UnauthorizedError`) when
        anonymous, 403 (:class:`InsufficientScopeError`) when the Bearer key
        lacks the ``account:read`` scope.
        """
        response = await self._config.http_client.get(
            f"{self._config.base_url}/account/balance",
            headers=_build_headers(self._config.api_key),
        )
        _raise_for_status(response)
        return response.json()  # type: ignore[no-any-return]


__all__ = ["AccountNamespace"]
