from __future__ import annotations

from types import TracebackType
from typing import Self

import httpx

from .account import AccountNamespace
from .account import _ResolvedConfig as _AccountResolvedConfig
from .invalid_client_config_error import InvalidClientConfigError
from .poe import PoeNamespace
from .poe import _ResolvedConfig as _PoeResolvedConfig
from .records import RecordsNamespace
from .records import _ResolvedConfig as _RecordsResolvedConfig


def _resolve_base_url(base_url: str | None) -> str:
    """Validate and normalise the gateway base URL.

    ``base_url`` is REQUIRED. The client is gateway-agnostic: it targets
    whatever HTTP origin the caller supplies (the cardanowall service, a
    self-hosted Label 309 gateway, a local dev server) and never assumes a
    default vendor host. A missing or empty value cannot be resolved into a
    target, so it raises :class:`InvalidClientConfigError`.
    """
    if base_url is None or base_url.strip() == "":
        raise InvalidClientConfigError(
            "Label309Client: base_url is required. Pass the HTTP origin of "
            "the Label 309 gateway to target (e.g. base_url='https://gateway.example.com')."
        )
    return base_url


class Label309Client:
    """Top-level HTTP client wrapping a Label 309 gateway REST API.

    Gateway-agnostic: ``base_url`` is required and used verbatim, and
    ``api_key`` is an opaque bearer token forwarded as
    ``Authorization: Bearer <key>`` with no format validation or inference.
    A third-party gateway may issue keys in any format. With no key the
    client is anonymous (read-only).

    PoE submissions debit a USD micro-cents balance. Acquire a price lock
    via ``client.poe.quote(...)`` first; the resulting ``quote_id`` is
    consumed by the publish call. Top up via the gateway's billing surface.

    Async-canonical: every namespace method returns a coroutine. For sync use,
    wrap calls in ``asyncio.run(...)``. Use as an async context manager to
    close the underlying ``httpx.AsyncClient`` cleanly:

        async with Label309Client(base_url="https://gateway.example.com") as client:
            resource = await client.records.get(tx_hash)
    """

    poe: PoeNamespace
    records: RecordsNamespace
    account: AccountNamespace

    def __init__(
        self,
        *,
        base_url: str | None = None,
        api_key: str | None = None,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        self._owns_client = http_client is None
        self._http_client = http_client if http_client is not None else httpx.AsyncClient()
        self._base_url = _resolve_base_url(base_url).rstrip("/")
        self._api_key = api_key
        self.poe = PoeNamespace(
            _PoeResolvedConfig(
                api_key=self._api_key, base_url=self._base_url, http_client=self._http_client
            )
        )
        self.records = RecordsNamespace(
            _RecordsResolvedConfig(
                api_key=self._api_key, base_url=self._base_url, http_client=self._http_client
            )
        )
        self.account = AccountNamespace(
            _AccountResolvedConfig(
                api_key=self._api_key, base_url=self._base_url, http_client=self._http_client
            )
        )

    async def aclose(self) -> None:
        if self._owns_client:
            await self._http_client.aclose()

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self.aclose()


__all__ = ["InvalidClientConfigError", "Label309Client"]
