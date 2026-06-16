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

    ``base_url`` is REQUIRED and is the FULL versioned base — it includes the
    API version segment (e.g. ``https://gateway.example.com/api/v1``). Each
    request appends only a resource suffix (``/records``, ``/poe/quote``, …)
    to it, so the version lives entirely in the configured base. Pointing the
    client at a future ``/api/v2`` gateway is therefore a config change, not a
    code change.

    The client is gateway-agnostic: it targets whatever HTTP base the caller
    supplies (the cardanowall service, a self-hosted Label 309 gateway, a local
    dev server) and never assumes a default vendor host. Leading/trailing ASCII
    whitespace is trimmed first, so a whitespace-only value is rejected and the
    returned base matches the other SDKs byte-for-byte before the trailing-slash
    strip runs. A missing or empty value cannot be resolved into a target, so it
    raises :class:`InvalidClientConfigError`.
    """
    trimmed = base_url.strip() if base_url is not None else ""
    if trimmed == "":
        raise InvalidClientConfigError(
            "Label309Client: base_url is required. Pass the full versioned base "
            "of the Label 309 gateway to target, including the API version "
            "segment (e.g. base_url='https://gateway.example.com/api/v1')."
        )
    return trimmed


class Label309Client:
    """Top-level HTTP client wrapping a Label 309 gateway REST API.

    Gateway-agnostic: ``base_url`` is required and used verbatim. It is the
    FULL versioned base, including the API version segment (e.g.
    ``https://gateway.example.com/api/v1``); every request appends only a
    resource suffix to it. ``api_key`` is an opaque bearer token forwarded as
    ``Authorization: Bearer <key>`` with no format validation or inference.
    A third-party gateway may issue keys in any format. With no key the
    client is anonymous (read-only).

    PoE submissions debit a USD micro-cents balance. Acquire a price lock
    via ``client.poe.quote(...)`` first; the resulting ``quote_id`` is
    consumed by the publish call. Top up via the gateway's billing surface.

    Async-canonical: every namespace method returns a coroutine. For sync use,
    wrap calls in ``asyncio.run(...)``. Use as an async context manager to
    close the underlying ``httpx.AsyncClient`` cleanly:

        async with Label309Client(base_url="https://gateway.example.com/api/v1") as client:
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
        # `_resolve_base_url` has already trimmed surrounding whitespace; strip
        # AT MOST ONE trailing slash here (matching the sdk-ts/sdk-rs
        # normalisation), then append resource suffixes verbatim. A base that
        # ends "…/" collapses to "…"; a doubled "…//" keeps one slash so the
        # join byte-matches the other SDKs.
        resolved = _resolve_base_url(base_url)
        self._base_url = resolved[:-1] if resolved.endswith("/") else resolved
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
