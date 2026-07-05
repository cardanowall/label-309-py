"""Raised by the internally-quoting publish helpers (``submit_sealed``,
``publish_sealed``, ``publish_merkle``) when the quoted price exceeds the
caller's ``max_usd_micros`` cap.

Nothing is spent against the offending quote: the cap is enforced against the
initial quote before any storage upload, and again against any refreshed
quote — FX may move while an upload runs, and the cap is a promise about what
gets spent.
"""

from __future__ import annotations


class MaxUsdExceededError(Exception):
    """The quoted price exceeds the caller's price cap.

    ``quoted_usd_micros`` is the gateway's decimal micro-USD ``amount``
    string; ``max_usd_micros`` is the caller's cap in USD micro-cents
    (1 USD = 1,000,000).
    """

    def __init__(self, quoted_usd_micros: str, max_usd_micros: int) -> None:
        super().__init__(
            f"MAX_USD_EXCEEDED: quoted price {quoted_usd_micros} micro-USD exceeds "
            f"the {max_usd_micros} micro-USD cap"
        )
        self.quoted_usd_micros: str = quoted_usd_micros
        self.max_usd_micros: int = max_usd_micros


__all__ = ["MaxUsdExceededError"]
