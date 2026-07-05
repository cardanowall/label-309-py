"""Raised by ``submit_sealed`` when an upload receipt passed for resume does
not match the prepared material it claims to cover.

The rejection fires before any network call: an unknown ``item_id``, a digest
or byte count that differs from the prepared ciphertext, an empty URI, or a
duplicate receipt is rejected outright rather than skipped — a receipt is a
paid-storage claim, and honouring a wrong one would publish a record whose
URI points at bytes the prepared seal never produced.
"""

from __future__ import annotations


class InvalidUploadReceiptError(Exception):
    """An upload receipt failed validation against the prepared seal."""

    def __init__(self, detail: str) -> None:
        super().__init__(f"INVALID_UPLOAD_RECEIPT: {detail}")
        self.detail: str = detail


__all__ = ["InvalidUploadReceiptError"]
