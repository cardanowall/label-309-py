"""Raised by the high-level helpers (``publish_sealed``, ``publish_merkle``)
when one or more files uploaded via /poe/uploads come back with ``ok: false``.

The error carries the full ``UploadsResponse`` so callers can:

- retry just the failed indices (use :attr:`failed_indices` to subset their input)
- inspect per-file ``error.code`` / ``error.detail`` for diagnostics
- see which files DID land (already-uploaded files are billed and the URIs
  remain valid; reuploading them would double-charge)
"""

from __future__ import annotations

from .types import UploadFailureEntry, UploadsResponse


class PartialUploadError(Exception):
    response: UploadsResponse
    failed: tuple[UploadFailureEntry, ...]

    def __init__(self, response: UploadsResponse) -> None:
        failed: list[UploadFailureEntry] = [
            u for u in response["uploads"] if u["ok"] is False
        ]
        detail = "; ".join(
            f"[{f['idx']}] {f['error']['code']} — {f['error']['detail']}" for f in failed
        )
        super().__init__(
            f"{len(failed)} of {len(response['uploads'])} upload(s) failed: {detail}",
        )
        self.response = response
        self.failed = tuple(failed)

    @property
    def failed_indices(self) -> tuple[int, ...]:
        """The ``idx`` of every failed entry, in input order."""
        return tuple(f["idx"] for f in self.failed)


__all__ = ["PartialUploadError"]
