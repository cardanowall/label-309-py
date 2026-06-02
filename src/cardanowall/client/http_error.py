"""RFC 7807 ``application/problem+json`` envelope and the typed error class
hierarchy raised by the SDK on every non-2xx response.

A conforming CIP-309 gateway's ``/api/v1/*`` routes emit the canonical shape::

    Content-Type: application/problem+json
    {
      "type":     "about:blank",
      "title":    "Payment Required",
      "status":   402,
      "detail":   "Required $0.18 for this publish; balance is $0.05.",
      "code":     "insufficient-funds",
      "trace_id": "01977c...",
      "errors":   [{"field": "items.0.hashes", "code": "invalid_type", "detail": "..."}],
      <extension members per RFC 7807 §3.2, e.g. balance_usd_micros / required_usd_micros>
    }

Field semantics:

* ``code`` is lowercase-kebab. Consumers dispatch on ``code``; the SDK
  already dispatches on ``code`` to pick the most-specific subclass.
* ``status`` matches the HTTP status. ``http_status`` is a convenience alias.
* ``errors`` carries per-field validation errors (Zod-derived on the
  server). ``field`` is the dotted JSON path; empty string denotes a
  body-level issue.
* ``trace_id`` is echoed on the ``X-Request-Id`` response header for log
  correlation. Use ``err.request_id`` when filing bug reports.
* Extension members (anything outside the canonical seven fields) are
  surfaced on ``err.extensions``. Typed subclasses project the relevant
  extension fields onto attributes (e.g.
  ``InsufficientFundsError.balance_usd_micros``).
"""

from __future__ import annotations

from typing import Any, TypedDict

__all__ = [
    "CANONICAL_PROBLEM_KEYS",
    "Cip309HttpError",
    "ProblemDetails",
    "ProblemErrorEntry",
    "extract_problem_extensions",
]


class ProblemErrorEntry(TypedDict):
    """RFC 7807 per-field error entry."""

    field: str
    """Dotted JSON path of the offending field; empty for body-level errors."""

    code: str
    """Stable lowercase-kebab (or Zod issue) code for the specific failure."""

    detail: str
    """Human-readable explanation of this individual field error."""


class ProblemDetails(TypedDict, total=False):
    """RFC 7807 ``application/problem+json`` document.

    Canonical fields (``type``, ``title``, ``status``, ``detail``, ``code``,
    ``trace_id``) are always present after parsing. ``errors`` is present on
    validation responses. ``instance`` is optional per RFC 7807 §3.1.

    Additional top-level fields are RFC 7807 §3.2 extension members and
    are preserved verbatim on ``Cip309HttpError.extensions``.
    """

    type: str
    title: str
    status: int
    detail: str
    code: str
    trace_id: str
    errors: list[ProblemErrorEntry]
    instance: str


CANONICAL_PROBLEM_KEYS: frozenset[str] = frozenset(
    {"type", "title", "status", "detail", "code", "trace_id", "errors", "instance"}
)
"""The set of canonical RFC 7807 fields, used to split extensions cleanly."""


def extract_problem_extensions(problem: ProblemDetails) -> dict[str, Any]:
    """Return RFC 7807 §3.2 extension members from a problem document.

    The result is a fresh dict containing every top-level key that is NOT
    one of the canonical fields above.
    """
    return {k: v for k, v in problem.items() if k not in CANONICAL_PROBLEM_KEYS}


class Cip309HttpError(Exception):
    """Parent class for every typed SDK HTTP error.

    Carries the full RFC 7807 problem document plus headers
    (``X-Request-Id``, ``Retry-After``) relevant for retry logic and log
    correlation.

    Consumers can dispatch on:

    * ``err.code``        — lowercase-kebab problem code
    * ``err.http_status`` — HTTP status (== ``err.problem['status']``)
    * ``isinstance(err, SpecificError)`` — see the subclasses re-exported
      from ``cardanowall.client``
    """

    problem: ProblemDetails
    code: str
    http_status: int
    title: str
    detail: str
    type: str
    trace_id: str
    instance: str | None
    errors: tuple[ProblemErrorEntry, ...] | None
    extensions: dict[str, Any]
    request_id: str
    retry_after_seconds: int | None

    def __init__(
        self,
        *,
        problem: ProblemDetails,
        extensions: dict[str, Any] | None = None,
        request_id: str | None = None,
        retry_after_seconds: int | None = None,
    ) -> None:
        detail = problem.get("detail", "") or ""
        title = problem.get("title", "") or ""
        status = problem.get("status", 0) or 0
        super().__init__(detail or f"{title} (HTTP {status})")
        self.problem = problem
        self.code = problem.get("code", "") or ""
        self.http_status = status
        self.title = title
        self.detail = detail
        self.type = problem.get("type", "") or ""
        self.trace_id = problem.get("trace_id", "") or ""
        self.instance = problem.get("instance")
        errors = problem.get("errors")
        self.errors = tuple(errors) if errors is not None else None
        self.extensions = (
            extensions if extensions is not None else extract_problem_extensions(problem)
        )
        # X-Request-Id falls back to the in-body trace_id so callers always
        # have a correlation handle even when the header is stripped by a
        # proxy.
        self.request_id = request_id if request_id is not None else self.trace_id
        self.retry_after_seconds = retry_after_seconds
