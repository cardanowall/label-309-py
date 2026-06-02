"""Decodes an RFC 7807 ``application/problem+json`` body into the
most-specific :class:`Cip309HttpError` subclass.

Dispatch order:

1. By ``code`` (lowercase-kebab) — preferred. Each registered code maps to a
   named subclass with typed projections of its extension members.
2. By HTTP status, when the body is missing or non-conforming. In that case
   a minimal :class:`ProblemDetails` is synthesised so consumers always see
   a well-formed ``err.problem``.

The dispatcher is intentionally exhaustive over the codes emitted by the
server's problem-json builder; codes the SDK doesn't recognise fall through
to the parent :class:`Cip309HttpError` with the verbatim problem
document. Forward-compatibility: the server can introduce new codes without
breaking older SDKs — consumers either catch the parent class or dispatch
on ``err.code`` directly.
"""

from __future__ import annotations

from typing import Any, cast

from .batch_empty_error import BatchEmptyError
from .batch_too_large_error import BatchTooLargeError
from .forbidden_error import ForbiddenError
from .http_error import (
    Cip309HttpError,
    ProblemDetails,
    ProblemErrorEntry,
    extract_problem_extensions,
)
from .idempotency_conflict_error import IdempotencyConflictError
from .insufficient_funds_error import InsufficientFundsError
from .insufficient_scope_error import InsufficientScopeError
from .internal_server_error import InternalServerError
from .invalid_body_error import InvalidBodyError
from .malformed_cbor_error import MalformedCborError
from .not_found_error import NotFoundError
from .quote_already_consumed_error import QuoteAlreadyConsumedError
from .quote_expired_error import QuoteExpiredError
from .quote_not_found_error import QuoteNotFoundError
from .rate_limited_error import RateLimitedError
from .record_not_found_error import RecordNotFoundError
from .service_unavailable_error import ServiceUnavailableError
from .unauthorized_error import UnauthorizedError
from .validation_failed_error import ValidationFailedError


def _as_str(value: Any) -> str | None:
    return value if isinstance(value, str) else None


def _as_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    return None


def _as_problem_error_entries(value: Any) -> list[ProblemErrorEntry] | None:
    if not isinstance(value, list):
        return None
    out: list[ProblemErrorEntry] = []
    for entry in value:
        if not isinstance(entry, dict):
            continue
        out.append(
            ProblemErrorEntry(
                field=entry["field"] if isinstance(entry.get("field"), str) else "",
                code=entry["code"] if isinstance(entry.get("code"), str) else "",
                detail=entry["detail"] if isinstance(entry.get("detail"), str) else "",
            )
        )
    return out


def _synthesise_problem(http_status: int, request_id: str | None) -> ProblemDetails:
    """Build a minimal :class:`ProblemDetails` for non-conforming bodies."""
    return cast(
        ProblemDetails,
        {
            "type": "about:blank",
            "title": f"HTTP {http_status}",
            "status": http_status,
            "detail": f"Server returned HTTP {http_status} without a problem+json body.",
            "code": f"http-{http_status}",
            "trace_id": request_id or "",
        },
    )


def _to_problem_details(
    http_status: int, body: Any, request_id: str | None
) -> ProblemDetails:
    if not isinstance(body, dict):
        return _synthesise_problem(http_status, request_id)

    code = _as_str(body.get("code"))
    title = _as_str(body.get("title"))
    # Heuristic: a real RFC 7807 body has at minimum `code` or `title`. If
    # neither is present the body is non-conforming.
    if code is None and title is None:
        return _synthesise_problem(http_status, request_id)

    status = _as_int(body.get("status")) or http_status
    errors = _as_problem_error_entries(body.get("errors"))

    # Preserve every top-level field. Canonical fields fall back when the
    # server omitted them; everything else flows through verbatim as
    # RFC 7807 §3.2 extension members.
    out: dict[str, Any] = dict(body)
    # RFC 7807 §4.2: "about:blank" is the canonical type for a problem with no
    # dedicated reference document. Gateway-agnostic — we never synthesise a
    # vendor-specific problem URI when the server omits ``type``.
    out["type"] = _as_str(body.get("type")) or "about:blank"
    out["title"] = title or f"HTTP {status}"
    out["status"] = status
    out["detail"] = _as_str(body.get("detail")) or ""
    out["code"] = code or f"http-{status}"
    out["trace_id"] = _as_str(body.get("trace_id")) or request_id or ""
    if errors is not None:
        out["errors"] = errors
    return cast(ProblemDetails, out)


_DISPATCH: dict[str, type[Cip309HttpError]] = {
    "unauthorized": UnauthorizedError,
    "forbidden": ForbiddenError,
    "csrf-invalid": ForbiddenError,
    "insufficient-scope": InsufficientScopeError,
    "insufficient-funds": InsufficientFundsError,
    "quote-expired": QuoteExpiredError,
    "quote-not-found": QuoteNotFoundError,
    "quote-already-consumed": QuoteAlreadyConsumedError,
    "not-found": NotFoundError,
    "record-not-found": RecordNotFoundError,
    "idempotency-key-conflict": IdempotencyConflictError,
    "rate-limited": RateLimitedError,
    "validation-failed": ValidationFailedError,
    "invalid-body": InvalidBodyError,
    "malformed-cbor": MalformedCborError,
    "batch-too-large": BatchTooLargeError,
    "batch-empty": BatchEmptyError,
    "internal-error": InternalServerError,
    "service-unavailable": ServiceUnavailableError,
    # A gateway that prices on a live FX oracle may surface a transient
    # ``fx-stale`` pricing outage; to a vendor-neutral client that is just a
    # temporary inability to serve, i.e. a service-unavailable condition.
    "fx-stale": ServiceUnavailableError,
}


def parse_http_error(
    *,
    http_status: int,
    body: Any,
    request_id: str | None = None,
    retry_after_seconds: int | None = None,
) -> Cip309HttpError:
    problem = _to_problem_details(http_status, body, request_id)
    extensions = extract_problem_extensions(problem)
    klass = _DISPATCH.get(problem["code"], Cip309HttpError)
    return klass(
        problem=problem,
        extensions=extensions,
        request_id=request_id,
        retry_after_seconds=retry_after_seconds,
    )


__all__ = ["parse_http_error"]
