"""Decoder tests for the RFC 7807 ``application/problem+json`` envelope.

The contract under test is: given a real on-the-wire body emitted by the
server's problem-json builder, ``parse_http_error()`` returns the
most-specific typed error subclass with extension members projected onto
typed attributes.
"""

from __future__ import annotations

from typing import Any

import pytest

from cardanowall.client.batch_empty_error import BatchEmptyError
from cardanowall.client.batch_too_large_error import BatchTooLargeError
from cardanowall.client.forbidden_error import ForbiddenError
from cardanowall.client.http_error import (
    Cip309HttpError,
    extract_problem_extensions,
)
from cardanowall.client.idempotency_conflict_error import IdempotencyConflictError
from cardanowall.client.insufficient_funds_error import InsufficientFundsError
from cardanowall.client.insufficient_scope_error import InsufficientScopeError
from cardanowall.client.internal_server_error import InternalServerError
from cardanowall.client.invalid_body_error import InvalidBodyError
from cardanowall.client.malformed_cbor_error import MalformedCborError
from cardanowall.client.not_found_error import NotFoundError
from cardanowall.client.parse_http_error import parse_http_error
from cardanowall.client.quote_already_consumed_error import QuoteAlreadyConsumedError
from cardanowall.client.quote_expired_error import QuoteExpiredError
from cardanowall.client.quote_not_found_error import QuoteNotFoundError
from cardanowall.client.rate_limited_error import RateLimitedError
from cardanowall.client.record_not_found_error import RecordNotFoundError
from cardanowall.client.service_unavailable_error import ServiceUnavailableError
from cardanowall.client.unauthorized_error import (
    UnauthenticatedError,
    UnauthorizedError,
)
from cardanowall.client.validation_failed_error import ValidationFailedError


def _problem_body(**overrides: Any) -> dict[str, Any]:
    return {
        "type": "https://cardanowall.com/problems/example",
        "title": "Example",
        "status": 400,
        "detail": "Example failure.",
        "code": "example",
        "trace_id": "01977c00-0000-7000-8000-000000000000",
        **overrides,
    }


# ---------------------------------------------------------------------------
# Envelope projection
# ---------------------------------------------------------------------------


def test_envelope_preserves_verbatim_problem_and_projects_canonical_fields() -> None:
    body = _problem_body(
        type="https://cardanowall.com/problems/insufficient-funds",
        title="Payment Required",
        status=402,
        detail="Required $0.18 for this publish; balance is $0.05.",
        code="insufficient-funds",
        balance_usd_micros="50000",
        required_usd_micros="180000",
        top_up_url="/billing/top-up",
    )

    err = parse_http_error(http_status=402, body=body, request_id="req-1")

    assert err.problem == body
    assert err.code == "insufficient-funds"
    assert err.http_status == 402
    assert err.title == "Payment Required"
    assert err.detail == "Required $0.18 for this publish; balance is $0.05."
    assert err.type == "https://cardanowall.com/problems/insufficient-funds"
    assert err.trace_id == "01977c00-0000-7000-8000-000000000000"
    assert err.request_id == "req-1"
    assert err.extensions == {
        "balance_usd_micros": "50000",
        "required_usd_micros": "180000",
        "top_up_url": "/billing/top-up",
    }
    assert str(err) == "Required $0.18 for this publish; balance is $0.05."


def test_request_id_falls_back_to_trace_id_when_header_absent() -> None:
    err = parse_http_error(
        http_status=500,
        body=_problem_body(code="internal-error", status=500, trace_id="trace-xyz"),
    )
    assert err.request_id == "trace-xyz"


def test_synthesises_problem_for_non_rfc7807_bodies() -> None:
    err = parse_http_error(http_status=418, body=None)
    assert isinstance(err, Cip309HttpError)
    assert not isinstance(err, RateLimitedError)
    assert err.code == "http-418"
    assert err.http_status == 418
    assert err.type == "about:blank"


def test_synthesises_problem_for_unrecognised_body_shape() -> None:
    # A dict that lacks both `code` and `title` is non-conforming and is
    # treated as if no body had been returned.
    err = parse_http_error(http_status=503, body={"random": "junk"})
    assert isinstance(err, Cip309HttpError)
    assert err.code == "http-503"
    assert err.http_status == 503


def test_extract_problem_extensions_strips_canonical_keys() -> None:
    problem = _problem_body(balance=1, extra="hello")
    extensions = extract_problem_extensions(problem)  # type: ignore[arg-type]
    assert extensions == {"balance": 1, "extra": "hello"}


def test_retry_after_seconds_flows_through_to_error() -> None:
    err = parse_http_error(
        http_status=429,
        body=_problem_body(code="rate-limited", status=429),
        retry_after_seconds=42,
    )
    assert isinstance(err, RateLimitedError)
    assert err.retry_after_seconds == 42


# ---------------------------------------------------------------------------
# Dispatch by code
# ---------------------------------------------------------------------------


def test_unauthorized_maps_to_unauthorized_error() -> None:
    err = parse_http_error(
        http_status=401,
        body=_problem_body(code="unauthorized", status=401),
    )
    assert isinstance(err, UnauthorizedError)
    assert isinstance(err, Cip309HttpError)
    # The legacy alias still resolves to the same class.
    assert isinstance(err, UnauthenticatedError)


def test_forbidden_and_csrf_invalid_both_map_to_forbidden_error() -> None:
    a = parse_http_error(
        http_status=403,
        body=_problem_body(code="forbidden", status=403),
    )
    b = parse_http_error(
        http_status=403,
        body=_problem_body(code="csrf-invalid", status=403),
    )
    assert isinstance(a, ForbiddenError)
    assert isinstance(b, ForbiddenError)
    assert b.code == "csrf-invalid"


def test_insufficient_scope_projects_required_and_granted_scopes() -> None:
    err = parse_http_error(
        http_status=403,
        body=_problem_body(
            code="insufficient-scope",
            status=403,
            required=["poe:create"],
            granted=["poe:read", "account:read"],
        ),
    )
    assert isinstance(err, InsufficientScopeError)
    assert err.required_scopes == ("poe:create",)
    assert err.granted_scopes == ("poe:read", "account:read")
    assert err.required_scope == "poe:create"


def test_insufficient_funds_projects_typed_bigint_usd_micro_fields() -> None:
    err = parse_http_error(
        http_status=402,
        body=_problem_body(
            code="insufficient-funds",
            status=402,
            balance_usd_micros="50000",
            required_usd_micros="180000",
            top_up_url="/billing/top-up",
        ),
    )
    assert isinstance(err, InsufficientFundsError)
    assert err.balance_usd_micros == 50_000
    assert err.required_usd_micros == 180_000
    assert err.top_up_url == "/billing/top-up"


def test_quote_expired_projects_quote_id() -> None:
    err = parse_http_error(
        http_status=410,
        body=_problem_body(
            code="quote-expired",
            status=410,
            quote_id="01956b41-7c00-7000-8000-000000000001",
        ),
    )
    assert isinstance(err, QuoteExpiredError)
    assert err.quote_id == "01956b41-7c00-7000-8000-000000000001"


def test_quote_already_consumed_projects_quote_id() -> None:
    err = parse_http_error(
        http_status=409,
        body=_problem_body(
            code="quote-already-consumed",
            status=409,
            quote_id="01956b41-7c00-7000-8000-000000000002",
        ),
    )
    assert isinstance(err, QuoteAlreadyConsumedError)
    assert err.quote_id == "01956b41-7c00-7000-8000-000000000002"


def test_quote_not_found_projects_quote_id() -> None:
    err = parse_http_error(
        http_status=404,
        body=_problem_body(
            code="quote-not-found",
            status=404,
            quote_id="01956b41-7c00-7000-8000-000000000003",
        ),
    )
    assert isinstance(err, QuoteNotFoundError)
    assert err.quote_id == "01956b41-7c00-7000-8000-000000000003"


def test_fx_stale_maps_to_service_unavailable() -> None:
    # A gateway that prices on a live FX oracle may surface a transient
    # ``fx-stale`` pricing outage; the vendor-neutral client surfaces it as the
    # generic service-unavailable condition (no FX-specific error class).
    err = parse_http_error(
        http_status=503,
        body=_problem_body(
            code="fx-stale",
            status=503,
            title="Service Unavailable",
            detail="Pricing temporarily unavailable.",
        ),
    )
    assert isinstance(err, ServiceUnavailableError)
    assert err.code == "fx-stale"


def test_not_found_and_record_not_found_dispatch_distinctly() -> None:
    generic = parse_http_error(
        http_status=404,
        body=_problem_body(code="not-found", status=404),
    )
    record = parse_http_error(
        http_status=404,
        body=_problem_body(code="record-not-found", status=404),
    )
    assert isinstance(generic, NotFoundError)
    assert isinstance(record, RecordNotFoundError)
    # The two are siblings — the generic 404 must NOT match RecordNotFoundError.
    assert not isinstance(generic, RecordNotFoundError)


def test_idempotency_key_conflict_maps_to_idempotency_conflict_error() -> None:
    err = parse_http_error(
        http_status=409,
        body=_problem_body(code="idempotency-key-conflict", status=409),
    )
    assert isinstance(err, IdempotencyConflictError)


def test_rate_limited_takes_retry_hint_from_header_not_body() -> None:
    err = parse_http_error(
        http_status=429,
        body=_problem_body(code="rate-limited", status=429),
        retry_after_seconds=7,
    )
    assert isinstance(err, RateLimitedError)
    assert err.retry_after_seconds == 7


def test_validation_failed_carries_errors_array() -> None:
    errors = [
        {
            "field": "items.0.hashes",
            "code": "invalid_type",
            "detail": "Expected object, got string",
        },
        {"field": "", "code": "custom", "detail": "Body-level rule failed"},
    ]
    err = parse_http_error(
        http_status=400,
        body=_problem_body(code="validation-failed", status=400, errors=errors),
    )
    assert isinstance(err, ValidationFailedError)
    assert err.errors == tuple(errors)


def test_invalid_body_maps_to_invalid_body_error() -> None:
    err = parse_http_error(
        http_status=400,
        body=_problem_body(code="invalid-body", status=400),
    )
    assert isinstance(err, InvalidBodyError)


def test_malformed_cbor_maps_to_malformed_cbor_error() -> None:
    err = parse_http_error(
        http_status=400,
        body=_problem_body(code="malformed-cbor", status=400),
    )
    assert isinstance(err, MalformedCborError)


def test_batch_too_large_projects_max_and_got() -> None:
    err = parse_http_error(
        http_status=400,
        body=_problem_body(code="batch-too-large", status=400, max=50, got=73),
    )
    assert isinstance(err, BatchTooLargeError)
    assert err.max == 50
    assert err.got == 73


def test_batch_empty_maps_to_batch_empty_error() -> None:
    err = parse_http_error(
        http_status=400,
        body=_problem_body(code="batch-empty", status=400),
    )
    assert isinstance(err, BatchEmptyError)


def test_internal_error_maps_to_internal_server_error() -> None:
    err = parse_http_error(
        http_status=500,
        body=_problem_body(code="internal-error", status=500),
    )
    assert isinstance(err, InternalServerError)


def test_service_unavailable_carries_retry_after_header() -> None:
    err = parse_http_error(
        http_status=503,
        body=_problem_body(code="service-unavailable", status=503),
        retry_after_seconds=30,
    )
    assert isinstance(err, ServiceUnavailableError)
    assert err.retry_after_seconds == 30


def test_unknown_code_falls_through_to_parent_with_verbatim_body() -> None:
    err = parse_http_error(
        http_status=451,
        body=_problem_body(code="unavailable-for-legal-reasons", status=451),
    )
    assert isinstance(err, Cip309HttpError)
    assert not isinstance(err, InternalServerError)
    assert err.code == "unavailable-for-legal-reasons"


def test_request_id_threaded_through_to_typed_subclass() -> None:
    err = parse_http_error(
        http_status=429,
        body=_problem_body(code="rate-limited", status=429),
        request_id="req-xyz",
        retry_after_seconds=1,
    )
    assert err.request_id == "req-xyz"


@pytest.mark.parametrize(
    "klass",
    [
        UnauthorizedError,
        ForbiddenError,
        NotFoundError,
        RecordNotFoundError,
        IdempotencyConflictError,
        MalformedCborError,
        InternalServerError,
        InsufficientFundsError,
        InsufficientScopeError,
        RateLimitedError,
        InvalidBodyError,
        ValidationFailedError,
        BatchTooLargeError,
        BatchEmptyError,
        ServiceUnavailableError,
        QuoteExpiredError,
        QuoteAlreadyConsumedError,
        QuoteNotFoundError,
    ],
)
def test_every_subclass_inherits_from_parent_and_exception(klass: type) -> None:
    problem = _problem_body(code="example", status=400)
    instance = klass(problem=problem)
    assert isinstance(instance, Exception)
    assert isinstance(instance, Cip309HttpError)
    assert isinstance(instance, klass)
