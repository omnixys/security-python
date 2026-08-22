"""Behavioral tests for security exceptions and request context."""

from __future__ import annotations

from security import (
    AccessDeniedError,
    EventAccessDeniedError,
    InvalidCredentialsError,
    RefreshTokenExpiredError,
    RequestContext,
    SecurityError,
    TenantDisabledError,
    TenantMembershipInactiveError,
    TenantMembershipNotFoundError,
    TenantNotFoundError,
    TokenInvalidError,
    current_request_context,
    reset_request_context,
    set_request_context,
)


def test_security_error_carries_code_and_metadata() -> None:
    exc = InvalidCredentialsError(
        "bad password",
        metadata={"provider": "email"},
        request_id="r1",
    )
    assert exc.code == "INVALID_CREDENTIALS"
    assert exc.message == "bad password"
    assert exc.metadata == {"provider": "email"}
    assert exc.request_id == "r1"
    assert str(exc) == "bad password"


def test_security_error_default_message() -> None:
    assert AccessDeniedError().message == "Access denied"
    assert RefreshTokenExpiredError().code == "REFRESH_TOKEN_EXPIRED"
    assert TokenInvalidError().code == "TOKEN_INVALID"


def test_to_dict_wire_shape() -> None:
    exc = EventAccessDeniedError(metadata={"eventId": "e1"})
    assert exc.to_dict() == {
        "code": "EVENT_ACCESS_DENIED",
        "message": "Access to this event is denied",
        "metadata": {"eventId": "e1"},
    }


def test_tenant_error_codes() -> None:
    assert TenantNotFoundError().code == "TENANT_NOT_FOUND"
    assert TenantDisabledError().code == "TENANT_DISABLED"
    assert TenantMembershipNotFoundError().code == "TENANT_MEMBERSHIP_NOT_FOUND"
    assert TenantMembershipInactiveError().code == "TENANT_MEMBERSHIP_INACTIVE"


def test_security_error_is_an_exception() -> None:
    try:
        raise TenantDisabledError()
    except SecurityError as exc:
        assert exc.code == "TENANT_DISABLED"


def test_request_context_defaults() -> None:
    ctx = RequestContext()
    assert ctx.is_authenticated is False
    assert ctx.is_internal is False
    assert ctx.roles == []
    assert ctx.scopes == []
    assert ctx.tenant_ids == []


def test_request_context_contextvar_roundtrip() -> None:
    reset_request_context()
    assert current_request_context().user_id is None

    ctx = RequestContext(user_id="u1", tenant_id="t1")
    set_request_context(ctx)
    assert current_request_context().user_id == "u1"
    assert current_request_context().tenant_id == "t1"

    reset_request_context()
    assert current_request_context().user_id is None
