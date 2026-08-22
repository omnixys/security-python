"""Security exceptions with stable machine-readable codes.

Mirrors the TypeScript security error shape: every exception carries a
``code`` (the same vocabulary as the contracts `ErrorCode`), an optional
``metadata`` payload, and exposes a ``to_dict()`` wire form.
"""

from __future__ import annotations

from typing import Any


class SecurityError(Exception):
    code: str = "SECURITY_ERROR"
    default_message: str = "Security error"

    def __init__(
        self,
        message: str | None = None,
        *,
        metadata: dict[str, Any] | None = None,
        request_id: str | None = None,
        correlation_id: str | None = None,
    ) -> None:
        self.message = message or self.default_message
        self.metadata = metadata or {}
        self.request_id = request_id
        self.correlation_id = correlation_id
        super().__init__(self.message)

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "message": self.message,
            "metadata": self.metadata,
        }


class InvalidCredentialsError(SecurityError):
    code = "INVALID_CREDENTIALS"
    default_message = "Invalid credentials"


class RefreshTokenExpiredError(SecurityError):
    code = "REFRESH_TOKEN_EXPIRED"
    default_message = "Refresh token has expired"


class TokenInvalidError(SecurityError):
    code = "TOKEN_INVALID"
    default_message = "Token is invalid"


class AccessDeniedError(SecurityError):
    code = "ACCESS_DENIED"
    default_message = "Access denied"


class EventAccessDeniedError(SecurityError):
    code = "EVENT_ACCESS_DENIED"
    default_message = "Access to this event is denied"


class TenantNotFoundError(SecurityError):
    code = "TENANT_NOT_FOUND"
    default_message = "Tenant not found"


class TenantDisabledError(SecurityError):
    code = "TENANT_DISABLED"
    default_message = "Tenant is disabled"


class TenantMembershipNotFoundError(SecurityError):
    code = "TENANT_MEMBERSHIP_NOT_FOUND"
    default_message = "User is not a member of this tenant"


class TenantMembershipInactiveError(SecurityError):
    code = "TENANT_MEMBERSHIP_INACTIVE"
    default_message = "Tenant membership is inactive"
