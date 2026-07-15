from __future__ import annotations

from contextvars import ContextVar
from dataclasses import dataclass, field


@dataclass
class RequestContext:
    user_id: str | None = None
    username: str | None = None
    email: str | None = None
    first_name: str | None = None
    last_name: str | None = None
    roles: list[str] = field(default_factory=list)
    scopes: list[str] = field(default_factory=list)
    organization_id: str | None = None
    tenant_id: str | None = None
    correlation_id: str | None = None
    request_id: str | None = None
    client_ip: str | None = None
    is_authenticated: bool = False
    is_internal: bool = False


_request_context_var: ContextVar[RequestContext | None] = ContextVar("request_context", default=None)


def current_request_context() -> RequestContext:
    ctx = _request_context_var.get()
    if ctx is None:
        ctx = RequestContext()
        _request_context_var.set(ctx)
    return ctx


def set_request_context(ctx: RequestContext) -> None:
    _request_context_var.set(ctx)


def reset_request_context() -> None:
    _request_context_var.set(None)
