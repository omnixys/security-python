"""Behavioral tests for the ASGI SecurityMiddleware."""

from __future__ import annotations

import asyncio
import copy
from collections.abc import Iterator
from typing import Any

import pytest

from security import (
    JwtClaims,
    RequestContext,
    SecurityMiddleware,
    current_request_context,
    reset_request_context,
)


class _FakeJwtValidator:
    def __init__(self, claims: JwtClaims | None = None) -> None:
        self._claims = claims

    async def validate(self, token: str) -> JwtClaims:
        if self._claims is None:
            raise ValueError("invalid token")
        return self._claims


def _capturing_app(scope: dict[str, Any], receive: object, send: object) -> Any:
    async def _inner() -> None:
        return None

    return _inner()


@pytest.fixture(autouse=True)
def _cleanup_context() -> Iterator[None]:
    reset_request_context()
    yield
    reset_request_context()


def _run(
    middleware: SecurityMiddleware,
    path: str,
    headers: list[tuple[bytes, bytes]] | None = None,
) -> RequestContext:
    snapshot: dict[str, RequestContext] = {}
    original_app = middleware.app

    async def app(scope: dict[str, Any], receive: object, send: object) -> None:
        snapshot["ctx"] = copy.copy(current_request_context())
        await original_app(scope, receive, send)

    middleware.app = app
    try:
        async def _noop_receive() -> None:
            return None

        async def _noop_send(message: dict) -> None:
            return None

        scope = {
            "type": "http",
            "path": path,
            "method": "GET",
            "headers": headers or [],
            "client": ("10.0.0.5", 1234),
        }
        asyncio.run(middleware(scope, _noop_receive, _noop_send))
    finally:
        middleware.app = original_app
    return snapshot["ctx"]


def test_excluded_path_passes_through_without_validation() -> None:
    middleware = SecurityMiddleware(app=_capturing_app, jwt_validator=_FakeJwtValidator())
    ctx = _run(middleware, "/health")
    assert ctx.is_authenticated is False


def test_internal_api_key_sets_internal_context() -> None:
    middleware = SecurityMiddleware(
        app=_capturing_app,
        jwt_validator=_FakeJwtValidator(),
        internal_api_key="internal-key",
    )
    ctx = _run(middleware, "/events", [(b"authorization", b"Bearer internal-key")])
    assert ctx.is_internal is True
    assert ctx.is_authenticated is True


def test_invalid_jwt_leaves_unauthenticated() -> None:
    middleware = SecurityMiddleware(app=_capturing_app, jwt_validator=_FakeJwtValidator())
    ctx = _run(middleware, "/events", [(b"authorization", b"Bearer bad-token")])
    assert ctx.is_authenticated is False
    assert ctx.user_id is None
    assert ctx.client_ip == "10.0.0.5"


def test_valid_jwt_populates_context() -> None:
    claims = JwtClaims(
        sub="u1",
        preferred_username="ada",
        email="ada@example.com",
        roles=["admin"],
        realm_access={"roles": ["admin"]},
        tenant_ids=["t1", "t2"],
    )
    middleware = SecurityMiddleware(app=_capturing_app, jwt_validator=_FakeJwtValidator(claims))
    ctx = _run(middleware, "/events", [(b"authorization", b"Bearer valid-token"), (b"x-tenant-id", b"t2")])
    assert ctx.is_authenticated is True
    assert ctx.user_id == "u1"
    assert ctx.username == "ada"
    assert ctx.email == "ada@example.com"
    assert ctx.roles == ["admin"]
    assert ctx.tenant_id == "t2"
    assert ctx.client_ip == "10.0.0.5"


def test_tenant_header_outside_tenant_ids_is_ignored() -> None:
    claims = JwtClaims(tenant_ids=["t1"])
    middleware = SecurityMiddleware(app=_capturing_app, jwt_validator=_FakeJwtValidator(claims))
    ctx = _run(middleware, "/events", [(b"authorization", b"Bearer valid-token"), (b"x-tenant-id", b"t-other")])
    assert ctx.tenant_id is None


def test_request_and_correlation_ids_propagate() -> None:
    claims = JwtClaims(sub="u1")
    middleware = SecurityMiddleware(app=_capturing_app, jwt_validator=_FakeJwtValidator(claims))
    ctx = _run(
        middleware,
        "/events",
        [(b"authorization", b"Bearer valid-token"), (b"x-request-id", b"req-1"), (b"x-correlation-id", b"corr-1")],
    )
    assert ctx.request_id == "req-1"
    assert ctx.correlation_id == "corr-1"


def test_context_reset_after_request() -> None:
    claims = JwtClaims(sub="u1")
    middleware = SecurityMiddleware(app=_capturing_app, jwt_validator=_FakeJwtValidator(claims))
    ctx = _run(middleware, "/events", [(b"authorization", b"Bearer valid-token")])
    assert ctx.user_id == "u1"
    assert current_request_context().user_id is None
