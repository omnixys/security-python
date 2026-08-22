"""Behavioral tests for RateLimiter and RateLimitMiddleware."""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

import pytest

from security import RateLimiter, RateLimitMiddleware, RequestContext, current_request_context, set_request_context

if TYPE_CHECKING:
    from collections.abc import Iterator


class _FakeRedis:
    def __init__(self) -> None:
        self.values: dict[str, int] = {}

    async def incr(self, key: str) -> int:
        self.values[key] = self.values.get(key, 0) + 1
        return self.values[key]

    async def expire(self, key: str, _seconds: int) -> None:
        self.values.setdefault(key, self.values.get(key, 0))


async def _app(scope: dict, receive: object, send: object) -> None:
    return None


def test_is_allowed_until_limit() -> None:
    limiter = RateLimiter(_FakeRedis(), default_limit=2, default_window_ms=60000)
    assert asyncio.run(limiter.is_allowed("user:u1")) is True
    assert asyncio.run(limiter.is_allowed("user:u1")) is True
    assert asyncio.run(limiter.is_allowed("user:u1")) is False
    assert asyncio.run(limiter.is_allowed("user:u2")) is True


def test_is_allowed_respects_custom_limit() -> None:
    limiter = RateLimiter(_FakeRedis(), default_limit=5, default_window_ms=60000)
    assert asyncio.run(limiter.is_allowed("k", limit=1)) is True
    assert asyncio.run(limiter.is_allowed("k", limit=1)) is False


def test_key_builders() -> None:
    limiter = RateLimiter(_FakeRedis())
    assert asyncio.run(limiter.ip_key("10.0.0.1")) == "ip:10.0.0.1"
    assert asyncio.run(limiter.user_key("u1")) == "user:u1"
    assert asyncio.run(limiter.org_key("o1")) == "org:o1"


@pytest.fixture(autouse=True)
def _cleanup_context() -> Iterator[None]:
    yield
    from security import reset_request_context

    reset_request_context()


def _send_429(middleware: RateLimitMiddleware, scope: dict) -> list[dict]:
    sent: list[dict] = []

    async def _noop_receive() -> None:
        return None

    async def _noop_send(message: dict) -> None:
        sent.append(message)

    async def _run() -> None:
        await middleware(scope, _noop_receive, _noop_send)

    asyncio.run(_run())
    return sent


def _scope(path: str = "/events") -> dict:
    return {"type": "http", "path": path, "method": "GET", "headers": [], "client": ("10.0.0.5", 1234)}


def _limited_middleware(limiter: RateLimiter) -> RateLimitMiddleware:
    return RateLimitMiddleware(app=_app, limiter=limiter)


def test_middleware_blocks_when_ip_over_limit() -> None:
    limiter = RateLimiter(_FakeRedis(), default_limit=1, default_window_ms=60000)
    middleware = _limited_middleware(limiter)
    set_request_context(RequestContext(client_ip="10.0.0.5"))

    assert _send_429(middleware, _scope()) == []
    blocked = _send_429(middleware, _scope())
    assert len(blocked) == 2
    assert blocked[0]["status"] == 429


def test_middleware_blocks_when_user_over_limit() -> None:
    limiter = RateLimiter(_FakeRedis(), default_limit=1, default_window_ms=60000)
    middleware = _limited_middleware(limiter)
    set_request_context(RequestContext(user_id="u1"))

    _send_429(middleware, _scope())
    blocked = _send_429(middleware, _scope())
    assert len(blocked) == 2
    assert blocked[0]["status"] == 429


def test_middleware_excluded_path_never_limited() -> None:
    limiter = RateLimiter(_FakeRedis(), default_limit=0, default_window_ms=60000)
    middleware = _limited_middleware(limiter)
    set_request_context(RequestContext(client_ip="10.0.0.5"))

    assert _send_429(middleware, _scope("/health")) == []


def test_middleware_allows_when_no_context() -> None:
    middleware = _limited_middleware(RateLimiter(_FakeRedis(), default_limit=0, default_window_ms=60000))
    set_request_context(RequestContext())
    assert _send_429(middleware, _scope()) == []


def test_middleware_429_body() -> None:
    limiter = RateLimiter(_FakeRedis(), default_limit=0, default_window_ms=60000)
    middleware = _limited_middleware(limiter)
    set_request_context(RequestContext(client_ip="10.0.0.5"))

    blocked = _send_429(middleware, _scope())
    assert len(blocked) == 2
    assert b"rate_limit_exceeded" in blocked[1]["body"]
    assert blocked[0]["status"] == 429


def test_context_defaults_for_current() -> None:
    ctx = current_request_context()
    assert ctx.client_ip is None
    assert ctx.user_id is None
