from __future__ import annotations

import time
from typing import TYPE_CHECKING, Any

from omnixys_security.request_context import current_request_context

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable


class RateLimiter:
    def __init__(self, redis_client: Any, default_limit: int = 120, default_window_ms: int = 60000) -> None:
        self._redis = redis_client
        self._default_limit = default_limit
        self._default_window_ms = default_window_ms

    async def is_allowed(self, key: str, limit: int | None = None, window_ms: int | None = None) -> bool:
        limit = limit or self._default_limit
        window_ms = window_ms or self._default_window_ms
        window_sec = window_ms / 1000.0
        now = time.time()
        window_start = int(now // window_sec) * int(window_sec)

        redis_key = f"ratelimit:{key}:{int(window_start)}"
        count: int | None = await self._redis.incr(redis_key)
        if count is None:
            return True
        if count == 1:
            await self._redis.expire(redis_key, int(window_sec) + 1)
        return count <= limit

    async def ip_key(self, client_ip: str) -> str:
        return f"ip:{client_ip}"

    async def user_key(self, user_id: str) -> str:
        return f"user:{user_id}"

    async def org_key(self, org_id: str) -> str:
        return f"org:{org_id}"


class RateLimitMiddleware:
    def __init__(
        self,
        app: Callable[..., Awaitable[Any]],
        limiter: RateLimiter,
        *,
        exclude_paths: list[str] | None = None,
    ) -> None:
        self.app = app
        self._limiter = limiter
        self._exclude_paths = exclude_paths or ["/health", "/metrics", "/favicon.ico"]

    async def __call__(
        self,
        scope: dict[str, Any],
        receive: Callable[[], Awaitable[Any]],
        send: Callable[[dict[str, Any]], Awaitable[None]],
    ) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "")
        if any(path.startswith(ex) for ex in self._exclude_paths):
            await self.app(scope, receive, send)
            return

        ctx = current_request_context()

        if ctx.client_ip and not await self._limiter.is_allowed(await self._limiter.ip_key(ctx.client_ip)):
            await self._send_429(send)
            return

        if ctx.user_id and not await self._limiter.is_allowed(await self._limiter.user_key(ctx.user_id)):
            await self._send_429(send)
            return

        if ctx.organization_id and not await self._limiter.is_allowed(await self._limiter.org_key(ctx.organization_id)):
            await self._send_429(send)
            return

        await self.app(scope, receive, send)

    async def _send_429(self, send: Callable[[dict[str, Any]], Awaitable[None]]) -> None:
        body = b'{"error":"rate_limit_exceeded","message":"Too many requests"}'
        await send({
            "type": "http.response.start",
            "status": 429,
            "headers": [(b"content-type", b"application/json")],
        })
        await send({
            "type": "http.response.body",
            "body": body,
        })
