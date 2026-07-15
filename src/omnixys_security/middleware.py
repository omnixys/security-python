from __future__ import annotations

from typing import TYPE_CHECKING, Any

from omnixys_security.request_context import RequestContext, reset_request_context, set_request_context

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

    from omnixys_security.jwt_validator import JwtClaims, JwtValidator


class SecurityMiddleware:
    def __init__(
        self,
        app: Callable[..., Awaitable[Any]],
        jwt_validator: JwtValidator,
        *,
        exclude_paths: list[str] | None = None,
        internal_api_key: str | None = None,
    ) -> None:
        self.app = app
        self._jwt_validator = jwt_validator
        self._exclude_paths = exclude_paths or ["/health", "/metrics", "/favicon.ico"]
        self._internal_api_key = internal_api_key

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

        headers = dict(scope.get("headers", []))
        ctx = RequestContext()

        if await self._try_internal(headers, ctx):
            set_request_context(ctx)
            try:
                await self.app(scope, receive, send)
            finally:
                reset_request_context()
            return

        await self._resolve_jwt(headers, ctx)
        self._resolve_headers(headers, ctx)
        self._resolve_client_ip(headers, scope, ctx)

        set_request_context(ctx)
        try:
            await self.app(scope, receive, send)
        finally:
            reset_request_context()

    async def _try_internal(self, headers: dict[bytes, bytes], ctx: RequestContext) -> bool:
        if not self._internal_api_key:
            return False
        auth_header = headers.get(b"authorization", b"").decode()
        if auth_header == f"Bearer {self._internal_api_key}":
            ctx.is_internal = True
            ctx.is_authenticated = True
            return True
        return False

    async def _resolve_jwt(self, headers: dict[bytes, bytes], ctx: RequestContext) -> None:
        auth_header = headers.get(b"authorization", b"").decode()
        if not auth_header.startswith("Bearer "):
            return
        token = auth_header[7:]
        try:
            claims: JwtClaims = await self._jwt_validator.validate(token)
            ctx.user_id = claims.user_id
            ctx.username = claims.preferred_username
            ctx.email = claims.email
            ctx.first_name = claims.given_name
            ctx.last_name = claims.family_name
            ctx.roles = claims.roles
            ctx.scopes = claims.scopes
            ctx.organization_id = claims.organization_id
            ctx.tenant_id = claims.tenant_id
            ctx.is_authenticated = True
        except ValueError:
            pass

    @staticmethod
    def _resolve_headers(headers: dict[bytes, bytes], ctx: RequestContext) -> None:
        correlation_id = headers.get(b"x-correlation-id", b"").decode()
        request_id = headers.get(b"x-request-id", b"").decode()
        ctx.correlation_id = correlation_id or None
        ctx.request_id = request_id or None

    @staticmethod
    def _resolve_client_ip(headers: dict[bytes, bytes], scope: dict[str, Any], ctx: RequestContext) -> None:
        forwarded = headers.get(b"x-forwarded-for", b"").decode()
        client_ip = forwarded.split(",")[0].strip()
        if not client_ip:
            client = scope.get("client", (None, None))[0]
            client_ip = client or ""
        ctx.client_ip = client_ip or None
