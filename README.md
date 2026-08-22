# omnixys-security

Shared security toolkit for Omnixys services: JWT validation against a JWKS
endpoint, pluggable ASGI middleware, per-request context, rate limiting, and
timing-safe Argon2id password hashing.

## Installation

```bash
pip install omnixys-security
```

## Features

- **JwtValidator** — validates RS256 JWTs against a remote JWKS with in-memory caching, issuer and audience checks.
- **SecurityMiddleware** — ASGI middleware that resolves the request context from a bearer token or internal API key.
- **RequestContext** — typed, context-local request metadata (user, roles, tenant, request/correlation id, client IP).
- **RateLimiter / RateLimitMiddleware** — fixed-window Redis-backed rate limiting by IP, user, and tenant.
- **HashService** — Argon2id password hashing with optional pepper and timing-safe `dummy_verify`.
- **SecurityError hierarchy** — typed exceptions with stable codes for authz failures, expired tokens, tenant errors.

## Quick start

```python
from security import JwtValidator, SecurityMiddleware, RateLimitMiddleware, RateLimiter

jwt_validator = JwtValidator(
    jwks_url="https://auth.omnixys.com/.well-known/jwks.json",
    issuer="https://auth.omnixys.com/realms/omnixys",
    audience="omnixys-api",
)

redis = redis.asyncio.from_url("redis://localhost:6379")
limiter = RateLimiter(redis, default_limit=120, default_window_ms=60000)

app = SecurityMiddleware(
    app=my_asgi_app,
    jwt_validator=jwt_validator,
    internal_api_key=os.getenv("INTERNAL_API_KEY"),
)
app = RateLimitMiddleware(app=app, limiter=limiter)
```

## Request context

Within a handled request you can read the resolved identity at any point:

```python
from security import current_request_context

async def handler():
    ctx = current_request_context()
    if ctx.user_id and "admin" in ctx.roles:
        await do_admin_thing(ctx.tenant_id)
    else:
        raise AccessDeniedError()
```

`RequestContext` carries `user_id`, `username`, `email`, `first_name`,
`last_name`, `roles`, `scopes`, `tenant_ids`, `tenant_id` (pinned via the
`x-tenant-id` header when it is contained in the token), `correlation_id`,
`request_id`, `client_ip`, `is_authenticated`, and `is_internal`.

The middleware always resets the context after the request, so stale identity
never leaks between requests.

## JWT validation

```python
from security import JwtValidator

validator = JwtValidator(
    jwks_url="...",
    issuer="...",
    audience="...",
    cache_ttl_seconds=900,
)

claims = await validator.validate(token)
assert claims.user_id == claims.sub
assert claims.roles == ["admin"]
```

`validate` raises `ValueError` when the token is invalid, expired, from a
different issuer, or signed by an unknown key. JWKS responses are cached for
`cache_ttl_seconds` to avoid a fetch per request.

## Rate limiting

```python
from security import RateLimiter, RateLimitMiddleware

limiter = RateLimiter(redis, default_limit=120, default_window_ms=60000)

async def view():
    if not await limiter.is_allowed(await limiter.user_key(ctx.user_id)):
        return json_response({"error": "rate_limit_exceeded"}, status=429)
```

`RateLimitMiddleware` checks IP, then user, then tenant (in that order) and
responds `429 {"error":"rate_limit_exceeded"}` when a limit is hit. Paths such
as `/health` and `/metrics` are excluded by default and never limited.

## Password hashing

```python
from security import HashOptions, HashService

service = HashService(HashOptions(pepper=os.getenv("PEPPER", "")))

stored = service.hash(password)          # $argon2id$...
ok = service.verify(stored, password)    # never raises
needs_upgrade = service.needs_rehash(stored)

# call for unknown users to equalize timing with known-user lookups
service.dummy_verify()
```

## Errors

All domain errors subclass `SecurityError` and carry a stable `code`:

```python
from security import AccessDeniedError, InvalidCredentialsError

try:
    authorize(ctx, "events.write")
except AccessDeniedError as exc:
    print(exc.code, exc.to_dict())
```

The hierarchy includes `TokenInvalidError`, `InvalidCredentialsError`,
`RefreshTokenExpiredError`, `AccessDeniedError`, `EventAccessDeniedError`,
`TenantNotFoundError`, `TenantDisabledError`,
`TenantMembershipNotFoundError`, and `TenantMembershipInactiveError`.

## Development

```bash
uv sync
uv run pytest -q
uv run ruff check .
uv run mypy src/
```

## License

GPL-3.0-or-later
