from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import cast

import httpx
from jose import jwt as jose_jwt
from jose.exceptions import JWTError
from pydantic import BaseModel, ConfigDict


class JwtClaims(BaseModel):
    model_config = ConfigDict(extra="allow")
    sub: str | None = None
    iss: str | None = None
    aud: str | list[str] | None = None
    exp: int | None = None
    iat: int | None = None
    preferred_username: str | None = None
    email: str | None = None
    given_name: str | None = None
    family_name: str | None = None
    realm_access: dict[str, list[str]] | None = None
    resource_access: dict[str, dict[str, list[str]]] | None = None
    organization_id: str | None = None
    tenant_id: str | None = None
    scope: str | None = None
    azp: str | None = None
    jti: str | None = None

    @property
    def user_id(self) -> str | None:
        return self.sub

    @property
    def roles(self) -> list[str]:
        if self.realm_access:
            return self.realm_access.get("roles", [])
        return []

    @property
    def scopes(self) -> list[str]:
        return self.scope.split() if self.scope else []

    @property
    def is_expired(self) -> bool:
        if self.exp is None:
            return False
        return time.time() > self.exp


@dataclass
class CachedJwks:
    keys: list[dict[str, object]] = field(default_factory=list)
    expires_at: float = 0.0


class JwtValidator:
    def __init__(
        self,
        jwks_url: str,
        issuer: str,
        audience: str | None = None,
        cache_ttl_seconds: int = 900,
    ) -> None:
        self._jwks_url = jwks_url
        self._issuer = issuer
        self._audience = audience
        self._cache_ttl = cache_ttl_seconds
        self._cache: CachedJwks = CachedJwks()

    async def _fetch_jwks(self) -> list[dict[str, object]]:
        async with httpx.AsyncClient() as client:
            resp = await client.get(self._jwks_url, timeout=10)
            resp.raise_for_status()
            data = cast("dict[str, object]", resp.json())
            keys = cast("list[dict[str, object]]", data.get("keys", []))
            return keys

    async def _get_jwks(self) -> list[dict[str, object]]:
        if time.time() >= self._cache.expires_at:
            self._cache.keys = await self._fetch_jwks()
            self._cache.expires_at = time.time() + self._cache_ttl
        return self._cache.keys

    async def validate(self, token: str) -> JwtClaims:
        keys = await self._get_jwks()

        for key in keys:
            try:
                payload = jose_jwt.decode(
                    token,
                    key,
                    algorithms=["RS256"],
                    issuer=self._issuer,
                    audience=self._audience,
                    options={"verify_exp": True},
                )
                return JwtClaims(**payload)
            except JWTError:
                continue

        msg = "Token validation failed: no matching key or invalid token"
        raise ValueError(msg)
