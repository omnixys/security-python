"""Behavioral tests for JwtClaims and JwtValidator."""

from __future__ import annotations

import time

import pytest
from jose import jwt as jose_jwt

from security import JwtClaims, JwtValidator


class _PublicKey:
    def __init__(self, public_key: dict) -> None:
        self._public_key = public_key

    def to_dict(self) -> dict:
        return self._public_key


async def _make_validator(public_key: dict, *, audience: str | None = None) -> JwtValidator:
    validator = JwtValidator(
        jwks_url="https://example.test/jwks",
        issuer="https://example.test",
        audience=audience,
        cache_ttl_seconds=60,
    )
    validator._fetch_jwks = _fake_fetch_jwks  # type: ignore[method-assign]
    validator._cache.keys = [public_key]
    validator._cache.expires_at = time.time() + 60
    return validator


async def _fake_fetch_jwks(self) -> list[dict]:
    return list(self._cache.keys)


def _rsa_keys() -> tuple[dict, dict]:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from jose import jwk

    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")
    public_pem = private.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")

    public_jwk = jwk.RSAKey(public_pem, algorithm="RS256").to_dict()
    public_jwk["use"] = "sig"
    public_jwk["alg"] = "RS256"
    public_jwk["kid"] = "test-kid"
    return private_pem, public_jwk


def test_jwt_claims_parses_roles_scopes_and_expiry() -> None:
    now = int(time.time())
    claims = JwtClaims(
        sub="keycloak-sub-1",
        omnixys_user_id="user-U-1",
        exp=now + 60,
        realm_access={"roles": ["admin"]},
        scope="read write",
        tenant_ids=["t1"],
    )
    assert claims.user_id == "user-U-1"
    assert claims.roles == ["admin"]
    assert claims.scopes == ["read", "write"]
    assert claims.is_expired is False

    expired = JwtClaims(exp=now - 10)
    assert expired.is_expired is True


def test_jwt_claims_no_exp_or_roles() -> None:
    claims = JwtClaims()
    assert claims.is_expired is False
    assert claims.roles == []
    assert claims.scopes == []


async def test_validate_accepts_valid_token() -> None:
    private_jwk, public_jwk = _rsa_keys()
    token = jose_jwt.encode(
        {
            "sub": "keycloak-sub-1",
            "omnixys_user_id": "user-U-1",
            "iss": "https://example.test",
            "exp": int(time.time()) + 60,
        },
        private_jwk,
        algorithm="RS256",
        headers={"kid": "test-kid"},
    )
    validator = await _make_validator(public_jwk)
    claims = await validator.validate(token)
    assert claims.user_id == "user-U-1"


async def test_validate_rejects_token_from_wrong_key() -> None:
    private_jwk, public_jwk = _rsa_keys()
    other_private, _ = _rsa_keys()
    token = jose_jwt.encode(
        {"sub": "user-1", "iss": "https://example.test", "exp": int(time.time()) + 60},
        other_private,
        algorithm="RS256",
    )
    validator = await _make_validator(public_jwk)
    with pytest.raises(ValueError):
        await validator.validate(token)


async def test_validate_rejects_expired_token() -> None:
    private_jwk, public_jwk = _rsa_keys()
    token = jose_jwt.encode(
        {"sub": "user-1", "iss": "https://example.test", "exp": int(time.time()) - 60},
        private_jwk,
        algorithm="RS256",
    )
    validator = await _make_validator(public_jwk)
    with pytest.raises(ValueError):
        await validator.validate(token)


async def test_validate_rejects_garbage_token() -> None:
    validator = await _make_validator({})
    with pytest.raises(ValueError):
        await validator.validate("not.a.jwt")


async def test_validate_verifies_audience() -> None:
    private_jwk, public_jwk = _rsa_keys()
    token = jose_jwt.encode(
        {
            "sub": "user-1",
            "iss": "https://example.test",
            "aud": "wrong-audience",
            "exp": int(time.time()) + 60,
        },
        private_jwk,
        algorithm="RS256",
    )
    validator = await _make_validator(public_jwk, audience="expected-audience")
    with pytest.raises(ValueError):
        await validator.validate(token)
