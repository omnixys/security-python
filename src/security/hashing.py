"""Argon2id password hashing with pepper support and timing-safe verify."""

from __future__ import annotations

import contextlib
from dataclasses import dataclass

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError


@dataclass(frozen=True, slots=True)
class HashOptions:
    memory_cost: int = 65536
    time_cost: int = 3
    parallelism: int = 1
    pepper: str = ""


_DUMMY_HASH = "$argon2id$v=19$m=65536,t=3,p=4$zD1JbPQISnVpD+aGRGYfmg$sLMMar7xev6VQAZft9tB+AJApi2BUbsjy2OaW0y1nNc"


class HashService:
    """Hash/verify values with Argon2id, mirroring the TypeScript `HashService`.

    A static ``pepper`` can be mixed into every input. ``verify`` never raises;
    it returns ``False`` for malformed hashes. ``dummy_verify`` performs a
    comparable dummy verification so callers cannot distinguish unknown users
    from wrong passwords by timing.
    """

    def __init__(self, options: HashOptions | None = None) -> None:
        opts = options or HashOptions()
        self._pepper = opts.pepper
        self._hasher = PasswordHasher(
            memory_cost=opts.memory_cost,
            time_cost=opts.time_cost,
            parallelism=opts.parallelism,
        )

    def hash(self, value: str) -> str:
        return self._hasher.hash(value + self._pepper)

    def verify(self, hashed: str, plain: str) -> bool:
        with contextlib.suppress(InvalidHashError, VerifyMismatchError, ValueError, TypeError):
            return self._hasher.verify(hashed, plain + self._pepper)
        return False

    def needs_rehash(self, hashed: str) -> bool:
        with contextlib.suppress(InvalidHashError, ValueError, TypeError):
            return self._hasher.check_needs_rehash(hashed)
        return False

    def dummy_verify(self) -> None:
        with contextlib.suppress(InvalidHashError, VerifyMismatchError, ValueError, TypeError):
            self._hasher.verify(_DUMMY_HASH, "dummy")
