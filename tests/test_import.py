"""Smoke test - verifies omnixys-security can be imported."""

from __future__ import annotations

import importlib
from importlib.metadata import version as pkg_version


def test_package_importable() -> None:
    mod = importlib.import_module("security")
    assert hasattr(mod, "__version__")
    assert mod.__version__ == pkg_version("omnixys-security")


def test_public_api() -> None:
    from security import jwt_validator, middleware, request_context

    assert jwt_validator is not None
    assert middleware is not None
    assert request_context is not None
