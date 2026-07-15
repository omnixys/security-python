"""Smoke test - verifies omnixys-security can be imported."""

from __future__ import annotations

import importlib



def test_package_importable() -> None:
    mod = importlib.import_module("omnixys_security")
    assert hasattr(mod, "__version__")
    assert mod.__version__ == "1.0.0"


def test_public_api() -> None:
    from omnixys_security import jwt_validator, middleware, request_context

    assert jwt_validator is not None
    assert middleware is not None
    assert request_context is not None
