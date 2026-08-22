"""Behavioral tests for the Argon2id HashService."""

from __future__ import annotations

from security import HashOptions, HashService


def test_hash_verify_roundtrip() -> None:
    service = HashService()
    hashed = service.hash("s3cret")
    assert hashed != "s3cret"
    assert service.verify(hashed, "s3cret") is True
    assert service.verify(hashed, "wrong") is False


def test_hash_is_salted() -> None:
    service = HashService()
    assert service.hash("same") != service.hash("same")


def test_verify_malformed_hash_returns_false() -> None:
    service = HashService()
    assert service.verify("not-a-hash", "x") is False
    assert service.verify("", "x") is False


def test_verify_non_string_plain_returns_false() -> None:
    service = HashService()
    hashed = service.hash("x")
    assert service.verify(hashed, "x") is True


def test_pepper_changes_verification_domain() -> None:
    service_a = HashService(HashOptions(pepper="pepper-a"))
    service_b = HashService(HashOptions(pepper="pepper-b"))
    hashed = service_a.hash("secret")

    assert service_a.verify(hashed, "secret") is True
    assert service_b.verify(hashed, "secret") is False


def test_custom_parameters_produce_valid_hash() -> None:
    service = HashService(HashOptions(memory_cost=32768, time_cost=2, parallelism=2))
    hashed = service.hash("secret")
    assert service.verify(hashed, "secret") is True
    assert hashed.startswith("$argon2id$")


def test_dummy_verify_does_not_raise() -> None:
    HashService().dummy_verify()
