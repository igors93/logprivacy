from __future__ import annotations

import logging

import pytest

from logprivacy import (
    Cleaner,
    CleanerPolicy,
    LogBlockedError,
    LogPrivacyFilter,
    clean,
    clean_text,
    safe_print,
)


def _hash_policy() -> CleanerPolicy:
    return CleanerPolicy.default(masking="hash")


def _partial_policy() -> CleanerPolicy:
    return CleanerPolicy.default(masking="partial")


def test_generic_credential_uses_partial_masking() -> None:
    result = clean_text("password=super-secret-value", policy=_partial_policy())

    assert result.startswith("password=")
    assert "super-secret-value" not in result
    assert "*" in result
    assert "[SECRET]" not in result


def test_generic_credential_uses_hash_masking() -> None:
    first = clean_text("password=super-secret-value", policy=_hash_policy())
    second = clean_text("password=super-secret-value", policy=_hash_policy())
    different = clean_text("password=another-secret-value", policy=_hash_policy())

    assert first == second
    assert first != different
    assert first.startswith("password=[SECRET:")
    assert "super-secret-value" not in first


def test_authorization_and_bearer_tokens_use_concrete_masking() -> None:
    token = "abcdefgh1234567890"

    partial = clean_text(f"Authorization: Bearer {token}", policy=_partial_policy())
    hashed = clean_text(f"Authorization: Bearer {token}", policy=_hash_policy())

    assert partial.startswith("Authorization: Bearer ")
    assert hashed.startswith("Authorization: Bearer [TOKEN:")
    assert token not in partial
    assert token not in hashed
    assert "*" in partial


def test_standalone_bearer_and_jwt_use_concrete_masking() -> None:
    bearer = "Bearer abcdefgh1234567890"
    jwt = "eyJabcdefghijk.abcdefghijk.abcdefghijk"

    bearer_result = clean_text(bearer, policy=_hash_policy())
    jwt_result = clean_text(jwt, policy=_partial_policy())

    assert bearer_result.startswith("Bearer [TOKEN:")
    assert "abcdefgh1234567890" not in bearer_result
    assert jwt not in jwt_result
    assert "*" in jwt_result


def test_sensitive_mapping_values_use_partial_and_hash_masking() -> None:
    value = "super-secret-value"

    partial = clean({"password": value}, policy=_partial_policy())
    hashed = clean({"password": value}, policy=_hash_policy())

    assert partial["password"] != "[SECRET]"
    assert "*" in partial["password"]
    assert hashed["password"].startswith("[SECRET:")
    assert value not in partial["password"]
    assert value not in hashed["password"]


def test_sensitive_mapping_values_are_stable_and_distinct_under_hashing() -> None:
    first = clean({"password": "alpha-secret"}, policy=_hash_policy())
    again = clean({"password": "alpha-secret"}, policy=_hash_policy())
    different = clean({"password": "beta-secret"}, policy=_hash_policy())

    assert first == again
    assert first != different


def test_sensitive_arbitrary_objects_are_never_stringified() -> None:
    class MustNotBeRendered:
        def __str__(self) -> str:
            raise AssertionError("sensitive object must not be stringified")

        def __repr__(self) -> str:
            raise AssertionError("sensitive object must not be represented")

    result = clean({"password": MustNotBeRendered()}, policy=_hash_policy())

    assert result == {"password": "[SECRET]"}


def test_structured_cleaning_honors_production_blocking() -> None:
    with pytest.raises(LogBlockedError):
        clean({"password": "super-secret-value"}, policy=CleanerPolicy.production())


def test_logging_extra_uses_hash_masking() -> None:
    record = logging.LogRecord(
        name="secure",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="request",
        args=(),
        exc_info=None,
    )
    record.password = "super-secret-value"

    assert LogPrivacyFilter(cleaner=Cleaner(policy=_hash_policy())).filter(record) is True
    assert record.password.startswith("[SECRET:")
    assert "super-secret-value" not in record.password


def test_nested_logging_mapping_uses_partial_masking() -> None:
    record = logging.LogRecord(
        name="secure",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="request",
        args=(),
        exc_info=None,
    )
    record.payload = {"password": "super-secret-value"}

    assert LogPrivacyFilter(cleaner=Cleaner(policy=_partial_policy())).filter(record) is True
    assert "*" in record.payload["password"]
    assert record.payload["password"] != "[SECRET]"


def test_safe_print_uses_hash_masking_for_sensitive_mapping_values(
    capsys: pytest.CaptureFixture[str],
) -> None:
    safe_print({"password": "super-secret-value"}, policy=_hash_policy())

    output = capsys.readouterr().out
    assert "[SECRET:" in output
    assert "super-secret-value" not in output


def test_safe_print_does_not_stringify_sensitive_arbitrary_objects(
    capsys: pytest.CaptureFixture[str],
) -> None:
    class MustNotBeRendered:
        def __str__(self) -> str:
            raise AssertionError("sensitive object must not be stringified")

        def __repr__(self) -> str:
            raise AssertionError("sensitive object must not be represented")

    safe_print({"password": MustNotBeRendered()}, policy=_hash_policy())

    assert capsys.readouterr().out == "{'password': '[SECRET]'}\n"


def test_placeholder_behavior_remains_unchanged() -> None:
    assert clean_text("password=super-secret-value") == "password=[SECRET]"
    assert clean({"password": "super-secret-value"}) == {"password": "[SECRET]"}
