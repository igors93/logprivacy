from __future__ import annotations

import pytest

from logprivacy import CleanerPolicy, LogBlockedError, safe_print


class UnsafeObject:
    def __str__(self) -> str:
        return "owner=john@example.com password=secret123"

    def __repr__(self) -> str:
        return "UnsafeObject(email=john@example.com, password=secret123)"


def test_safe_print_cleans_unknown_top_level_object(capsys: pytest.CaptureFixture[str]) -> None:
    safe_print(UnsafeObject())

    output = capsys.readouterr().out
    assert output == "owner=[EMAIL] password=[SECRET]\n"
    assert "john@example.com" not in output
    assert "secret123" not in output


def test_safe_print_cleans_unknown_objects_inside_containers(
    capsys: pytest.CaptureFixture[str],
) -> None:
    safe_print([UnsafeObject()], {"payload": UnsafeObject()})

    output = capsys.readouterr().out
    assert "john@example.com" not in output
    assert "secret123" not in output
    assert "owner=[EMAIL] password=[SECRET]" in output


def test_safe_print_cleans_unknown_objects_inside_sets(
    capsys: pytest.CaptureFixture[str],
) -> None:
    safe_print({UnsafeObject()}, frozenset({UnsafeObject()}))

    output = capsys.readouterr().out
    assert "john@example.com" not in output
    assert "secret123" not in output
    assert "owner=[EMAIL] password=[SECRET]" in output


def test_safe_print_masks_sensitive_mapping_values_without_stringifying_them(
    capsys: pytest.CaptureFixture[str],
) -> None:
    class MustNotBeRendered:
        def __str__(self) -> str:
            raise AssertionError("sensitive values must be masked before rendering")

    safe_print({"password": MustNotBeRendered()})

    assert capsys.readouterr().out == "{'password': '[SECRET]'}\n"


def test_safe_print_handles_recursive_containers(capsys: pytest.CaptureFixture[str]) -> None:
    recursive: list[object] = ["john@example.com"]
    recursive.append(recursive)

    safe_print(recursive)

    output = capsys.readouterr().out
    assert output == "['[EMAIL]', [...]]\n"
    assert "john@example.com" not in output


def test_safe_print_cleans_bytes(capsys: pytest.CaptureFixture[str]) -> None:
    safe_print(b"email=john@example.com password=secret123")

    assert capsys.readouterr().out == "email=[EMAIL] password=[SECRET]\n"


def test_safe_print_cleans_separator_and_end(capsys: pytest.CaptureFixture[str]) -> None:
    safe_print(
        "left",
        "right",
        sep=" john@example.com ",
        end=" password=secret123\n",
    )

    assert capsys.readouterr().out == "left [EMAIL] right password=[SECRET]\n"


def test_safe_print_preserves_existing_structured_output(
    capsys: pytest.CaptureFixture[str],
) -> None:
    safe_print("token=abc123456789", {"password": "123456"})

    assert capsys.readouterr().out == "token=[SECRET] {'password': '[SECRET]'}\n"


def test_safe_print_honors_production_blocking_for_sensitive_mapping_keys() -> None:
    with pytest.raises(LogBlockedError):
        safe_print({"password": "plain-value"}, policy=CleanerPolicy.production())


def test_safe_print_replaces_unprintable_objects(capsys: pytest.CaptureFixture[str]) -> None:
    class BrokenObject:
        def __str__(self) -> str:
            raise ValueError("conversion failed")

    safe_print(BrokenObject())

    assert capsys.readouterr().out == "<unprintable BrokenObject>\n"
