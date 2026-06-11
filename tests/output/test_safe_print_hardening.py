from __future__ import annotations

import io
from collections.abc import Iterator, Mapping, Sequence
from typing import Any

import pytest

from logprivacy import safe_print


class UnsafeInt(int):
    def __repr__(self) -> str:
        return "password=super-secret"

    def __str__(self) -> str:
        return "token=abcdefgh12345678"


def test_safe_print_does_not_trust_numeric_subclass_repr(
    capsys: pytest.CaptureFixture[str],
) -> None:
    safe_print(UnsafeInt(42), [UnsafeInt(7)])

    output = capsys.readouterr().out
    assert "super-secret" not in output
    assert "abcdefgh12345678" not in output
    assert "token=[SECRET]" in output


def test_safe_print_keeps_large_range_compact(capsys: pytest.CaptureFixture[str]) -> None:
    safe_print(range(1_000_000_000))

    assert capsys.readouterr().out == "range(0, 1000000000)\n"


def test_safe_print_truncates_large_containers_by_item_limit(
    capsys: pytest.CaptureFixture[str],
) -> None:
    safe_print(list(range(1_000)), max_items=3)

    output = capsys.readouterr().out
    assert output == "[0, 1, 2, ...]\n"
    assert "999" not in output


def test_safe_print_enforces_global_character_limit(
    capsys: pytest.CaptureFixture[str],
) -> None:
    safe_print("x" * 10_000, max_chars=40)

    output = capsys.readouterr().out
    assert len(output.removesuffix("\n")) <= 40
    assert output.endswith("...\n")


def test_mapping_key_is_stringified_only_once(
    capsys: pytest.CaptureFixture[str],
) -> None:
    class StatefulKey:
        calls = 0

        def __hash__(self) -> int:
            return 1

        def __eq__(self, other: object) -> bool:
            return self is other

        def __str__(self) -> str:
            self.calls += 1
            return "password"

    key = StatefulKey()
    safe_print({key: "must-never-appear"})

    output = capsys.readouterr().out
    assert key.calls == 1
    assert "must-never-appear" not in output
    assert "[SECRET]" in output


def test_broken_sequence_fails_closed(capsys: pytest.CaptureFixture[str]) -> None:
    class BrokenSequence(Sequence[object]):
        def __len__(self) -> int:
            return 1

        def __getitem__(self, index: int) -> object:
            raise RuntimeError("password=super-secret")

        def __iter__(self) -> Iterator[object]:
            raise RuntimeError("password=super-secret")

    safe_print(BrokenSequence())

    output = capsys.readouterr().out
    assert "super-secret" not in output
    assert output == "<unrenderable BrokenSequence>\n"


def test_broken_mapping_fails_closed(capsys: pytest.CaptureFixture[str]) -> None:
    class BrokenMapping(Mapping[str, str]):
        def __getitem__(self, key: str) -> str:
            raise KeyError(key)

        def __iter__(self) -> Iterator[str]:
            return iter(())

        def __len__(self) -> int:
            return 0

        def items(self) -> Any:
            raise RuntimeError("token=abcdefgh12345678")

    safe_print(BrokenMapping())

    output = capsys.readouterr().out
    assert "abcdefgh12345678" not in output
    assert output == "<unrenderable BrokenMapping>\n"


def test_safe_print_neutralizes_terminal_control_characters(
    capsys: pytest.CaptureFixture[str],
) -> None:
    safe_print("\x1b[2J password=secret\rnext\u202e")

    output = capsys.readouterr().out
    assert "\x1b" not in output
    assert "\r" not in output
    assert "\u202e" not in output
    assert output == "\\x1b[2J password=[SECRET]\\x0dnext\\u202e\n"


def test_safe_print_supports_file_and_flush() -> None:
    class FlushTrackingBuffer(io.StringIO):
        flush_count = 0

        def flush(self) -> None:
            self.flush_count += 1
            super().flush()

    target = FlushTrackingBuffer()
    safe_print("john@example.com", file=target, flush=True)

    assert target.getvalue() == "[EMAIL]\n"
    assert target.flush_count == 1


def test_safe_print_accepts_none_separator_and_end() -> None:
    target = io.StringIO()
    safe_print("left", "right", sep=None, end=None, file=target)

    assert target.getvalue() == "left right\n"


@pytest.mark.parametrize(
    ("kwargs", "parameter"),
    [
        ({"max_items": 0}, "max_items"),
        ({"max_chars": 0}, "max_chars"),
        ({"max_items": True}, "max_items"),
    ],
)
def test_safe_print_rejects_invalid_limits(
    kwargs: dict[str, object],
    parameter: str,
) -> None:
    with pytest.raises(ValueError, match=parameter):
        safe_print("safe", **kwargs)  # type: ignore[arg-type]
