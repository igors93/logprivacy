"""Regression tests for JSONL completeness with invalid input lines."""

from __future__ import annotations

import json
from pathlib import Path

from logprivacy.jsonl import clean_jsonl


def test_clean_jsonl_skip_marks_result_incomplete(tmp_path: Path) -> None:
    source = tmp_path / "input.jsonl"
    output = tmp_path / "output.jsonl"
    source.write_text('{"ok":1}\nINVALID\n{"ok":2}\n', encoding="utf-8")

    result = clean_jsonl(source, output=output, on_error="skip")

    assert result.complete is False
    assert result.limitations == ("invalid_json",)
    assert result.stats.lines_read == 3
    assert result.stats.lines_written == 2
    assert result.stats.invalid_lines == 1
    assert result.stats.skipped_lines == 1
    assert result.stats.placeholder_lines == 0


def test_clean_jsonl_placeholder_marks_result_incomplete(tmp_path: Path) -> None:
    source = tmp_path / "input.jsonl"
    output = tmp_path / "output.jsonl"
    source.write_text('{"ok":1}\nINVALID\n', encoding="utf-8")

    result = clean_jsonl(source, output=output, on_error="placeholder")

    assert result.complete is False
    assert result.limitations == ("invalid_json",)
    assert result.stats.lines_read == 2
    assert result.stats.lines_written == 2
    assert result.stats.invalid_lines == 1
    assert result.stats.skipped_lines == 0
    assert result.stats.placeholder_lines == 1

    lines = output.read_text(encoding="utf-8").splitlines()
    placeholder = json.loads(lines[1])
    assert placeholder == {
        "_logprivacy_error": "invalid_json",
        "_line": 2,
    }


def test_clean_jsonl_deduplicates_invalid_json_limitation(tmp_path: Path) -> None:
    source = tmp_path / "input.jsonl"
    output = tmp_path / "output.jsonl"
    source.write_text('INVALID\nALSO INVALID\n{"ok":1}\n', encoding="utf-8")

    result = clean_jsonl(source, output=output, on_error="placeholder")

    assert result.complete is False
    assert result.limitations == ("invalid_json",)
    assert result.stats.invalid_lines == 2
    assert result.stats.placeholder_lines == 2


def test_clean_jsonl_valid_input_remains_complete(tmp_path: Path) -> None:
    source = tmp_path / "input.jsonl"
    output = tmp_path / "output.jsonl"
    source.write_text('{"ok":1}\n{"ok":2}\n', encoding="utf-8")

    result = clean_jsonl(source, output=output)

    assert result.complete is True
    assert result.limitations == ()
    assert result.stats.invalid_lines == 0
