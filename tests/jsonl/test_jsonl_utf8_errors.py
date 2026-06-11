"""Regression tests for safe handling of invalid UTF-8 in JSONL."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from logprivacy import JSONLProcessingError
from logprivacy.jsonl import clean_jsonl, iter_safe_jsonl, scan_jsonl


def _write_mixed_utf8_file(path: Path) -> None:
    path.write_bytes(b'{"id":1}\n{"secret":"before-invalid"}\xff\n{"id":2}\n')


def test_iter_safe_jsonl_normalizes_invalid_utf8_error(tmp_path: Path) -> None:
    source = tmp_path / "input.jsonl"
    _write_mixed_utf8_file(source)

    with pytest.raises(JSONLProcessingError) as caught:
        list(iter_safe_jsonl(source, on_error="raise"))

    assert caught.value.line_number == 2
    assert caught.value.reason == "invalid_utf8"
    assert str(caught.value) == "invalid UTF-8 at line 2"
    assert "before-invalid" not in str(caught.value)


def test_iter_safe_jsonl_can_skip_invalid_utf8_and_continue(
    tmp_path: Path,
) -> None:
    source = tmp_path / "input.jsonl"
    _write_mixed_utf8_file(source)

    records = list(iter_safe_jsonl(source, on_error="skip"))

    assert [record.line_number for record in records] == [1, 3]
    assert [record.result.cleaned for record in records] == [{"id": 1}, {"id": 2}]


def test_iter_safe_jsonl_can_yield_invalid_utf8_placeholder(
    tmp_path: Path,
) -> None:
    source = tmp_path / "input.jsonl"
    _write_mixed_utf8_file(source)

    records = list(iter_safe_jsonl(source, on_error="placeholder"))

    assert [record.line_number for record in records] == [1, 2, 3]
    placeholder = records[1].result
    assert placeholder.cleaned == {
        "_logprivacy_error": "invalid_utf8",
        "_line": 2,
    }
    assert placeholder.complete is False
    assert placeholder.limitations == ("invalid_utf8",)


def test_clean_jsonl_skip_reports_invalid_utf8_as_incomplete(
    tmp_path: Path,
) -> None:
    source = tmp_path / "input.jsonl"
    output = tmp_path / "output.jsonl"
    _write_mixed_utf8_file(source)

    result = clean_jsonl(source, output=output, on_error="skip")

    assert result.complete is False
    assert result.limitations == ("invalid_utf8",)
    assert result.stats.lines_read == 3
    assert result.stats.lines_written == 2
    assert result.stats.invalid_lines == 1
    assert result.stats.skipped_lines == 1
    assert result.stats.placeholder_lines == 0

    output_lines = [json.loads(line) for line in output.read_text(encoding="utf-8").splitlines()]
    assert output_lines == [{"id": 1}, {"id": 2}]


def test_clean_jsonl_placeholder_reports_invalid_utf8(
    tmp_path: Path,
) -> None:
    source = tmp_path / "input.jsonl"
    output = tmp_path / "output.jsonl"
    _write_mixed_utf8_file(source)

    result = clean_jsonl(source, output=output, on_error="placeholder")

    assert result.complete is False
    assert result.limitations == ("invalid_utf8",)
    assert result.stats.lines_read == 3
    assert result.stats.lines_written == 3
    assert result.stats.invalid_lines == 1
    assert result.stats.skipped_lines == 0
    assert result.stats.placeholder_lines == 1

    output_lines = [json.loads(line) for line in output.read_text(encoding="utf-8").splitlines()]
    assert output_lines == [
        {"id": 1},
        {"_logprivacy_error": "invalid_utf8", "_line": 2},
        {"id": 2},
    ]


def test_clean_jsonl_invalid_utf8_raise_preserves_existing_output(
    tmp_path: Path,
) -> None:
    source = tmp_path / "input.jsonl"
    output = tmp_path / "output.jsonl"
    _write_mixed_utf8_file(source)
    original = '{"existing":true}\n'
    output.write_text(original, encoding="utf-8")

    with pytest.raises(JSONLProcessingError) as caught:
        clean_jsonl(source, output=output, on_error="raise")

    assert caught.value.reason == "invalid_utf8"
    assert caught.value.line_number == 2
    assert output.read_text(encoding="utf-8") == original
    assert list(tmp_path.glob("*.jsonl.tmp")) == []


def test_scan_jsonl_normalizes_invalid_utf8_error(tmp_path: Path) -> None:
    source = tmp_path / "input.jsonl"
    _write_mixed_utf8_file(source)

    with pytest.raises(JSONLProcessingError) as caught:
        list(scan_jsonl(source, on_error="raise"))

    assert caught.value.reason == "invalid_utf8"
    assert caught.value.line_number == 2


def test_scan_jsonl_skip_omits_invalid_utf8_line(tmp_path: Path) -> None:
    source = tmp_path / "input.jsonl"
    _write_mixed_utf8_file(source)

    # The valid records contain no findings; the invalid line is safely omitted.
    assert list(scan_jsonl(source, on_error="skip")) == []
