"""Tests for JSONL streaming APIs."""

from __future__ import annotations

import io
import json
import os
from pathlib import Path

import pytest

import logprivacy.jsonl.streaming as _streaming_module
from logprivacy.exceptions import JSONLProcessingError
from logprivacy.jsonl import clean_jsonl, iter_safe_jsonl, safe_jsonl_write, scan_jsonl
from logprivacy.path_rules.rules import PathRule
from logprivacy.policy import CleanerPolicy

# ---------------------------------------------------------------------------
# safe_jsonl_write
# ---------------------------------------------------------------------------


def test_safe_jsonl_write_basic():
    buf = io.StringIO()
    safe_jsonl_write({"key": "value"}, buf)
    line = buf.getvalue()
    assert line.endswith("\n")
    parsed = json.loads(line.strip())
    assert parsed["key"] == "value"


def test_safe_jsonl_write_sanitizes_email():
    buf = io.StringIO()
    safe_jsonl_write({"email": "user@example.com"}, buf)
    parsed = json.loads(buf.getvalue().strip())
    assert "user@example.com" not in str(parsed["email"])


def test_safe_jsonl_write_returns_result():
    buf = io.StringIO()
    result = safe_jsonl_write({"x": 1}, buf)
    assert result.complete is True


def test_safe_jsonl_write_multiple():
    buf = io.StringIO()
    safe_jsonl_write({"a": 1}, buf)
    safe_jsonl_write({"b": 2}, buf)
    lines = buf.getvalue().strip().split("\n")
    assert len(lines) == 2
    assert json.loads(lines[0])["a"] == 1
    assert json.loads(lines[1])["b"] == 2


# ---------------------------------------------------------------------------
# iter_safe_jsonl
# ---------------------------------------------------------------------------


def test_iter_safe_jsonl_empty_file(tmp_path: Path):
    f = tmp_path / "empty.jsonl"
    f.write_text("", encoding="utf-8")
    records = list(iter_safe_jsonl(f))
    assert records == []


def test_iter_safe_jsonl_single_line(tmp_path: Path):
    f = tmp_path / "data.jsonl"
    f.write_text('{"x": 1}\n', encoding="utf-8")
    records = list(iter_safe_jsonl(f))
    assert len(records) == 1
    assert records[0].line_number == 1
    assert records[0].result.cleaned["x"] == 1  # type: ignore[index]


def test_iter_safe_jsonl_multiple_lines(tmp_path: Path):
    f = tmp_path / "data.jsonl"
    f.write_text('{"a":1}\n{"b":2}\n{"c":3}\n', encoding="utf-8")
    records = list(iter_safe_jsonl(f))
    assert len(records) == 3
    assert records[2].line_number == 3


def test_iter_safe_jsonl_no_trailing_newline(tmp_path: Path):
    f = tmp_path / "data.jsonl"
    f.write_text('{"a":1}\n{"b":2}', encoding="utf-8")
    records = list(iter_safe_jsonl(f))
    assert len(records) == 2


def test_iter_safe_jsonl_unicode(tmp_path: Path):
    f = tmp_path / "data.jsonl"
    f.write_text('{"name": "用户"}\n', encoding="utf-8")
    records = list(iter_safe_jsonl(f))
    assert records[0].result.cleaned["name"] == "用户"  # type: ignore[index]


def test_iter_safe_jsonl_invalid_json_raise(tmp_path: Path):
    f = tmp_path / "bad.jsonl"
    f.write_text('{"ok":1}\nNOT JSON\n{"ok":2}\n', encoding="utf-8")
    with pytest.raises(JSONLProcessingError) as exc_info:
        list(iter_safe_jsonl(f, on_error="raise"))
    assert exc_info.value.line_number == 2
    assert exc_info.value.reason == "invalid_json"
    # error message must NOT contain raw line
    assert "NOT JSON" not in str(exc_info.value)


def test_iter_safe_jsonl_invalid_json_skip(tmp_path: Path):
    f = tmp_path / "bad.jsonl"
    f.write_text('{"ok":1}\nNOT JSON\n{"ok":2}\n', encoding="utf-8")
    records = list(iter_safe_jsonl(f, on_error="skip"))
    assert len(records) == 2
    assert records[0].line_number == 1
    assert records[1].line_number == 3


def test_iter_safe_jsonl_invalid_json_placeholder(tmp_path: Path):
    f = tmp_path / "bad.jsonl"
    f.write_text('{"ok":1}\nBAD\n', encoding="utf-8")
    records = list(iter_safe_jsonl(f, on_error="placeholder"))
    assert len(records) == 2
    placeholder = records[1].result.cleaned
    assert placeholder["_logprivacy_error"] == "invalid_json"  # type: ignore[index]
    assert placeholder["_line"] == 2  # type: ignore[index]
    assert records[1].result.complete is False


def test_iter_safe_jsonl_sanitizes_email(tmp_path: Path):
    f = tmp_path / "data.jsonl"
    f.write_text('{"email":"user@example.com"}\n', encoding="utf-8")
    records = list(iter_safe_jsonl(f))
    assert "user@example.com" not in str(records[0].result.cleaned)


def test_iter_safe_jsonl_with_allowlist(tmp_path: Path):
    policy = CleanerPolicy.default().with_rules().allow_paths("status")
    f = tmp_path / "data.jsonl"
    f.write_text('{"status":"ok","secret":"hidden"}\n', encoding="utf-8")
    records = list(iter_safe_jsonl(f, policy=policy))
    cleaned = records[0].result.cleaned
    assert cleaned["status"] == "ok"  # type: ignore[index]
    assert "secret" not in cleaned  # type: ignore[index]


def test_iter_safe_jsonl_with_path_rule(tmp_path: Path):
    policy = (
        CleanerPolicy.default()
        .with_rules()
        .add_path_rules(PathRule.exact("user.id", action="remove"))
    )
    f = tmp_path / "data.jsonl"
    f.write_text('{"user":{"id":"U123","name":"Alice"}}\n', encoding="utf-8")
    records = list(iter_safe_jsonl(f, policy=policy))
    assert records[0].result.cleaned["user"]["id"] == "[REMOVED]"  # type: ignore[index]


def test_iter_safe_jsonl_invalid_on_error_value(tmp_path: Path):
    f = tmp_path / "data.jsonl"
    f.write_text("{}\n", encoding="utf-8")
    with pytest.raises(ValueError, match="on_error"):
        list(iter_safe_jsonl(f, on_error="bad"))  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# clean_jsonl
# ---------------------------------------------------------------------------


def test_clean_jsonl_basic(tmp_path: Path):
    src = tmp_path / "input.jsonl"
    out = tmp_path / "output.jsonl"
    src.write_text('{"x":1}\n{"y":2}\n', encoding="utf-8")
    result = clean_jsonl(src, output=out)
    assert result.stats.lines_read == 2
    assert result.stats.lines_written == 2
    lines = out.read_text(encoding="utf-8").strip().split("\n")
    assert json.loads(lines[0])["x"] == 1
    assert json.loads(lines[1])["y"] == 2


def test_clean_jsonl_sanitizes(tmp_path: Path):
    src = tmp_path / "input.jsonl"
    out = tmp_path / "output.jsonl"
    src.write_text('{"email":"user@example.com"}\n', encoding="utf-8")
    clean_jsonl(src, output=out)
    parsed = json.loads(out.read_text(encoding="utf-8").strip())
    assert "user@example.com" not in str(parsed)


def test_clean_jsonl_in_place(tmp_path: Path):
    src = tmp_path / "data.jsonl"
    src.write_text('{"a":1}\n{"b":2}\n', encoding="utf-8")
    result = clean_jsonl(src, output=src)
    assert result.stats.lines_written == 2
    lines = src.read_text(encoding="utf-8").strip().split("\n")
    assert len(lines) == 2


def test_clean_jsonl_invalid_raise(tmp_path: Path):
    src = tmp_path / "input.jsonl"
    out = tmp_path / "output.jsonl"
    src.write_text('{"ok":1}\nBAD\n', encoding="utf-8")
    with pytest.raises(JSONLProcessingError):
        clean_jsonl(src, output=out)
    # original output should not exist or be untouched
    assert not out.exists()


def test_clean_jsonl_invalid_skip(tmp_path: Path):
    src = tmp_path / "input.jsonl"
    out = tmp_path / "output.jsonl"
    src.write_text('{"ok":1}\nBAD\n{"ok":2}\n', encoding="utf-8")
    result = clean_jsonl(src, output=out, on_error="skip")
    assert result.stats.lines_read == 3
    assert result.stats.invalid_lines == 1
    assert result.stats.skipped_lines == 1
    assert result.stats.lines_written == 2


def test_clean_jsonl_invalid_placeholder(tmp_path: Path):
    src = tmp_path / "input.jsonl"
    out = tmp_path / "output.jsonl"
    src.write_text('{"ok":1}\nBAD\n', encoding="utf-8")
    result = clean_jsonl(src, output=out, on_error="placeholder")
    assert result.stats.placeholder_lines == 1
    assert result.stats.lines_written == 2
    lines = out.read_text(encoding="utf-8").strip().split("\n")
    placeholder = json.loads(lines[1])
    assert placeholder["_logprivacy_error"] == "invalid_json"


def test_clean_jsonl_stats_complete(tmp_path: Path):
    src = tmp_path / "input.jsonl"
    out = tmp_path / "output.jsonl"
    src.write_text('{"x":1}\n', encoding="utf-8")
    result = clean_jsonl(src, output=out)
    assert result.complete is True


def test_clean_jsonl_empty_file(tmp_path: Path):
    src = tmp_path / "input.jsonl"
    out = tmp_path / "output.jsonl"
    src.write_text("", encoding="utf-8")
    result = clean_jsonl(src, output=out)
    assert result.stats.lines_read == 0
    assert result.stats.lines_written == 0


def test_clean_jsonl_atomic_failure_cleanup(tmp_path: Path):
    """Verify no tmp file is left behind after processing failure."""
    src = tmp_path / "bad.jsonl"
    out = tmp_path / "output.jsonl"
    src.write_text("BAD JSON\n", encoding="utf-8")
    with pytest.raises(JSONLProcessingError):
        clean_jsonl(src, output=out)
    tmp_files = list(tmp_path.glob("*.tmp"))
    assert tmp_files == []


def test_clean_jsonl_string_paths(tmp_path: Path):
    src = tmp_path / "input.jsonl"
    out = tmp_path / "output.jsonl"
    src.write_text('{"a":1}\n', encoding="utf-8")
    result = clean_jsonl(str(src), output=str(out))
    assert result.stats.lines_written == 1


# ---------------------------------------------------------------------------
# scan_jsonl
# ---------------------------------------------------------------------------


def test_scan_jsonl_with_findings(tmp_path: Path):
    f = tmp_path / "data.jsonl"
    f.write_text('{"email":"user@example.com"}\n{"x":1}\n', encoding="utf-8")
    records = list(scan_jsonl(f))
    assert len(records) == 1
    assert records[0].line_number == 1
    assert len(records[0].findings) >= 1


def test_scan_jsonl_no_findings_not_yielded(tmp_path: Path):
    f = tmp_path / "data.jsonl"
    f.write_text('{"x":1}\n{"y":2}\n', encoding="utf-8")
    records = list(scan_jsonl(f))
    assert records == []


def test_scan_jsonl_invalid_json_raise(tmp_path: Path):
    f = tmp_path / "bad.jsonl"
    f.write_text("BAD\n", encoding="utf-8")
    with pytest.raises(JSONLProcessingError):
        list(scan_jsonl(f, on_error="raise"))


def test_scan_jsonl_invalid_json_skip(tmp_path: Path):
    f = tmp_path / "bad.jsonl"
    f.write_text('BAD\n{"email":"x@x.com"}\n', encoding="utf-8")
    records = list(scan_jsonl(f, on_error="skip"))
    assert len(records) == 1
    assert records[0].line_number == 2


def test_scan_jsonl_empty(tmp_path: Path):
    f = tmp_path / "empty.jsonl"
    f.write_text("", encoding="utf-8")
    assert list(scan_jsonl(f)) == []


# ---------------------------------------------------------------------------
# clean_jsonl — BaseException cleanup (LP-REM-003)
# ---------------------------------------------------------------------------


def test_clean_jsonl_temp_removed_on_keyboard_interrupt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """KeyboardInterrupt during processing must not leave an orphaned temp file."""
    src = tmp_path / "input.jsonl"
    src.write_text('{"x": 1}\n', encoding="utf-8")
    out = tmp_path / "output.jsonl"

    def _raise_ki(*args, **kwargs):
        raise KeyboardInterrupt

    monkeypatch.setattr(_streaming_module, "to_safe_data_with_result", _raise_ki)

    with pytest.raises(KeyboardInterrupt):
        clean_jsonl(src, output=out)

    assert list(tmp_path.glob("*.tmp")) == []
    assert not out.exists()


def test_clean_jsonl_temp_removed_on_system_exit(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """SystemExit during processing must not leave an orphaned temp file."""
    src = tmp_path / "input.jsonl"
    src.write_text('{"x": 1}\n', encoding="utf-8")
    out = tmp_path / "output.jsonl"

    def _raise_se(*args, **kwargs):
        raise SystemExit(1)

    monkeypatch.setattr(_streaming_module, "to_safe_data_with_result", _raise_se)

    with pytest.raises(SystemExit):
        clean_jsonl(src, output=out)

    assert list(tmp_path.glob("*.tmp")) == []
    assert not out.exists()


def test_clean_jsonl_fd_closed_on_fdopen_failure(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """If os.fdopen raises, the raw fd must be closed and temp file removed."""
    src = tmp_path / "input.jsonl"
    src.write_text('{"x": 1}\n', encoding="utf-8")
    out = tmp_path / "output.jsonl"

    original_close = os.close
    closed: list[int] = []

    def _mock_fdopen(fd, *args, **kwargs):
        raise OSError("simulated fdopen failure")

    def _mock_close(fd: int) -> None:
        closed.append(fd)
        original_close(fd)

    monkeypatch.setattr(os, "fdopen", _mock_fdopen)
    monkeypatch.setattr(os, "close", _mock_close)

    with pytest.raises(OSError, match="simulated fdopen failure"):
        clean_jsonl(src, output=out)

    assert len(closed) == 1, "raw fd must be closed exactly once"
    assert list(tmp_path.glob("*.tmp")) == []
