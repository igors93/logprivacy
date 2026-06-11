from __future__ import annotations

import logging
from pathlib import Path

import pytest

from logprivacy.cleaner import Cleaner
from logprivacy.exceptions import InputLimitExceededError
from logprivacy.files.operations import clean_file, scan_file
from logprivacy.integrations.logging_filter import LogPrivacyFilter
from logprivacy.internal.matches import _DetectedMatch
from logprivacy.jsonl.streaming import _iter_lines, iter_safe_jsonl
from logprivacy.policy import CleanerPolicy

_MAX_LINE = 1_000_000


class _GuardedBinaryStream:
    def __init__(self, data: bytes) -> None:
        self.data = data
        self.position = 0
        self.requested_sizes: list[int] = []

    def __iter__(self):
        return self

    def __next__(self):
        raise AssertionError("physical lines must not be read through unbounded iteration")

    def readline(self, size: int = -1) -> bytes:
        if size < 0:
            raise AssertionError("readline() must always receive a finite size")
        self.requested_sizes.append(size)
        if self.position >= len(self.data):
            return b""
        end = min(self.position + size, len(self.data))
        newline = self.data.find(b"\n", self.position, end)
        if newline >= 0:
            end = newline + 1
        chunk = self.data[self.position : end]
        self.position = end
        return chunk


class _BlockingRule:
    name = "custom_block"
    category = "credential\nERROR forged-event"

    def find(self, text: str) -> tuple[_DetectedMatch, ...]:
        if "blocked-value" not in text:
            return ()
        start = text.index("blocked-value")
        return (
            _DetectedMatch(
                rule_name=self.name,
                category=self.category,
                start=start,
                end=start + len("blocked-value"),
                matched="blocked-value",
                reason="test blocked value",
            ),
        )

    def replacement_for(self, match: _DetectedMatch, masking: object) -> str:
        return "[BLOCKED]"


def _record(message: str) -> logging.LogRecord:
    return logging.LogRecord(
        name="security.marker",
        level=logging.WARNING,
        pathname=__file__,
        lineno=1,
        msg=message,
        args=(),
        exc_info=None,
    )


def test_jsonl_reader_uses_bounded_readline_and_recovers_after_oversized_line() -> None:
    stream = _GuardedBinaryStream(b"a" * (_MAX_LINE + 1) + b"\n" + b'{"status":"ok"}\n')

    lines = list(_iter_lines(stream))

    assert lines[0] == (1, None, "max_line_bytes")
    assert lines[1] == (2, '{"status":"ok"}\n', None)
    assert stream.requested_sizes
    assert max(stream.requested_sizes) <= _MAX_LINE + 1


def test_iter_safe_jsonl_can_replace_an_oversized_line_and_continue() -> None:
    stream = _GuardedBinaryStream(b"a" * (_MAX_LINE + 1) + b"\n" + b'{"status":"ok"}\n')

    records = list(iter_safe_jsonl(stream, on_error="placeholder"))

    assert records[0].line_number == 1
    assert records[0].result.cleaned["_logprivacy_error"] == "max_line_bytes"
    assert records[1].line_number == 2
    assert records[1].result.cleaned == {"status": "ok"}


def test_clean_file_rejects_oversized_line_before_replacing_destination(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source.log"
    destination = tmp_path / "clean.log"
    source.write_bytes(b"a" * (_MAX_LINE + 1) + b"\n")
    destination.write_text("existing-safe-output", encoding="utf-8")

    with pytest.raises(InputLimitExceededError) as caught:
        clean_file(source, output=destination)

    assert caught.value.limit == "max_line_chars"
    assert destination.read_text(encoding="utf-8") == "existing-safe-output"


def test_scan_file_marks_oversized_physical_line_incomplete(tmp_path: Path) -> None:
    source = tmp_path / "source.log"
    source.write_bytes(b"a" * (_MAX_LINE + 1) + b"\nnormal line\n")

    report = scan_file(source)

    assert report.complete is False
    assert report.limitations == ("max_line_chars",)


def test_blocked_marker_escapes_control_characters_from_category() -> None:
    rule = _BlockingRule()
    policy = CleanerPolicy(
        rules=(rule,),
        block_categories=(rule.category,),
    )
    record = _record("blocked-value")

    assert LogPrivacyFilter(cleaner=Cleaner(policy=policy)).filter(record) is True

    rendered = record.getMessage()
    assert rendered.splitlines() == [rendered]
    assert "\n" not in rendered
    assert r"\x0aERROR forged-event" in rendered
    assert "blocked-value" not in rendered


def test_clean_file_preserves_configured_multibyte_encoding(tmp_path: Path) -> None:
    source = tmp_path / "source-utf16.log"
    destination = tmp_path / "clean-utf16.log"
    source.write_text("password=secret123\nstatus=ok\n", encoding="utf-16")

    clean_file(source, output=destination, encoding="utf-16")

    cleaned = destination.read_text(encoding="utf-16")
    assert "secret123" not in cleaned
    assert "password=[SECRET]" in cleaned
    assert "status=ok" in cleaned
