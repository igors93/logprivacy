from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest

from logprivacy import scan_jsonl
from logprivacy.exceptions import InputLimitExceededError
from logprivacy.field_rules import FieldRule
from logprivacy.internal import regex_timeout

_ROOT = Path(__file__).resolve().parents[2]


def _readme_scan_jsonl_example() -> str:
    readme = (_ROOT / "README.md").read_text(encoding="utf-8")
    section = readme.split("## JSONL Streaming", maxsplit=1)[1].split("\n---", maxsplit=1)[0]
    match = re.search(r"```python\n(.*?)```", section, flags=re.DOTALL)
    assert match is not None, "README JSONL example was not found"
    block = match.group(1)
    start = block.index("# Scan for findings")
    end = block.index("# Clean atomically")
    return block[start:end].strip()


def test_readme_scan_jsonl_example_executes_as_streaming_code(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    source = tmp_path / "app.jsonl"
    source.write_text(
        '{"status":"ok"}\n{"email":"john@example.com"}\n',
        encoding="utf-8",
    )
    code = _readme_scan_jsonl_example().replace('"app.jsonl"', repr(str(source)))

    exec(code, {"scan_jsonl": scan_jsonl})

    assert capsys.readouterr().out == "line 2: 1 finding(s)\n"


def test_field_regex_reuses_one_worker_for_many_fields(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    shutdown = getattr(regex_timeout, "_shutdown_worker", None)
    if shutdown is not None:
        shutdown()
    monkeypatch.setattr(regex_timeout, "_signal_timeout_available", lambda: False)
    real_popen = subprocess.Popen
    starts = 0
    processes: list[subprocess.Popen[bytes]] = []

    def counted_popen(*args: object, **kwargs: object) -> subprocess.Popen[bytes]:
        nonlocal starts
        starts += 1
        process = real_popen(*args, **kwargs)
        processes.append(process)
        return process  # type: ignore[arg-type,return-value]

    monkeypatch.setattr(regex_timeout.subprocess, "Popen", counted_popen)
    rule = FieldRule.regex(r"^auth_token$")

    try:
        for index in range(8):
            assert rule.matches(f"field_{index}") is False
    finally:
        shutdown = getattr(regex_timeout, "_shutdown_worker", None)
        if shutdown is not None:
            shutdown()

    assert starts == 1
    assert all(process.poll() is not None for process in processes)


def test_persistent_worker_is_recreated_after_regex_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    shutdown = getattr(regex_timeout, "_shutdown_worker", None)
    if shutdown is not None:
        shutdown()
    monkeypatch.setattr(regex_timeout, "_signal_timeout_available", lambda: False)
    slow = FieldRule.regex(r"(a+)+$")

    with pytest.raises(InputLimitExceededError) as caught:
        slow.matches("a" * 26 + "!")
    assert caught.value.limit == "regex_execution_ms"

    assert FieldRule.regex(r"^request_id$").matches("requestId") is True
    shutdown = getattr(regex_timeout, "_shutdown_worker", None)
    if shutdown is not None:
        shutdown()
