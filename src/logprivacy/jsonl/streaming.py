"""Safe JSONL streaming for structured data."""

from __future__ import annotations

import contextlib
import json as _json
import os
import tempfile
from collections.abc import Iterator
from pathlib import Path
from typing import IO, Literal, TextIO  # noqa: F401

from logprivacy.adapters import AdapterRegistry
from logprivacy.cleaner import Cleaner
from logprivacy.exceptions.errors import JSONLProcessingError
from logprivacy.policy import CleanerPolicy
from logprivacy.result import (
    JSONLRecord,
    JSONLResult,
    JSONLScanRecord,
    JSONLStats,
    SafeDataResult,
    SafeDataStats,
)
from logprivacy.safe_data import to_safe_data_with_result

_OnError = Literal["raise", "skip", "placeholder"]
_SourceType = Path | str | TextIO
_OutputPath = Path | str

_LIMIT_INVALID_JSON = "invalid_json"


def safe_jsonl_write(
    value: object,
    stream: TextIO,
    *,
    policy: CleanerPolicy | None = None,
    adapters: AdapterRegistry | None = None,
) -> SafeDataResult:
    """Sanitize ``value`` and write it as one JSON Lines record to ``stream``.

    Appends a newline after the JSON payload. Does not accept ``default=`` or
    ``allow_nan=True`` options. Returns the ``SafeDataResult`` from sanitization.
    """
    result = to_safe_data_with_result(value, policy=policy, adapters=adapters)
    line = _json.dumps(result.cleaned, allow_nan=False, separators=(",", ":"))
    stream.write(line)
    stream.write("\n")
    return result


def iter_safe_jsonl(
    source: _SourceType,
    *,
    policy: CleanerPolicy | None = None,
    adapters: AdapterRegistry | None = None,
    on_error: _OnError = "raise",
) -> Iterator[JSONLRecord]:
    """Yield sanitized records from a JSON Lines source line by line.

    The source is read one line at a time; the full file is never loaded into
    memory. Each yielded ``JSONLRecord`` contains the 1-based line number and
    a ``SafeDataResult`` for the sanitized object.

    Invalid JSON lines are handled according to ``on_error``:
    - ``"raise"`` — raise ``JSONLProcessingError`` without including line content;
    - ``"skip"`` — skip the line silently;
    - ``"placeholder"`` — yield a record with a placeholder object instead.

    UTF-8 decoding errors on the stream are propagated unchanged.
    """
    _validate_on_error(on_error)
    with _open_source(source) as stream:
        for line_number, raw_line in _iter_lines(stream):
            stripped = raw_line.strip()
            if not stripped:
                continue
            try:
                parsed = _json.loads(stripped)
            except _json.JSONDecodeError as exc:
                if on_error == "raise":
                    raise JSONLProcessingError(
                        f"invalid JSON at line {line_number}",
                        line_number=line_number,
                        reason=_LIMIT_INVALID_JSON,
                    ) from exc
                if on_error == "skip":
                    continue
                placeholder_result = SafeDataResult(
                    cleaned={"_logprivacy_error": _LIMIT_INVALID_JSON, "_line": line_number},
                    complete=False,
                    limitations=(_LIMIT_INVALID_JSON,),
                    stats=SafeDataStats(),
                )
                yield JSONLRecord(line_number=line_number, result=placeholder_result)
                continue

            result = to_safe_data_with_result(parsed, policy=policy, adapters=adapters)
            yield JSONLRecord(line_number=line_number, result=result)


def clean_jsonl(
    source: _SourceType,
    *,
    output: _OutputPath,
    policy: CleanerPolicy | None = None,
    adapters: AdapterRegistry | None = None,
    on_error: _OnError = "raise",
) -> JSONLResult:
    """Sanitize a JSON Lines file and write the cleaned output atomically.

    Each line is read, sanitized, and written to a temporary file. When all
    lines are processed, the temp file is atomically renamed to ``output``.
    If processing fails, the temp file is removed and the original is untouched.

    When ``source`` and ``output`` resolve to the same file, in-place cleaning
    is performed safely via an intermediate temp file in the same directory.

    Skipped or placeholder lines are intentional recovery behaviors, but they
    mean the source was not fully processed as valid JSON. In both cases the
    returned result has ``complete=False`` and includes ``"invalid_json"`` in
    ``limitations``.
    """
    _validate_on_error(on_error)
    output_path = _require_path(output, "output")
    output_dir = output_path.parent

    lines_read = 0
    lines_written = 0
    invalid_lines = 0
    skipped_lines = 0
    placeholder_lines = 0
    all_complete = True
    all_limitations: list[str] = []

    fd, tmp_path_str = tempfile.mkstemp(dir=output_dir, suffix=".jsonl.tmp")
    tmp_path = Path(tmp_path_str)
    try:
        with (
            os.fdopen(fd, "w", encoding="utf-8", newline="") as tmp_stream,
            _open_source(source) as src_stream,
        ):
            for line_number, raw_line in _iter_lines(src_stream):
                stripped = raw_line.strip()
                if not stripped:
                    continue
                lines_read += 1
                try:
                    parsed = _json.loads(stripped)
                except _json.JSONDecodeError as exc:
                    invalid_lines += 1
                    if on_error == "raise":
                        raise JSONLProcessingError(
                            f"invalid JSON at line {line_number}",
                            line_number=line_number,
                            reason=_LIMIT_INVALID_JSON,
                        ) from exc

                    all_complete = False
                    _append_unique(all_limitations, _LIMIT_INVALID_JSON)

                    if on_error == "skip":
                        skipped_lines += 1
                        continue

                    placeholder = {
                        "_logprivacy_error": _LIMIT_INVALID_JSON,
                        "_line": line_number,
                    }
                    tmp_stream.write(_json.dumps(placeholder, allow_nan=False))
                    tmp_stream.write("\n")
                    placeholder_lines += 1
                    lines_written += 1
                    continue

                result = to_safe_data_with_result(parsed, policy=policy, adapters=adapters)
                tmp_stream.write(_json.dumps(result.cleaned, allow_nan=False))
                tmp_stream.write("\n")
                lines_written += 1
                if not result.complete:
                    all_complete = False
                for limitation in result.limitations:
                    _append_unique(all_limitations, limitation)

        try:
            existing_mode = output_path.stat().st_mode
            os.chmod(tmp_path, existing_mode)
        except OSError:
            pass

        os.replace(tmp_path_str, str(output_path))
    except Exception:
        with contextlib.suppress(OSError):
            tmp_path.unlink(missing_ok=True)
        raise

    return JSONLResult(
        complete=all_complete,
        limitations=tuple(all_limitations),
        stats=JSONLStats(
            lines_read=lines_read,
            lines_written=lines_written,
            invalid_lines=invalid_lines,
            skipped_lines=skipped_lines,
            placeholder_lines=placeholder_lines,
        ),
    )


def scan_jsonl(
    source: _SourceType,
    *,
    policy: CleanerPolicy | None = None,
    adapters: AdapterRegistry | None = None,
    on_error: _OnError = "raise",
) -> Iterator[JSONLScanRecord]:
    """Yield scan findings from a JSON Lines source, line by line.

    Each non-empty line is parsed as JSON, then audited for sensitive values.
    Yields ``JSONLScanRecord`` for lines that contain findings.
    Lines with no findings are not yielded.

    ``"raise"`` raises for invalid JSON. Because scan records only represent
    findings, ``"skip"`` and ``"placeholder"`` both omit invalid lines instead
    of yielding a synthetic scan finding. The original line content is never
    stored or included in errors.
    """
    _validate_on_error(on_error)
    effective_policy = CleanerPolicy.default() if policy is None else policy
    cleaner = Cleaner(policy=effective_policy)

    with _open_source(source) as stream:
        for line_number, raw_line in _iter_lines(stream):
            stripped = raw_line.strip()
            if not stripped:
                continue
            try:
                parsed = _json.loads(stripped)
            except _json.JSONDecodeError as exc:
                if on_error == "raise":
                    raise JSONLProcessingError(
                        f"invalid JSON at line {line_number}",
                        line_number=line_number,
                        reason=_LIMIT_INVALID_JSON,
                    ) from exc
                continue

            report = cleaner.audit(parsed)
            if report.findings:
                yield JSONLScanRecord(line_number=line_number, findings=report.findings)


def _validate_on_error(on_error: str) -> None:
    if on_error not in ("raise", "skip", "placeholder"):
        raise ValueError(f"on_error must be 'raise', 'skip', or 'placeholder'; got {on_error!r}")


def _require_path(source: _OutputPath, name: str) -> Path:
    if isinstance(source, (str, Path)):
        return Path(source)
    raise TypeError(f"{name} must be a file path (str or Path) for atomic write")


def _open_source(source: _SourceType) -> IO[str]:
    """Return a context manager that yields a text stream for reading."""
    if isinstance(source, (str, Path)):
        return open(Path(source), encoding="utf-8", newline="")  # noqa: SIM115
    return _NullContextManager(source)  # type: ignore[return-value]


class _NullContextManager:
    """Wrap an existing stream so it can be used in a with-statement without closing."""

    def __init__(self, stream: TextIO) -> None:
        self._stream = stream

    def __enter__(self) -> TextIO:
        return self._stream

    def __exit__(self, *args: object) -> None:
        pass


def _iter_lines(stream: IO[str]) -> Iterator[tuple[int, str]]:
    """Yield (1-based line_number, line_text) pairs."""
    yield from enumerate(stream, start=1)


def _append_unique(values: list[str], value: str) -> None:
    """Append ``value`` once while preserving first-seen order."""
    if value not in values:
        values.append(value)
