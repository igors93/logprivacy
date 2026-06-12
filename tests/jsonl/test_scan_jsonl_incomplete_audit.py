from __future__ import annotations

from dataclasses import replace
from pathlib import Path

from logprivacy.jsonl import scan_jsonl
from logprivacy.policy import CleanerPolicy
from logprivacy.result import JSONLScanRecord


def test_scan_jsonl_yields_incomplete_audit_without_findings(tmp_path: Path) -> None:
    source = tmp_path / "input.jsonl"
    source.write_text('{"outer":{"status":"ok"}}\n', encoding="utf-8")
    policy = replace(CleanerPolicy.default(), max_depth=0)

    records = list(scan_jsonl(source, policy=policy))

    assert len(records) == 1
    assert records[0].line_number == 1
    assert records[0].findings == ()
    assert records[0].complete is False
    assert records[0].limitations == ("max_depth",)


def test_scan_jsonl_preserves_findings_when_audit_is_incomplete(tmp_path: Path) -> None:
    source = tmp_path / "input.jsonl"
    source.write_text(
        '{"email":"user@example.com","nested":{"status":"ok"}}\n',
        encoding="utf-8",
    )
    policy = replace(CleanerPolicy.default(), max_items=1)

    records = list(scan_jsonl(source, policy=policy))

    assert len(records) == 1
    assert records[0].complete is False
    assert records[0].limitations == ("max_items",)
    assert {finding.category for finding in records[0].findings} == {"email"}


def test_scan_jsonl_still_omits_complete_lines_without_findings(tmp_path: Path) -> None:
    source = tmp_path / "input.jsonl"
    source.write_text('{"status":"ok"}\n', encoding="utf-8")

    assert list(scan_jsonl(source)) == []


def test_jsonl_scan_record_defaults_preserve_existing_construction() -> None:
    record = JSONLScanRecord(line_number=3, findings=())

    assert record.complete is True
    assert record.limitations == ()
