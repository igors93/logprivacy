"""Helpers for scanning and cleaning log files."""

from __future__ import annotations

from pathlib import Path

from logprivacy.audit import AuditReport
from logprivacy.cleaner import Cleaner
from logprivacy.policy import CleanerPolicy
from logprivacy.result import Finding


def scan_file(
    path: str | Path,
    *,
    policy: CleanerPolicy | None = None,
    encoding: str = "utf-8",
) -> AuditReport:
    """Return an audit report for a text file."""
    cleaner = Cleaner(policy=policy or CleanerPolicy.default())
    findings: list[Finding] = []
    file_path = Path(path)
    with file_path.open("r", encoding=encoding, errors="replace") as stream:
        for line in stream:
            findings.extend(cleaner.audit(line).findings)
    return AuditReport(tuple(findings))


def clean_file(
    path: str | Path,
    *,
    output: str | Path,
    policy: CleanerPolicy | None = None,
    encoding: str = "utf-8",
) -> Path:
    """Clean a text file line by line and write the cleaned output."""
    cleaner = Cleaner(policy=policy or CleanerPolicy.default())
    input_path = Path(path)
    output_path = Path(output)

    with (
        input_path.open("r", encoding=encoding, errors="replace") as source,
        output_path.open("w", encoding=encoding) as target,
    ):
        for line in source:
            target.write(cleaner.clean_text(line))

    return output_path
