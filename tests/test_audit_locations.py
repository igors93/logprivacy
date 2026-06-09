from __future__ import annotations

from pathlib import Path

from logprivacy import audit, scan_file
from logprivacy.result import Finding


def test_audit_reports_nested_mapping_locations() -> None:
    report = audit(
        {
            "user": {
                "email": "john@example.com",
                "credentials": {"password": "secret-value"},
            }
        }
    )

    assert report.locations == ("$.user.email", "$.user.credentials.password")
    assert [finding.category for finding in report.findings] == ["email", "credential"]


def test_audit_reports_sequence_indexes() -> None:
    report = audit({"users": ["safe", "john@example.com"]})

    assert report.locations == ("$.users[1]",)
    assert report.findings[0].start == 0
    assert report.findings[0].end == len("john@example.com")


def test_audit_sanitizes_sensitive_mapping_keys_in_locations() -> None:
    report = audit({"john@example.com": "password=secret-value"})

    assert report.locations == ('$["[EMAIL]"]',)
    assert "john@example.com" not in report.locations[0]


def test_audit_does_not_stringify_arbitrary_mapping_keys() -> None:
    class HostileKey:
        def __hash__(self) -> int:
            return 1

        def __str__(self) -> str:
            raise AssertionError("custom key must not be stringified")

    report = audit({HostileKey(): "john@example.com"})

    assert report.locations == ('$["<HostileKey>"]',)


def test_audit_handles_recursive_structures() -> None:
    payload: list[object] = []
    payload.append(payload)
    payload.append("john@example.com")

    report = audit(payload)

    assert report.finding_count == 1
    assert report.locations == ("$[1]",)


def test_root_text_findings_use_root_location() -> None:
    report = audit("john@example.com")

    assert report.locations == ("$",)
    assert report.findings[0].location == "$"


def test_finding_location_survives_replacement() -> None:
    finding = Finding(
        rule_name="email",
        category="email",
        start=0,
        end=16,
        matched="john@example.com",
        location="$.user.email",
    )

    replaced = finding.with_replacement("[EMAIL]")

    assert replaced.location == "$.user.email"
    assert replaced.to_dict()["location"] == "$.user.email"


def test_audit_details_are_safe_and_located() -> None:
    secret = "secret-value"
    report = audit({"password": secret})

    details = report.details()
    rendered = repr(details)

    assert details == [
        {
            "rule_name": "sensitive_key",
            "category": "credential",
            "location": "$.password",
            "start": 0,
            "end": len(secret),
            "reason": "value is associated with a policy-sensitive key",
        }
    ]
    assert secret not in rendered
    assert "matched" not in rendered
    assert "metadata" not in rendered


def test_audit_summary_and_description_include_safe_locations() -> None:
    report = audit({"password": "secret-value"})

    assert report.summary()["locations"] == ["$.password"]
    description = report.describe()
    assert "credential at $.password" in description
    assert "secret-value" not in description


def test_scan_file_reports_one_based_line_and_column(tmp_path: Path) -> None:
    path = tmp_path / "application.log"
    path.write_text(
        "safe line\njohn@example.com\nINFO password=secret-value\n",
        encoding="utf-8",
    )

    report = scan_file(path)

    assert report.locations == ("application.log:2:1", "application.log:3:6")


def test_scan_file_sanitizes_sensitive_file_names(tmp_path: Path) -> None:
    path = tmp_path / "john@example.com.log"
    path.write_text("password=secret-value\n", encoding="utf-8")

    report = scan_file(path)

    assert "john@example.com" not in report.findings[0].location
    assert report.findings[0].location.endswith(":1:1")
