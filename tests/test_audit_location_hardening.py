from __future__ import annotations

import os
from pathlib import Path

import pytest

from logprivacy import Cleaner, CleanerPolicy, audit, clean, scan_file
from logprivacy.internal.audit_location import format_file_location


class HostileKey:
    """Mapping key whose user-defined representations must never be invoked."""

    def __init__(self, identifier: int) -> None:
        self.identifier = identifier

    def __hash__(self) -> int:
        return self.identifier

    def __str__(self) -> str:
        raise AssertionError("custom key __str__ must not be called")

    def __repr__(self) -> str:
        raise AssertionError("custom key __repr__ must not be called")


def test_audit_json_escapes_quotes_and_control_characters_in_paths() -> None:
    key = 'part"]\nnext'

    report = audit({key: "john@example.com"})

    assert report.locations == ('$["part\\"]\\\\x0anext"]',)
    assert "\n" not in report.locations[0]


def test_audit_locations_are_distinct_in_first_seen_order() -> None:
    report = audit("john@example.com password=secret-value")

    assert report.finding_count == 2
    assert report.locations == ("$",)


def test_file_location_formatter_neutralizes_control_characters() -> None:
    location = format_file_location("bad\nname.log", line=2, column=3)

    assert location == "bad\\x0aname.log:2:3"
    assert "\n" not in location


@pytest.mark.skipif(os.name == "nt", reason="Windows does not reliably support control characters")
def test_scan_file_neutralizes_controls_and_sensitive_data_in_file_name(tmp_path: Path) -> None:
    path = tmp_path / "john@example.com\nactivity.log"
    path.write_text("password=secret-value\n", encoding="utf-8")

    report = scan_file(path)

    assert report.finding_count == 1
    assert "john@example.com" not in report.locations[0]
    assert "\n" not in report.locations[0]
    assert "\\x0a" in report.locations[0]
    assert report.locations[0].endswith(":1:1")


def test_clean_replaces_untrusted_mapping_key_without_calling_repr_or_str() -> None:
    key = HostileKey(1)

    cleaned = clean({key: "john@example.com"})

    assert key not in cleaned
    assert cleaned == {"<HostileKey>": "[SECRET]"}


def test_clean_preserves_entries_when_safe_key_labels_collide() -> None:
    first = HostileKey(1)
    second = HostileKey(2)

    cleaned = clean(
        {
            "<HostileKey>": "safe-value",
            first: "first-secret",
            second: "second-secret",
        }
    )

    assert cleaned == {
        "<HostileKey>": "safe-value",
        "<HostileKey>#2": "[SECRET]",
        "<HostileKey>#3": "[SECRET]",
    }


def test_untrusted_type_name_is_sanitized_in_audit_and_clean_results() -> None:
    secret_type_name = "ghp_" + "A" * 20

    class SecretNamedKey(HostileKey):
        pass

    SecretNamedKey.__name__ = secret_type_name
    key = SecretNamedKey(1)

    report = Cleaner(policy=CleanerPolicy.production()).audit({key: "value"})
    cleaned = clean({key: "value"})

    assert secret_type_name not in report.locations[0]
    assert "[SECRET]" in report.locations[0]
    assert secret_type_name not in repr(cleaned)
    assert list(cleaned) == ["<[SECRET]>"]


def test_long_mapping_key_locations_remain_bounded() -> None:
    report = audit({"a" * 1_000: "john@example.com"})

    assert len(report.locations[0]) <= 165
    assert report.locations[0].endswith('..."]')
