from __future__ import annotations

from collections.abc import Iterator, Mapping, Sequence
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from logprivacy import (
    Cleaner,
    CleanerPolicy,
    LogPrivacyAssertionError,
    assert_clean,
    audit,
    clean,
    scan_file,
)


class SensitiveString(str):
    """A string subclass that must retain normal text-cleaning semantics."""


class HostileKey:
    def __init__(self) -> None:
        self.stringified = False

    def __hash__(self) -> int:
        return 1

    def __str__(self) -> str:
        self.stringified = True
        raise RuntimeError("must not be called")


class BrokenSequence(Sequence[object]):
    def __len__(self) -> int:
        return 2

    def __getitem__(self, index: int) -> object:
        if index == 0:
            return "john@example.com"
        raise RuntimeError("simulated sequence failure")


class BrokenMapping(Mapping[str, object]):
    def __getitem__(self, key: str) -> object:
        raise KeyError(key)

    def __iter__(self) -> Iterator[str]:
        return iter(())

    def __len__(self) -> int:
        return 1

    def items(self) -> Any:
        raise RuntimeError("simulated mapping failure")


def test_clean_replaces_uninspected_deep_branch_instead_of_returning_secret() -> None:
    policy = replace(CleanerPolicy.default(), max_depth=1)
    value = {"level1": {"level2": {"password": "deep-secret"}}}

    cleaned = clean(value, policy=policy)

    assert cleaned == {"level1": {"level2": "[MAX_DEPTH]"}}
    assert "deep-secret" not in repr(cleaned)


def test_incomplete_deep_audit_is_never_reported_as_safe() -> None:
    policy = replace(CleanerPolicy.default(), max_depth=1)
    value = {"level1": {"level2": {"password": "deep-secret"}}}

    report = audit(value, policy=policy)

    assert report.safe is False
    assert report.complete is False
    assert report.truncated is True
    assert report.risk_level == "unknown"
    assert report.limitations == ("max_depth",)
    assert report.finding_count == 0


def test_clean_handles_recursive_sequences_without_retaining_original_cycle() -> None:
    value: list[object] = []
    value.append(value)

    cleaned = clean(value)

    assert cleaned == [["[RECURSIVE]"]]


def test_audit_handles_cycles_without_marking_a_fully_seen_graph_incomplete() -> None:
    value: list[object] = ["safe"]
    value.append(value)

    report = audit(value)

    assert report.safe is True
    assert report.complete is True
    assert report.findings == ()


def test_global_item_budget_truncates_cleaning_without_exposing_remaining_values() -> None:
    policy = replace(CleanerPolicy.default(), max_items=2)
    value = ["safe", "john@example.com", "password=deep-secret"]

    cleaned = clean(value, policy=policy)

    assert cleaned == ["safe", "[EMAIL]", "[TRUNCATED]"]
    assert "deep-secret" not in repr(cleaned)


def test_item_limited_audit_is_incomplete_and_unsafe() -> None:
    policy = replace(CleanerPolicy.default(), max_items=2)
    value = ["safe", "john@example.com", "password=deep-secret"]

    report = audit(value, policy=policy)

    assert report.complete is False
    assert report.safe is False
    assert report.limitations == ("max_items",)
    assert report.finding_count == 1
    assert report.categories == ("email",)


def test_finding_budget_caps_memory_and_marks_report_incomplete() -> None:
    policy = replace(CleanerPolicy.default(), max_findings=1)

    report = audit(["first@example.com", "second@example.com"], policy=policy)

    assert report.finding_count == 1
    assert report.complete is False
    assert report.safe is False
    assert report.limitations == ("max_findings",)


def test_hostile_mapping_key_is_never_stringified_and_value_is_masked() -> None:
    key = HostileKey()

    cleaned = clean({key: "secret-value"})
    report = audit({key: "secret-value"})

    assert key not in cleaned
    assert cleaned == {"<HostileKey>": "[SECRET]"}
    assert key.stringified is False
    assert report.complete is True
    assert report.safe is False
    assert report.categories == ("credential",)


def test_sequence_iteration_failure_fails_closed() -> None:
    cleaner = Cleaner()

    cleaned = cleaner.clean(BrokenSequence())
    report = cleaner.audit(BrokenSequence())

    assert cleaned == ["[EMAIL]", "[UNAVAILABLE]"]
    assert report.safe is False
    assert report.complete is False
    assert report.limitations == ("iteration_error",)


def test_mapping_iteration_failure_fails_closed() -> None:
    cleaner = Cleaner()

    cleaned = cleaner.clean(BrokenMapping())
    report = cleaner.audit(BrokenMapping())

    assert cleaned == {"[LOGPRIVACY_ERROR]": "[UNAVAILABLE]"}
    assert report.safe is False
    assert report.complete is False
    assert report.limitations == ("iteration_error",)


def test_scan_file_caps_retained_findings(tmp_path: Path) -> None:
    path = tmp_path / "application.log"
    path.write_text("first@example.com\nsecond@example.com\n", encoding="utf-8")
    policy = replace(CleanerPolicy.default(), max_findings=1)

    report = scan_file(path, policy=policy)

    assert report.finding_count == 1
    assert report.complete is False
    assert report.safe is False
    assert report.limitations == ("max_findings",)


@pytest.mark.parametrize(
    ("field_name", "value", "error_type"),
    [
        ("max_depth", -1, ValueError),
        ("max_depth", True, TypeError),
        ("max_items", 0, ValueError),
        ("max_items", False, TypeError),
        ("max_findings", 0, ValueError),
        ("max_findings", True, TypeError),
    ],
)
def test_policy_rejects_invalid_traversal_limits(
    field_name: str,
    value: int,
    error_type: type[Exception],
) -> None:
    with pytest.raises(error_type):
        replace(CleanerPolicy.default(), **{field_name: value})


def test_normal_structured_cleaning_remains_compatible() -> None:
    value = {
        "email": "john@example.com",
        "password": "secret-value",
        "items": ["safe", "other@example.com"],
    }

    assert clean(value) == {
        "email": "[EMAIL]",
        "password": "[SECRET]",
        "items": ["safe", "[EMAIL]"],
    }


def test_assert_clean_rejects_incomplete_audit() -> None:
    policy = replace(CleanerPolicy.default(), max_depth=0)

    with pytest.raises(LogPrivacyAssertionError):
        assert_clean({"nested": {"status": "safe"}}, policy=policy)


def test_string_subclasses_are_cleaned_as_text_not_expanded_as_sequences() -> None:
    value = SensitiveString("john@example.com")

    assert clean(value) == "[EMAIL]"
    assert audit(value).categories == ("email",)
