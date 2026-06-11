from __future__ import annotations

import json

import pytest

from logprivacy import CleanerPolicy, LogBlockedError, clean_url, clean_with_result


@pytest.mark.parametrize(
    ("text", "secret", "expected_key"),
    [
        (
            "password=correct-horse-battery-staple",
            "correct-horse-battery-staple",
            "password",
        ),
        (
            "Authorization: Bearer abcdefghijklmnop",
            "abcdefghijklmnop",
            "Authorization",
        ),
    ],
)
def test_findings_do_not_expose_original_secret_in_metadata(
    text: str,
    secret: str,
    expected_key: str,
) -> None:
    result = clean_with_result(text)

    assert result.findings
    finding = result.findings[0]
    assert finding.metadata["key"] == expected_key
    assert "value" not in finding.metadata
    assert secret not in json.dumps(finding.metadata, sort_keys=True)
    assert secret not in json.dumps(finding.to_dict(include_metadata=True), sort_keys=True)


def test_clean_url_honors_production_blocking_for_sensitive_query_parameters() -> None:
    url = "https://api.example.com/callback?token=abcdefghijklmnop&page=1"

    with pytest.raises(LogBlockedError):
        clean_url(url, policy=CleanerPolicy.production())


def test_clean_url_keeps_default_masking_behavior() -> None:
    url = "https://api.example.com/callback?token=abcdefghijklmnop&page=1"

    assert clean_url(url) == "https://api.example.com/callback?token=[SECRET]&page=1"
