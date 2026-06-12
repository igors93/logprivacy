from __future__ import annotations

import os
import subprocess
import sys
from dataclasses import replace
from pathlib import Path

import pytest

from logprivacy.exceptions import InputLimitExceededError
from logprivacy.policy import CleanerPolicy
from logprivacy.url.cleaning import clean_url

_ROOT = Path(__file__).resolve().parents[2]


def test_clean_url_rejects_total_length_before_component_processing() -> None:
    url = "https://example.com/" + ("a" * 1_000_001)

    with pytest.raises(InputLimitExceededError) as caught:
        clean_url(url)

    assert caught.value.limit == "max_url_chars"
    assert str(caught.value).find("a" * 100) == -1


def test_clean_url_accepts_total_length_at_limit() -> None:
    prefix = "https://example.com/"
    url = prefix + ("a" * (1_000_000 - len(prefix)))

    assert clean_url(url) == url


def test_clean_url_rejects_query_fields_over_limit() -> None:
    query = "&".join(f"key{index}=value" for index in range(10_001))
    url = f"https://example.com/?{query}"

    with pytest.raises(InputLimitExceededError) as caught:
        clean_url(url)

    assert caught.value.limit == "max_url_fields"
    assert caught.value.maximum == 10_000


def test_clean_url_accepts_query_fields_at_limit() -> None:
    query = "&".join(f"key{index}=value" for index in range(10_000))
    url = f"https://example.com/?{query}"

    assert clean_url(url) == url


def test_clean_url_rejects_fragment_fields_over_limit() -> None:
    fragment = "&".join(f"key{index}=value" for index in range(10_001))
    url = f"https://example.com/callback#{fragment}"

    with pytest.raises(InputLimitExceededError) as caught:
        clean_url(url)

    assert caught.value.limit == "max_url_fields"


def test_custom_regex_execution_is_bounded_in_a_separate_worker() -> None:
    code = """
from logprivacy.cleaner import Cleaner
from logprivacy.exceptions import InputLimitExceededError
from logprivacy.policy import CleanerPolicy
from logprivacy.rules.custom import CustomRegexRule

rule = CustomRegexRule(name="slow", category="secret", pattern=r"(a+)+$")
cleaner = Cleaner(policy=CleanerPolicy(rules=(rule,)))
try:
    cleaner.clean_text("a" * 30 + "!")
except InputLimitExceededError as exc:
    raise SystemExit(0 if exc.limit == "regex_execution_ms" else 3)
raise SystemExit(2)
"""
    env = os.environ.copy()
    source_path = str(_ROOT / "src")
    env["PYTHONPATH"] = os.pathsep.join(
        value for value in (source_path, env.get("PYTHONPATH", "")) if value
    )

    completed = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        env=env,
        text=True,
        timeout=2.5,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr


def test_custom_regex_still_redacts_normal_matches() -> None:
    from logprivacy.cleaner import Cleaner
    from logprivacy.rules.custom import CustomRegexRule

    rule = CustomRegexRule(name="employee_id", category="secret", pattern=r"EMP-\d{4}")
    cleaner = Cleaner(policy=CleanerPolicy(rules=(rule,)))

    assert cleaner.clean_text("employee=EMP-1234") == "employee=[SECRET]"


def test_custom_regex_preserves_match_budget() -> None:
    from logprivacy.cleaner import Cleaner
    from logprivacy.rules.custom import CustomRegexRule

    rule = CustomRegexRule(name="letter", category="secret", pattern="a")
    cleaner = Cleaner(policy=replace(CleanerPolicy(rules=(rule,)), max_findings=2))

    with pytest.raises(InputLimitExceededError) as caught:
        cleaner.clean_text("aaa")

    assert caught.value.limit == "max_findings"


@pytest.mark.parametrize("timeout", [0, -1, float("inf"), float("nan")])
def test_custom_regex_rejects_invalid_execution_timeout(timeout: float) -> None:
    from logprivacy.rules.custom import CustomRegexRule

    with pytest.raises(ValueError):
        CustomRegexRule(
            name="invalid_timeout",
            category="secret",
            pattern="x",
            timeout_seconds=timeout,
        )


def test_custom_regex_allows_explicit_timeout_opt_out() -> None:
    from logprivacy.cleaner import Cleaner
    from logprivacy.rules.custom import CustomRegexRule

    rule = CustomRegexRule(
        name="simple",
        category="secret",
        pattern="value",
        timeout_seconds=None,
    )
    cleaner = Cleaner(policy=CleanerPolicy(rules=(rule,)))

    assert cleaner.clean_text("value") == "[SECRET]"


def test_oversized_url_can_still_be_fully_redacted_without_parsing() -> None:
    url = "https://example.com/" + ("a" * 1_000_001)

    assert clean_url(url, redact_full=True) == "[URL]"


def test_custom_regex_worker_fallback_handles_normal_match(monkeypatch: pytest.MonkeyPatch) -> None:
    from logprivacy.cleaner import Cleaner
    from logprivacy.rules import custom as custom_module
    from logprivacy.rules.custom import CustomRegexRule

    monkeypatch.setattr(custom_module, "_signal_timeout_available", lambda: False)
    rule = CustomRegexRule(name="worker", category="secret", pattern="WORK-\\d{2}")
    cleaner = Cleaner(policy=CleanerPolicy(rules=(rule,)))

    assert cleaner.clean_text("id=WORK-42") == "id=[SECRET]"


def test_custom_regex_worker_fallback_enforces_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from logprivacy.cleaner import Cleaner
    from logprivacy.rules import custom as custom_module
    from logprivacy.rules.custom import CustomRegexRule

    monkeypatch.setattr(custom_module, "_signal_timeout_available", lambda: False)
    rule = CustomRegexRule(
        name="slow_worker",
        category="secret",
        pattern=r"(a+)+$",
        timeout_seconds=0.05,
    )
    cleaner = Cleaner(policy=CleanerPolicy(rules=(rule,)))

    with pytest.raises(InputLimitExceededError) as caught:
        cleaner.clean_text("a" * 30 + "!")

    assert caught.value.limit == "regex_execution_ms"
    assert "a" * 30 not in str(caught.value)
