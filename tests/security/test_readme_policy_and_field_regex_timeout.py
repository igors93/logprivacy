from __future__ import annotations

import ast
import os
import re
import subprocess
import sys
from pathlib import Path

from logprivacy.field_rules import FieldRule

_ROOT = Path(__file__).resolve().parents[2]


def _documented_policy() -> dict[str, object]:
    readme = (_ROOT / "README.md").read_text(encoding="utf-8")
    match = re.search(
        r"policy3\s*=\s*CleanerPolicy\.from_dict\((\{.*?\})\)\s*$",
        readme,
        flags=re.DOTALL | re.MULTILINE,
    )
    assert match is not None, "README declarative policy example was not found"
    value = ast.literal_eval(match.group(1))
    assert isinstance(value, dict)
    return value


def test_readme_declarative_policy_uses_valid_field_rule_schema() -> None:
    policy = _documented_policy()
    raw_rules = policy["field_rules"]
    assert isinstance(raw_rules, list)
    assert len(raw_rules) == 1
    raw_rule = raw_rules[0]
    assert isinstance(raw_rule, dict)

    rule = FieldRule(**raw_rule)

    assert rule.mode == "exact"
    assert rule.match == "raw_body"
    assert rule.action == "truncate"
    assert rule.max_chars == 500
    assert rule.matches("rawBody") is True


def test_field_rule_regex_execution_is_bounded() -> None:
    code = r"""
from logprivacy.exceptions import InputLimitExceededError
from logprivacy.field_rules import FieldRule

rule = FieldRule.regex(r"(a+)+$")
try:
    rule.matches("a" * 26 + "!")
except InputLimitExceededError as exc:
    raise SystemExit(0 if exc.limit == "regex_execution_ms" else 3)
raise SystemExit(2)
"""
    env = os.environ.copy()
    env["PYTHONPATH"] = str(_ROOT / "src")

    completed = subprocess.run(
        [sys.executable, "-c", code],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        text=True,
        env=env,
        timeout=3.0,
        check=False,
    )

    assert completed.returncode == 0


def test_field_rule_regex_still_matches_normal_fields() -> None:
    rule = FieldRule.regex(r"^(api|auth)_token$")

    assert rule.matches("apiToken") is True
    assert rule.matches("auth-token") is True
    assert rule.matches("request_id") is False


def test_exact_and_contains_modes_keep_existing_behavior() -> None:
    assert FieldRule.exact("raw_body").matches("rawBody") is True
    assert FieldRule.contains("secret").matches("clientSecretValue") is True
