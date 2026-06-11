<h1 align="center">LogPrivacy</h1>

<p align="center">
  <a href="https://github.com/igors93/logprivacy/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/igors93/logprivacy/actions/workflows/ci.yml/badge.svg"></a>
  <a href="https://pypi.org/project/logprivacy/"><img alt="PyPI" src="https://img.shields.io/pypi/v/logprivacy.svg"></a>
  <a href="https://pypi.org/project/logprivacy/"><img alt="Python Versions" src="https://img.shields.io/pypi/pyversions/logprivacy.svg"></a>
  <a href="https://github.com/igors93/logprivacy"><img alt="status beta" src="https://img.shields.io/badge/status-beta-blue"></a>
  <a href="https://mypy.readthedocs.io/"><img alt="typing typed" src="https://img.shields.io/badge/typing-typed-green"></a>
  <a href="https://github.com/igors93/logprivacy"><img alt="dependencies zero" src="https://img.shields.io/badge/dependencies-zero-brightgreen"></a>
  <a href="LICENSE"><img alt="license MIT" src="https://img.shields.io/badge/license-MIT-blue"></a>
</p>

<p align="center"><strong>Simple by default. Powerful by composition. Safe by guidance.</strong></p>

LogPrivacy is a zero-dependency Python library that prevents accidental leaks of
sensitive data in logs, debug output, strings, dictionaries, files, and standard
Python logging records. It works on **Linux, macOS, and Windows** and supports
**Python 3.10 through 3.14**.

---

## Table of Contents

- [What it protects against](#what-it-protects-against)
- [Why LogPrivacy?](#why-logprivacy)
- [Installation](#installation)
- [Which API should I use?](#which-api-should-i-use)
- [Quick start](#quick-start)
- [Safe print](#safe-print)
- [Safe logger](#safe-logger)
- [Audit before logging](#audit-before-logging)
- [Fail tests when logs are unsafe](#fail-tests-when-logs-are-unsafe)
- [Clean structured data](#clean-structured-data)
- [Structured and JSON-safe data](#structured-and-json-safe-data)
- [JSONL streaming](#jsonl-streaming)
- [Clean URLs](#clean-urls)
- [Masking styles](#masking-styles)
- [Policies](#policies)
- [Path rules and pseudonymization](#path-rules-and-pseudonymization)
- [Clean log files](#clean-log-files)
- [CLI](#cli)
- [Security disclaimer](#security-disclaimer)
- [Development](#development)
- [Design goals](#design-goals)

---

## What it protects against

LogPrivacy detects and masks:

| Category | Example |
|---|---|
| Email addresses | `john@example.com` → `[EMAIL]` |
| Passwords and credentials | `password=123456` → `password=[SECRET]` |
| API keys and access tokens | `api_key=sk_live_abc` → `api_key=[SECRET]` |
| Bearer tokens and JWTs | `Authorization: Bearer eyJ...` → `[TOKEN]` |
| Generic secrets | `secret=abc123456789` → `[SECRET]` |
| Sensitive URL query parameters | `?token=abc123` → `?token=[SECRET]` |
| Credit card-like values (Luhn-validated) | `4111111111111111` → `[CREDIT_CARD]` |
| IP addresses *(strict mode)* | `192.168.1.1` → `[IP_ADDRESS]` |
| Phone-like values *(strict mode)* | `+1-800-555-0100` → `[PHONE]` |

---

## Why LogPrivacy?

Most log leaks are not attacks — they happen because someone prints a payload,
logs an exception, debugs a request, or passes a dictionary to a logger.

LogPrivacy gives you small, memorable tools that fit into your existing code
without replacing your logging setup:

```python
from logprivacy import clean, safe_print, get_safe_logger, audit, assert_clean

clean("email=john@example.com password=123456")
safe_print("token=abc123456789")
logger = get_safe_logger(__name__)
audit("Authorization: Bearer secret-token")
assert_clean("safe message")
```

**Zero runtime dependencies.** No third-party packages are installed alongside
LogPrivacy. Fully typed (`py.typed` marker included).

---

## Installation

```bash
pip install logprivacy
```

Requires Python 3.10 or later. No other dependencies.

---

## Which API should I use?

| I want to… | Use |
|---|---|
| Clean a string or structured value | `clean()` |
| Print safely while debugging | `safe_print()` |
| Use Python's `logging` module safely | `get_safe_logger()` |
| Check whether a value contains sensitive data | `audit()` |
| Fail a test when a log message leaks a secret | `assert_clean()` |
| Sanitize a URL while keeping safe query params | `clean_url()` |
| Scan or clean an old log file | `scan_file()` / `clean_file()` |
| Stream or clean a JSONL file | `scan_jsonl()` / `clean_jsonl()` |
| Get full result metadata alongside cleaned output | `clean_with_result()` / `to_safe_data_with_result()` |

See [docs/guides/which-api.md](docs/guides/which-api.md) for a longer guide.

---

## Quick start

```python
from logprivacy import clean

message = "Login failed for john@example.com with password=123456"
print(clean(message))
# Login failed for [EMAIL] with password=[SECRET]
```

`clean()` accepts strings, dicts, lists, tuples, and most standard Python types.

---

## Safe print

Drop-in replacement for `print()` during debugging:

```python
from logprivacy import safe_print

safe_print("User john@example.com used token=abc123456789")
# User [EMAIL] used token=[SECRET]
```

---

## Safe logger

Wraps any Python `logging.Logger` with a redaction filter:

```python
import logging
from logprivacy import get_safe_logger

logging.basicConfig(level=logging.INFO)
logger = get_safe_logger(__name__)

logger.warning("User john@example.com used password=123456")
# WARNING:__main__:User [EMAIL] used password=[SECRET]
```

The filter is attached once per logger name; calling `get_safe_logger()` again
on the same name reuses the existing filter without creating a duplicate.

---

## Audit before logging

Inspect what would be redacted without modifying the input:

```python
from logprivacy import audit

report = audit({"password": "123456", "email": "john@example.com"})
print(report.safe)         # False
print(report.risk_level)   # "high"
print(report.categories)   # ("credential", "email")
print(report.describe())
```

`audit()` traverses dicts, lists, and tuples recursively. Sensitive dictionary
keys (like `"password"`) are always reported as `credential` findings even when
the value does not match a text pattern.

---

## Fail tests when logs are unsafe

```python
from logprivacy import assert_clean

def test_log_message_has_no_sensitive_data():
    assert_clean("operation finished successfully")

def test_response_dict_is_safe():
    assert_clean({"username": "john", "status": "active"})
```

If sensitive data is found, `assert_clean()` raises `LogPrivacyAssertionError`
with a human-readable description of what was detected and why.

---

## Clean structured data

```python
from logprivacy import clean

payload = {
    "email": "john@example.com",
    "password": "123456",
    "status": "failed",
}

print(clean(payload))
# {'email': '[EMAIL]', 'password': '[SECRET]', 'status': 'failed'}
```

Nested structures (dicts inside dicts, lists of dicts, etc.) are traversed
recursively up to a configurable depth limit.

---

## Structured and JSON-safe data

Use `to_safe_data()` when the output must be safe to pass to JSON encoders.
It returns only JSON-compatible values, converts supported Python types
recursively, and fails closed for unsupported objects:

```python
from logprivacy import (
    AdapterRegistry,
    CleanerPolicy,
    FieldRule,
    safe_json_dumps,
    to_safe_data,
    to_safe_data_with_result,
)

to_safe_data({"email": "john@example.com", "password": "123"})
# {"email": "[EMAIL]", "password": "[SECRET]"}

safe_json_dumps({"token": "abc123456789"})
# '{"token": "[SECRET]"}'

# Register a custom type adapter
class Request:
    def __init__(self, identifier: str, token: str) -> None:
        self.identifier = identifier
        self.token = token

adapters = AdapterRegistry.default()
adapters.register(Request, lambda v: {"id": v.identifier, "token": v.token})
to_safe_data(Request("req-1", "abc123456789"), adapters=adapters)
# {"id": "req-1", "token": "[SECRET]"}

# Field-level rules
policy = CleanerPolicy.default().add_field_rules(
    FieldRule.exact("raw_body", action="truncate", max_chars=500),
    FieldRule.contains("secret", action="remove"),
)

# Rich result with completeness metadata
result = to_safe_data_with_result({"token": "abc", "name": "Alice"})
print(result.complete)      # True
print(result.stats.masked)  # 1
```

See [docs/data/structured-data.md](docs/data/structured-data.md) for supported
types, field-rule actions, adapters, and JSON serialization details.

---

## JSONL streaming

Process JSONL (newline-delimited JSON) files line by line without loading the
entire file into memory:

```python
from logprivacy import scan_jsonl, clean_jsonl, iter_safe_jsonl, safe_jsonl_write

# Scan a JSONL file for sensitive data
stats = scan_jsonl("app.jsonl")
print(stats.total_lines, stats.affected_lines)

# Clean a JSONL file atomically (original preserved on failure)
clean_jsonl("app.jsonl", output="app.clean.jsonl")

# Stream cleaned records
for record in iter_safe_jsonl("app.jsonl"):
    process(record)

# Write clean records directly
with open("output.jsonl", "w") as f:
    safe_jsonl_write([{"email": "john@example.com"}], f)
```

`clean_jsonl` writes via a temporary file and `os.replace`, so the original
is never partially overwritten on failure.

---

## Clean URLs

Sanitize sensitive query parameters while keeping safe context readable:

```python
from logprivacy import clean_url

url = "https://api.example.com/users?page=1&token=abc123&email=john@example.com"
print(clean_url(url))
# https://api.example.com/users?page=1&token=[SECRET]&email=[EMAIL]
```

Safe parameters like `page` and `sort` are preserved unchanged. Sensitive ones
like `token`, `api_key`, `email`, and `password` are replaced with placeholders.

---

## Masking styles

```python
from logprivacy import Cleaner, CleanerPolicy

Cleaner(CleanerPolicy.default(masking="placeholder"))  # [EMAIL], [SECRET]
Cleaner(CleanerPolicy.default(masking="partial"))       # j***@example.com
Cleaner(CleanerPolicy.default(masking="hash"))          # [EMAIL:855f96e9]
```

| Input | Placeholder | Partial | Hash |
|---|---|---|---|
| `john@example.com` | `[EMAIL]` | `j***@example.com` | `[EMAIL:855f96e9]` |
| `sk_live_abcdef123456` | `[SECRET]` | `sk_l********3456` | `[SECRET:3c6e0b8a]` |

**HMAC pseudonymization** is also available when you need stable, reversible
masking without exposing the original value:

```python
from logprivacy import HMACMaskingStrategy, CleanerPolicy

policy = CleanerPolicy.default().with_pseudonymizer(
    HMACMaskingStrategy(key=b"your-secret-key")
)
# Produces deterministic tokens: [EMAIL:hmac:3f4a...]
```

The HMAC key is never stored in `repr`, `str`, serialization, or exceptions.

---

## Policies

| Policy | What it detects | When to use |
|---|---|---|
| `CleanerPolicy.default()` | Email, credentials, tokens, secrets, URLs, credit cards | General-purpose log cleaning |
| `CleanerPolicy.strict()` | Everything above + IP addresses + phone numbers | Sensitive environments (healthcare, finance) |
| `CleanerPolicy.web()` | URLs, credentials, tokens, secrets | HTTP access log cleaning |
| `CleanerPolicy.production()` | Strict + raises `LogBlockedError` on high-risk categories | CI gates / production safety |

```python
from logprivacy import Cleaner, CleanerPolicy

# Strict mode: also catches IP addresses and phone numbers
cleaner = Cleaner(CleanerPolicy.strict())

# Production mode: raises instead of masking high-risk findings
cleaner = Cleaner(CleanerPolicy.production())
```

See [docs/core/policies.md](docs/core/policies.md) for details on each policy.

---

## Path rules and pseudonymization

`PathRule` matches fields by their full traversal path (`"account.balance"`,
`"orders.*.order_id"`) and takes precedence over `FieldRule` and `sensitive_keys`.

Declarative policies can be serialized to and from JSON for configuration-driven
deployments:

```python
from logprivacy import CleanerPolicy, PathRule

policy = CleanerPolicy.default().add_path_rules(
    PathRule.exact("user.email", action="mask"),
    PathRule.glob("orders.*.card_number", action="remove"),
)

# Serialize / deserialize
json_str = policy.to_json()
policy2 = CleanerPolicy.from_json(json_str)
```

See [docs/data/structured-data.md](docs/data/structured-data.md) for path-rule
glob syntax, precedence rules, and the `allow_paths` allowlist.

---

## Clean log files

```python
from logprivacy import scan_file, clean_file

report = scan_file("app.log")
print(report.describe())

clean_file("app.log", output="app.clean.log")
```

---

## CLI

```bash
# Scan a log file for sensitive data
python -m logprivacy scan app.log

# Clean a log file
python -m logprivacy clean app.log --output app.clean.log

# Clean a single string
python -m logprivacy text "email=john@example.com password=123"
```

---

## Security disclaimer

LogPrivacy reduces accidental sensitive-data exposure in logs. It is a safety
net, not a DLP system.

- **Regex-based detection has false positives and false negatives.** Novel
  secret formats, obfuscated values, or custom encodings may not be detected.
- **Avoid logging sensitive data in the first place.** LogPrivacy is the
  second control, not the first.
- **It does not replace secret management, encryption, access control, or
  legal privacy review.** Compliance with GDPR, HIPAA, or PCI-DSS requires
  a legal assessment that goes beyond log redaction.
- `CleanerPolicy.production()` turns silent leaks into loud failures — use it
  as a third control in CI and production.

See [docs/security/security-model.md](docs/security/security-model.md) for the
full security model and threat boundaries.

---

## Development

### Setup

**Linux / macOS:**

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install --upgrade pip
python3 -m pip install -e ".[dev]"
```

**Windows (PowerShell):**

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

### Run all checks

```bash
./scripts/ci.sh
```

### Individual commands

```bash
python -m ruff format .          # format code
python -m ruff check . --fix     # lint and auto-fix
python -m ruff format --check .  # check formatting
python -m ruff check .           # lint only
python -m mypy src               # type check
python -m pytest -v              # run tests
python -m build                  # build distribution
```

### CI matrix

The GitHub Actions workflow tests on:

| OS | Python versions |
|---|---|
| Linux (ubuntu-latest) | 3.10, 3.11, 3.12, 3.13, 3.14 |
| macOS (macos-latest) | 3.10, 3.11, 3.12, 3.13, 3.14 |
| Windows (windows-latest) | 3.10, 3.11, 3.12, 3.13 |

Python 3.14 is a pre-release; Windows support is added when it reaches GA.

---

## Design goals

1. Simple things should be simple.
2. Advanced usage should be composable.
3. Logs should be safe by default.
4. Rules should be modular and easy to test.
5. Output should be predictable and explainable.
6. Runtime dependencies should stay at zero.
7. Users should not need to replace their whole logging setup.
8. Security guidance should be honest: this reduces risk, it does not replace DLP.

---

## Status

Beta. Core API is stable; advanced features (path rules, JSONL, pseudonymization)
are in active use. See [CHANGELOG.md](CHANGELOG.md) for the full history.
