<h1 align="center">LogPrivacy</h1>

<p align="center">
  <a href="https://github.com/igors93/logprivacy/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/igors93/logprivacy/actions/workflows/ci.yml/badge.svg"></a>
  <a href="https://pypi.org/project/logprivacy/"><img alt="PyPI" src="https://img.shields.io/pypi/v/logprivacy.svg"></a>
  <a href="https://pypi.org/project/logprivacy/"><img alt="Python Versions" src="https://img.shields.io/pypi/pyversions/logprivacy.svg"></a>
  <a href="https://github.com/igors93/logprivacy"><img alt="status alpha" src="https://img.shields.io/badge/status-alpha-orange"></a>
  <a href="https://mypy.readthedocs.io/"><img alt="typing typed" src="https://img.shields.io/badge/typing-typed-green"></a>
  <a href="https://github.com/igors93/logprivacy"><img alt="dependencies zero" src="https://img.shields.io/badge/dependencies-zero-brightgreen"></a>
  <a href="LICENSE"><img alt="license MIT" src="https://img.shields.io/badge/license-MIT-blue"></a>
</p>

<p align="center"><strong>Simple by default, powerful by composition, safe by guidance.</strong></p>

LogPrivacy is a zero-dependency Python library that helps prevent accidental leaks of
sensitive data in logs, debug output, strings, dictionaries, files, and standard
Python logging records.

## What it protects against

LogPrivacy detects and masks:

- email addresses
- passwords and API keys
- bearer tokens and JWTs
- generic secrets and access tokens
- sensitive URL query parameters
- credit card-like values (Luhn-validated)
- IP addresses *(strict mode)*
- phone-like values *(strict mode)*

## Why LogPrivacy?

Most log leaks are not attacks. They happen because someone prints a payload,
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

## Installation

```bash
pip install logprivacy
```

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

See [docs/which-api.md](docs/which-api.md) for a longer guide.

## Quick start

```python
from logprivacy import clean

message = "Login failed for john@example.com with password=123456"
print(clean(message))
# Login failed for [EMAIL] with password=[SECRET]
```

## Safe print

```python
from logprivacy import safe_print

safe_print("User john@example.com used token=abc123456789")
# User [EMAIL] used token=[SECRET]
```

## Safe logger

```python
import logging
from logprivacy import get_safe_logger

logging.basicConfig(level=logging.INFO)
logger = get_safe_logger(__name__)

logger.warning("User john@example.com used password=123456")
# WARNING User [EMAIL] used password=[SECRET]
```

## Audit before logging

```python
from logprivacy import audit

report = audit({"password": "123456", "email": "john@example.com"})
print(report.safe)        # False
print(report.risk_level)  # "high"
print(report.categories)  # ("credential", "email")
print(report.describe())
```

## Fail tests when logs are unsafe

```python
from logprivacy import assert_clean

def test_log_message_has_no_sensitive_data():
    assert_clean("operation finished successfully")

def test_response_dict_is_safe():
    assert_clean({"username": "john", "status": "active"})
```

If sensitive data is found, `assert_clean()` raises `LogPrivacyAssertionError`.

## Clean structured data

```python
from logprivacy import clean

payload = {
    "email": "john@example.com",
    "password": "123456",
    "status": "failed",
}

print(clean(payload))
# {"email": "[EMAIL]", "password": "[SECRET]", "status": "failed"}
```

## Clean URLs without losing useful context

```python
from logprivacy import clean_url

url = "https://api.example.com/users?page=1&token=abc123&email=john@example.com"
print(clean_url(url))
# https://api.example.com/users?page=1&token=[SECRET]&email=[EMAIL]
```

## Masking styles

```python
from logprivacy import Cleaner, CleanerPolicy

Cleaner(CleanerPolicy.default(masking="placeholder"))  # [EMAIL], [SECRET]
Cleaner(CleanerPolicy.default(masking="partial"))      # j***@example.com
Cleaner(CleanerPolicy.default(masking="hash"))         # [EMAIL:855f96e9]
```

| Input | Placeholder | Partial | Hash |
|---|---|---|---|
| `john@example.com` | `[EMAIL]` | `j***@example.com` | `[EMAIL:855f96e9]` |
| `sk_live_abcdef123456` | `[SECRET]` | `sk_l********3456` | `[SECRET:3c6e0b8a]` |

## Policies

| Policy | What it detects | When to use |
|---|---|---|
| `CleanerPolicy.default()` | Email, credentials, tokens, secrets, URLs, credit cards | General-purpose log cleaning |
| `CleanerPolicy.strict()` | Everything above + IP addresses + phone numbers | Sensitive environments |
| `CleanerPolicy.web()` | URLs, credentials, tokens, secrets | HTTP access log cleaning |
| `CleanerPolicy.production()` | Strict + raises on high-risk categories | CI / production safety gates |

See [docs/policies.md](docs/policies.md) for details.

## Clean log files

```python
from logprivacy import scan_file, clean_file

report = scan_file("app.log")
print(report.describe())

clean_file("app.log", output="app.clean.log")
```

## CLI

```bash
python -m logprivacy scan app.log
python -m logprivacy clean app.log --output app.clean.log
python -m logprivacy text "email=john@example.com password=123"
```

## Security disclaimer

LogPrivacy reduces accidental sensitive-data exposure in logs. It is a safety
net, not a DLP system. Regex-based detection can have false positives and false
negatives. You should avoid logging sensitive data in the first place.
LogPrivacy does not replace secret management, encryption, access control, or
legal privacy review.

See [docs/security-model.md](docs/security-model.md) for the full security model.

## Development

```bash
python3 -m venv .venv
source .venv/bin/activate

python3 -m pip install --upgrade pip
python3 -m pip install -e ".[dev]"
```

Run all checks:

```bash
./scripts/ci.sh
```

Or individually:

```bash
python3 -m ruff format .
python3 -m ruff check .
python3 -m mypy src
python3 -m pytest
python3 -m build
```

## Design goals

1. Simple things should be simple.
2. Advanced usage should be composable.
3. Logs should be safe by default.
4. Rules should be modular and easy to test.
5. Output should be predictable and explainable.
6. Runtime dependencies should stay at zero.
7. Users should not need to replace their whole logging setup.
8. Security guidance should be honest: this reduces risk, it does not replace DLP.

## Status

Early development. Public API may still evolve. See [CHANGELOG.md](CHANGELOG.md).
