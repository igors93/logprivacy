# LogCleaner

**Simple by default, powerful by composition, safe by guidance.**

LogCleaner is a zero-dependency Python library that helps prevent accidental leaks of
sensitive data in logs, debug output, strings, dictionaries, files, and standard Python
logging records.

It removes or masks values such as:

- emails
- passwords
- API keys
- bearer tokens
- access tokens
- secrets
- sensitive URL query parameters
- IP addresses in strict mode
- credit card-like values
- phone-like values in strict mode

## Why LogCleaner?

Most log leaks are not attacks. They happen because someone prints a payload, logs an
exception, debugs a request, or sends a dictionary to a logger.

LogCleaner gives you small, memorable tools:

```python
from logcleaner import clean, safe_print, get_safe_logger, audit, assert_clean

clean("email=john@example.com password=123456")
safe_print("token=abc123456789")
logger = get_safe_logger(__name__)
audit("Authorization: Bearer secret-token")
assert_clean("safe message")
```

## Installation

```bash
pip install logcleaner
```

## Quick start

```python
from logcleaner import clean

message = "Login failed for john@example.com with password=123456"
print(clean(message))
```

Output:

```text
Login failed for [EMAIL] with password=[SECRET]
```

## Safe print

```python
from logcleaner import safe_print

safe_print("User john@example.com used token=abc123456789")
```

Output:

```text
User [EMAIL] used token=[SECRET]
```

## Safe logger

```python
from logcleaner import get_safe_logger

logger = get_safe_logger(__name__)
logger.warning("User john@example.com used password=123456")
```

Output:

```text
User [EMAIL] used password=[SECRET]
```

## Audit before logging

```python
from logcleaner import audit

report = audit("email=john@example.com password=123456")

print(report.safe)
print(report.risk_level)
print(report.categories)
print(report.describe())
```

## Fail tests if logs are unsafe

```python
from logcleaner import assert_clean

def test_log_message_has_no_sensitive_data():
    assert_clean("operation finished successfully")
```

If sensitive data is found, `assert_clean()` raises `LogCleanerAssertionError`.

## Clean structured data

```python
from logcleaner import clean

payload = {
    "email": "john@example.com",
    "password": "123456",
    "status": "failed",
}

print(clean(payload))
```

Output:

```python
{
    "email": "[EMAIL]",
    "password": "[SECRET]",
    "status": "failed",
}
```

## Clean URLs without losing useful context

```python
from logcleaner import clean_url

url = "https://api.example.com/users?page=1&token=abc123&email=john@example.com"
print(clean_url(url))
```

Output:

```text
https://api.example.com/users?page=1&token=[SECRET]&email=[EMAIL]
```

## Masking styles

```python
from logcleaner import Cleaner, CleanerPolicy

Cleaner(CleanerPolicy.default(masking="placeholder"))
Cleaner(CleanerPolicy.default(masking="partial"))
Cleaner(CleanerPolicy.default(masking="hash"))
```

Examples:

| Input | Placeholder | Partial | Hash |
|---|---|---|---|
| `john@example.com` | `[EMAIL]` | `j***@example.com` | `[EMAIL:855f96e9]` |
| `sk_live_abcdef123456` | `[SECRET]` | `sk_l********3456` | `[SECRET:3c6e0b8a]` |

## Clean files

```python
from logcleaner import scan_file, clean_file

report = scan_file("app.log")
clean_file("app.log", output="app.clean.log")
```

## CLI

```bash
python -m logcleaner scan app.log
python -m logcleaner clean app.log --output app.clean.log
python -m logcleaner text "email=john@example.com password=123"
```

## Development checks

```bash
python3 -m venv .venv
source .venv/bin/activate

python3 -m pip install --upgrade pip
python3 -m pip install -e ".[dev]"

python3 -m ruff format .
python3 -m ruff check .
python3 -m mypy src
python3 -m pytest
python3 -m build
```

Or run everything:

```bash
./scripts/ci.sh
```

## Design goals

1. Simple things should be simple.
2. Advanced usage should be composable.
3. Logs should be safe by default.
4. Rules should be modular and easy to test.
5. Output should be predictable and explainable.
6. Runtime dependencies should stay at zero.
7. The user should not need to replace their whole logging setup.
8. Security guidance should be honest: this reduces risk, it does not replace DLP.

## Status

Early development. Public API may still evolve.
