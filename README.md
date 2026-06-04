# LogCleaner

**Simple by default, powerful by composition, safe by guidance.**

LogCleaner is a privacy-first Python library that removes sensitive data from logs before they are printed, stored, or sent to monitoring tools.

It helps Python projects prevent accidental leaks of emails, passwords, API keys, bearer tokens, access tokens, secrets, sensitive URLs, and private values inside structured logs.

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

## Logging integration

```python
import logging
from logcleaner import LogCleanerFilter

logger = logging.getLogger("app")
logger.addFilter(LogCleanerFilter())

logger.warning("User john@example.com used token=abc123")
```

## Design goals

1. Simple things should be simple.
2. Advanced usage should be composable.
3. Logs should be safe by default.
4. Rules should be modular and easy to test.
5. Output should be predictable and explainable.
6. Runtime dependencies should stay at zero.

## Status

Early development. Public API may still evolve.
